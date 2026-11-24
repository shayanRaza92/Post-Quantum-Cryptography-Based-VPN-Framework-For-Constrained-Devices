// e5_telemetry.ino - Step 5 (experiment E5): signed MPU6050 telemetry on the drone.
// Started by sending "T". No Wi-Fi is used (the network was measured in Step 3).
//
// The sensor: if an MPU6050 answers on I2C (SDA E5_I2C_SDA, SCL E5_I2C_SCL), it is read for real
// (14-byte burst from register 0x3B). If not, SIMULATED samples are used: the same 14 bytes in the
// same register layout (accelerometer, temperature, gyroscope, big-endian), filled with
// realistic values (gravity on Z, slow motion, noise). Signing does not depend on what the bytes
// say, only on how many there are, so the timing results are the same. The log says which one
// was used (META,sensor).
//
// One telemetry sample = 22 bytes: sample number (4), drone clock in us (4), 14 sensor bytes.
// One telemetry message = 8-byte header + the samples, then the signature (or MAVLink 2 signature).
//
// Three ways to protect the telemetry (mode):
//   sig1   every sample is signed on its own                  (1 sample per message)
//   sig10  10 samples are collected, then signed together     (E5_BATCH samples per message)
//   mavsign  MAVLink 2's own message signing, what drones use today: every sample gets a 13-byte
//          signature made with a 32-byte key shared by the drone and the ground station
//          (https://mavlink.io/en/guide/message_signing.html). Fast, but it needs the shared key,
//          which MAVLink says must be set up over a secure link: that is where the public-key
//          authentication of Step 3 fits. The drone authenticates once, then uses this.
//
// Two ways to build the firmware (arch):
//   task    a high-priority sensor task takes the samples on a timer and puts them in a buffer;
//           a lower-priority task signs them (the right way for a drone)
//   inline  one loop reads the sensor and signs, like a simple Arduino loop() (shows what goes
//           wrong when signing is slower than the sample period)
//
// For every run (E5_SECONDS long) the firmware records:
//   late    how late each sample was taken compared to its exact time (sampling jitter)
//   sign    time to sign each message
//   age     age of the oldest sample in a message when its signature is ready (latency)
//   and the counts: samples due, taken, missed (inline: the loop was busy signing), dropped
//   (task: the buffer was full, the oldest unsigned sample is thrown away), signed.
// The buffer keeps at most E5_BUFFER_MS of unsigned samples, so the telemetry never gets older
// than that: when the drone cannot keep up, it signs the newest samples and drops the oldest.
//
// Output (between "### BEGIN TELEMETRY_BENCH" and "### END TELEMETRY_BENCH"):
//   META, SENSOR, KAT, E5RUN, RAW (name <alg>/<arch>/<mode>/<rate>, operations late, sign, age;
//   values in CPU cycles as in Step 1, 240 cycles = 1 us), SUM, LEAK

// (Wire.h and mbedtls/md.h are included in the main tab.)

enum { E5_NONE = 0, E5_SIG1, E5_SIGN_BATCH, E5_MAVSIGN };
static const char* const E5_MODE_NAME[] = {"none", "sig1", "sig" E5_STR(E5_BATCH), "mavsign"};
static const uint32_t E5_RATE_LIST[] = E5_RATES;
static const int E5_RATE_COUNT = sizeof(E5_RATE_LIST) / sizeof(E5_RATE_LIST[0]);

static const int E5_SAMPLE_BYTES = 22;
static const int E5_HDR_BYTES = 8;
static const int E5_MSG_MAX = E5_HDR_BYTES + E5_BATCH * E5_SAMPLE_BYTES;

struct E5Sample {
  uint32_t seq;
  uint32_t t_us;                                  // when it was taken (esp_timer, low 32 bits)
  uint8_t raw[14];
};

// ---- The sensor ---------------------------------------------------------------------------
static bool e5_real_sensor = false;
static uint32_t e5_i2c_errors = 0;
static uint32_t e5_rng = 0x6D2B79F5u;

static uint32_t e5_rand() {
  e5_rng ^= e5_rng << 13; e5_rng ^= e5_rng >> 17; e5_rng ^= e5_rng << 5;
  return e5_rng;
}

static void e5_put16(uint8_t* p, int16_t v) { p[0] = (uint8_t)((uint16_t)v >> 8); p[1] = (uint8_t)v; }
static void e5_put32(uint8_t* p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (24 - 8 * i)); }

static bool e5_i2c_write(uint8_t reg, uint8_t val) {
  Wire.beginTransmission(0x68);
  Wire.write(reg);
  Wire.write(val);
  return Wire.endTransmission() == 0;
}

static bool e5_i2c_read(uint8_t reg, uint8_t* out, int n) {
  Wire.beginTransmission(0x68);
  Wire.write(reg);
  if (Wire.endTransmission(false) != 0) return false;
  if (Wire.requestFrom((uint8_t)0x68, (uint8_t)n) != n) return false;
  for (int i = 0; i < n; i++) out[i] = Wire.read();
  return true;
}

// Looks for the MPU6050 and prints what was found on the I2C bus (helps to fix the wiring).
static void e5_sensor_init() {
  Wire.begin(E5_I2C_SDA, E5_I2C_SCL, E5_I2C_HZ);
  Serial.printf("SENSOR,i2c_pins,SDA=%d SCL=%d at %d Hz\n", E5_I2C_SDA, E5_I2C_SCL, E5_I2C_HZ);
  String found;
  for (uint8_t addr = 1; addr < 127; addr++) {
    Wire.beginTransmission(addr);
    if (Wire.endTransmission() == 0) found += String(found.length() ? " 0x" : "0x") + String(addr, HEX);
  }
  Serial.printf("SENSOR,i2c_scan,%s\n", found.length() ? found.c_str() : "no device answered");
  uint8_t who = 0;
  if (e5_i2c_read(0x75, &who, 1) && e5_i2c_write(0x6B, 0x00)) {   // WHO_AM_I, then wake up
    delay(100);
    e5_i2c_write(0x1A, 0x03);                                        // 44 Hz low-pass filter
    uint8_t test[14];
    e5_real_sensor = e5_i2c_read(0x3B, test, 14);
    Serial.printf("SENSOR,who_am_i,0x%02x\n", who);
  }
  if (e5_real_sensor) {
    Serial.println("META,sensor,real MPU6050 (14-byte burst read over I2C)");
  } else {
    Wire.end();
    Serial.println("META,sensor,SIMULATED MPU6050 (no sensor answered at 0x68; same 14-byte "
                   "register layout, generated values)");
  }
}

// Fills the 14 sensor bytes: accel X Y Z, temperature, gyro X Y Z (MPU6050 order, big-endian).
static void e5_read_sensor(uint32_t t_us, uint8_t raw[14]) {
  if (e5_real_sensor) {
    if (e5_i2c_read(0x3B, raw, 14)) return;
    e5_i2c_errors++;                              // keep going with a generated value
  }
  float t = t_us * 1e-6f;
  auto noise = [](int amp) { return (int)(e5_rand() % (2 * amp + 1)) - amp; };
  // +-2 g range: 16384 per g. +-250 deg/s range: 131 per deg/s. Temperature 25 C.
  e5_put16(raw + 0, (int16_t)(820 * sinf(2.1f * t) + noise(60)));
  e5_put16(raw + 2, (int16_t)(650 * sinf(1.3f * t + 1.0f) + noise(60)));
  e5_put16(raw + 4, (int16_t)(16384 + noise(80)));
  e5_put16(raw + 6, (int16_t)((25.0f - 36.53f) * 340.0f));
  e5_put16(raw + 8, (int16_t)(1300 * cosf(2.1f * t) + noise(20)));
  e5_put16(raw + 10, (int16_t)(900 * cosf(1.3f * t + 1.0f) + noise(20)));
  e5_put16(raw + 12, (int16_t)(noise(20)));
}

// ---- One run ------------------------------------------------------------------------------
struct E5Run {
  const SigAlgorithm* a;                          // nullptr for "none" and "mavsign"
  int mode, batch;
  bool inline_arch;
  uint32_t rate_hz, period_us, ticks_total;
  TaskHandle_t sampler;
  QueueHandle_t queue;
  volatile bool sampling_done, signer_done;
  int64_t t0_us;                                  // timer start; sample k is due at t0 + k * period
  // counters
  uint32_t ticks, taken, missed, dropped, signed_samples, messages, sign_fail, backlog;
  bool last_ok;
  size_t data_bytes, tag_bytes;
  // the measurements, in CPU cycles
  uint64_t *late, *sign, *age;
  int n_late, n_sign, n_age, cap;
  // signer state
  uint8_t msg[E5_MSG_MAX];
  E5Sample batch_buf[E5_BATCH];
  int in_batch;
  uint16_t msg_seq;
};

static uint8_t e5_sig[MAX_SIG_BYTES];
static uint8_t e5_key[32];                        // MAVLink 2 signing key (random, made once)
static uint8_t e5_mav_buf[32 + E5_MSG_MAX + 7];
static uint64_t e5_mav_ts = 0;

// MAVLink 2 message signing (mavlink.io, message_signing): the signature is the first 6 bytes of
// SHA-256(secret key | packet | link id | timestamp). 13 bytes are sent: link id (1), timestamp
// (6, in 10 us units, must always increase), signature (6). Numbers are little-endian, as in MAVLink.
static void e5_mavsign(const uint8_t* m, size_t len, uint64_t ts, uint8_t out[13]) {
  uint8_t h[32];
  memcpy(e5_mav_buf, e5_key, 32);
  memcpy(e5_mav_buf + 32, m, len);
  out[0] = 0;                                     // link id
  for (int i = 0; i < 6; i++) out[1 + i] = (uint8_t)(ts >> (8 * i));
  memcpy(e5_mav_buf + 32 + len, out, 7);
  sha256(e5_mav_buf, 32 + len + 7, h);
  memcpy(out + 7, h, 6);
}

static void e5_timer_cb(void* p) { xTaskNotifyGive(((E5Run*)p)->sampler); }

// Builds the message from the collected samples, signs it and records the time and the age.
static void e5_sign_batch(E5Run* r) {
  uint8_t* m = r->msg;
  m[0] = 'D'; m[1] = 'T'; m[2] = 1; m[3] = (uint8_t)r->mode; m[4] = (uint8_t)r->in_batch; m[5] = 0;
  m[6] = (uint8_t)(r->msg_seq >> 8); m[7] = (uint8_t)r->msg_seq;
  for (int i = 0; i < r->in_batch; i++) {
    uint8_t* s = m + E5_HDR_BYTES + i * E5_SAMPLE_BYTES;
    e5_put32(s, r->batch_buf[i].seq);
    e5_put32(s + 4, r->batch_buf[i].t_us);
    memcpy(s + 8, r->batch_buf[i].raw, 14);
  }
  size_t len = E5_HDR_BYTES + r->in_batch * E5_SAMPLE_BYTES;
  size_t taglen = 0;
  int rc;
  uint32_t c0 = cycles();
  if (r->mode == E5_MAVSIGN) {
    uint64_t ts = (uint64_t)esp_timer_get_time() / 10;
    e5_mav_ts = ts > e5_mav_ts ? ts : e5_mav_ts + 1;
    e5_mavsign(m, len, e5_mav_ts, e5_sig);
    rc = 0;
    taglen = 13;
  } else {
    rc = r->a->sign(m, len, e5_sig, &taglen);
  }
  uint32_t dc = cycles() - c0;
  uint32_t now = (uint32_t)esp_timer_get_time();
  if (rc != 0) { r->sign_fail++; r->in_batch = 0; return; }
  if (r->n_sign < r->cap) r->sign[r->n_sign++] = dc;
  if (r->n_age < r->cap) r->age[r->n_age++] = (uint64_t)(now - r->batch_buf[0].t_us) * CPU_MHZ;
  r->signed_samples += r->in_batch;
  r->messages++;
  r->msg_seq++;
  r->data_bytes = len;
  r->tag_bytes = taglen;
  r->in_batch = 0;
}

// Checks the last message once (outside the timing), so a wrong signature cannot go unnoticed.
static void e5_check_last(E5Run* r) {
  if (r->messages == 0) return;
  if (r->mode == E5_MAVSIGN) {
    uint8_t t[13];
    uint64_t ts = 0;
    for (int i = 0; i < 6; i++) ts |= (uint64_t)e5_sig[1 + i] << (8 * i);
    e5_mavsign(r->msg, r->data_bytes, ts, t);
    r->last_ok = memcmp(t, e5_sig, 13) == 0;
  } else {
    r->last_ok = r->a->verify(r->msg, r->data_bytes, e5_sig, r->tag_bytes) == 0;
  }
}

static void e5_sampler_task(void* p) {
  E5Run* r = (E5Run*)p;
  E5Sample s;
  while (r->ticks < r->ticks_total) {
    uint32_t n = ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(3000));
    if (n == 0) break;                            // the timer stopped: should not happen
    int64_t now = esp_timer_get_time();
    r->ticks += n;
    r->missed += n - 1;                           // ticks that came while this loop was busy
    int64_t due = r->t0_us + (int64_t)r->ticks * r->period_us;
    int64_t late = now - due;
    if (late < 0) late = 0;
    if (r->n_late < r->cap) r->late[r->n_late++] = (uint64_t)late * CPU_MHZ;
    s.seq = r->taken++;
    s.t_us = (uint32_t)now;
    e5_read_sensor(s.t_us, s.raw);
    if (r->mode == E5_NONE) continue;
    if (r->inline_arch) {                         // sign right here, in the sampling loop
      r->batch_buf[r->in_batch++] = s;
      if (r->in_batch == r->batch) e5_sign_batch(r);
    } else if (xQueueSend(r->queue, &s, 0) != pdTRUE) {
      E5Sample old;                               // buffer full: drop the oldest, keep the newest
      if (xQueueReceive(r->queue, &old, 0) == pdTRUE) r->dropped++;
      if (xQueueSend(r->queue, &s, 0) != pdTRUE) r->dropped++;
    }
  }
  r->sampling_done = true;
  if (r->inline_arch && r->mode != E5_NONE) {
    r->backlog = r->in_batch;
    e5_check_last(r);
    r->signer_done = true;
  }
  // Do not delete this task here: the timer may still send it a wake-up until e5_run stops the
  // timer, and a wake-up sent to a deleted task writes into freed memory. e5_run deletes it.
  for (;;) vTaskDelay(portMAX_DELAY);
}

static void e5_signer_task(void* p) {
  E5Run* r = (E5Run*)p;
  E5Sample s;
  while (!r->sampling_done) {
    if (xQueueReceive(r->queue, &s, pdMS_TO_TICKS(20)) != pdTRUE) continue;
    r->batch_buf[r->in_batch++] = s;
    if (r->in_batch == r->batch) e5_sign_batch(r);
  }
  r->backlog = uxQueueMessagesWaiting(r->queue) + r->in_batch;   // left unsigned at the end
  e5_check_last(r);
  r->signer_done = true;
  vTaskDelete(NULL);
}

static void e5_print_run(E5Run* r, const char* alg) {
  char name[64];
  snprintf(name, sizeof(name), "%s/%s/%s/%u", alg, r->inline_arch ? "inline" : "task", E5_MODE_NAME[r->mode],
           (unsigned)r->rate_hz);
  print_raw(name, "late", r->late, r->n_late);
  print_raw(name, "sign", r->sign, r->n_sign);
  print_raw(name, "age", r->age, r->n_age);
  Serial.printf("E5RUN,%s,rate_hz=%u,batch=%d,seconds=%d,due=%u,taken=%u,missed=%u,dropped=%u,signed=%u,"
                "messages=%u,backlog=%u,sign_fail=%u,data_bytes=%u,tag_bytes=%u,last_check=%s,i2c_errors=%u\n",
                name, (unsigned)r->rate_hz, r->batch, E5_SECONDS, (unsigned)r->ticks_total, (unsigned)r->taken,
                (unsigned)r->missed, (unsigned)r->dropped, (unsigned)r->signed_samples, (unsigned)r->messages,
                (unsigned)r->backlog, (unsigned)r->sign_fail, (unsigned)r->data_bytes, (unsigned)r->tag_bytes,
                r->mode == E5_NONE ? "n/a" : (r->last_ok ? "ok" : "FAIL"), (unsigned)e5_i2c_errors);
  Stats st = compute_stats(r->late, r->n_late, 0);
  print_stats(name, "late", st);
  if (r->n_sign) { st = compute_stats(r->sign, r->n_sign, (int)r->sign_fail); print_stats(name, "sign", st); }
  if (r->n_age) { st = compute_stats(r->age, r->n_age, 0); print_stats(name, "age", st); }
}

static bool e5_run(E5Run* r, const SigAlgorithm* a, const char* alg, int mode, bool inline_arch, uint32_t rate,
                   uint64_t* late, uint64_t* sign, uint64_t* age, int cap) {
  memset(r, 0, sizeof(*r));
  r->a = a; r->mode = mode; r->inline_arch = inline_arch; r->rate_hz = rate;
  r->batch = mode == E5_SIGN_BATCH ? E5_BATCH : 1;
  r->period_us = 1000000 / rate;
  r->ticks_total = rate * E5_SECONDS;
  r->late = late; r->sign = sign; r->age = age; r->cap = cap;
  uint32_t depth = rate * E5_BUFFER_MS / 1000;
  if (depth < (uint32_t)(2 * r->batch)) depth = 2 * r->batch;
  e5_i2c_errors = 0;
  Serial.printf("PROGRESS,%s,%s %s at %u Hz\n", alg, inline_arch ? "inline" : "task", E5_MODE_NAME[mode],
                (unsigned)rate);
  Serial.flush();

  bool need_big_sampler = inline_arch && mode != E5_NONE;
  bool need_signer = !inline_arch && mode != E5_NONE;
  if (need_signer && (r->queue = xQueueCreate(depth, sizeof(E5Sample))) == NULL) {
    Serial.println("ERROR,e5,could not create the sample buffer");
    return false;
  }
  if (xTaskCreatePinnedToCore(e5_sampler_task, "sampler", need_big_sampler ? E5_SIGN_STACK : 8192, r,
                              E5_SAMPLER_PRIORITY, &r->sampler, BENCH_CORE) != pdPASS) {
    Serial.println("ERROR,e5,could not create the sensor task");
    if (r->queue) vQueueDelete(r->queue);
    return false;
  }
  r->signer_done = (mode == E5_NONE);           // otherwise set by the signing task (task) or the sampler (inline)
  if (need_signer && xTaskCreatePinnedToCore(e5_signer_task, "signer", E5_SIGN_STACK, r, BENCH_PRIORITY, NULL,
                                             BENCH_CORE) != pdPASS) {
    Serial.println("ERROR,e5,could not create the signing task");
    r->ticks_total = 0;                           // stops the sampler at its first tick
    r->signer_done = true;
  }

  esp_timer_handle_t timer;
  esp_timer_create_args_t ta = {};
  ta.callback = e5_timer_cb;
  ta.arg = r;
  ta.name = "e5";
  esp_timer_create(&ta, &timer);
  r->t0_us = esp_timer_get_time();
  esp_timer_start_periodic(timer, r->period_us);
  while (!(r->sampling_done && r->signer_done)) delay(50);
  esp_timer_stop(timer);
  delay(20);                                      // a timer callback that already started finishes
  esp_timer_delete(timer);
  vTaskDelete(r->sampler);                        // only now: nothing can wake it any more
  delay(50);                                      // let the idle task free the finished tasks
  if (r->queue) vQueueDelete(r->queue);
  e5_print_run(r, alg);
  return true;
}

static void e5_print_meta() {
  print_meta_common();
  Serial.printf("META,seconds_per_run,%d\n", E5_SECONDS);
  Serial.printf("META,batch,%d samples per message in mode sig%d\n", E5_BATCH, E5_BATCH);
  Serial.printf("META,sample_bytes,%d (number 4, clock 4, MPU6050 registers 14); header %d\n", E5_SAMPLE_BYTES,
                E5_HDR_BYTES);
  Serial.printf("META,buffer_ms,%d (task: unsigned samples kept at most; oldest dropped when full)\n", E5_BUFFER_MS);
  Serial.printf("META,tasks,core %d; sensor task priority %d; signing task priority %d; timer esp_timer\n",
                BENCH_CORE, E5_SAMPLER_PRIORITY, BENCH_PRIORITY);
  Serial.println("META,mavsign,MAVLink 2 message signing: SHA-256 (mbedTLS, hardware) of key | message | link id | "
                 "timestamp, first 6 bytes; 13 bytes sent; 32-byte random key");
  Serial.println("META,timer,RAW values are CPU cycles (240 per us): late, sign, age");
}

void run_e5() {
  e5_print_meta();
  e5_sensor_init();
  for (int i = 0; i < 32; i++) e5_key[i] = (uint8_t)esp_random();

  uint32_t max_rate = 0;
  for (int k = 0; k < E5_RATE_COUNT; k++) if (E5_RATE_LIST[k] > max_rate) max_rate = E5_RATE_LIST[k];
  if (E5_INLINE_RATE > max_rate) max_rate = E5_INLINE_RATE;
  int cap = max_rate * E5_SECONDS + 8;
  uint64_t* late = (uint64_t*)malloc(cap * sizeof(uint64_t));
  uint64_t* sign = (uint64_t*)malloc(cap * sizeof(uint64_t));
  uint64_t* age = (uint64_t*)malloc(cap * sizeof(uint64_t));
  E5Run* r = (E5Run*)malloc(sizeof(E5Run));
  if (!late || !sign || !age || !r) {
    Serial.println("ERROR,e5,not enough memory for the measurement arrays");
    Serial.println("### END TELEMETRY_BENCH");
    return;
  }
  int64_t t_start = esp_timer_get_time();

  // 1. Sampling only, no signing: how regular is the sampling on its own?
  for (int k = 0; k < E5_RATE_COUNT; k++) e5_run(r, nullptr, "none", E5_NONE, false, E5_RATE_LIST[k], late, sign, age, cap);

  // 2. Every algorithm: sig1 and sig10 at every rate (task), then sig1 in a simple loop (inline)
  for (int k = 0; k < ALGORITHM_COUNT; k++) {
    const SigAlgorithm* a = ALGORITHMS[k];
    size_t free_before = ESP.getFreeHeap();
    e2_ready = false;
    run_in_task(e2_prepare_task, (void*)a, nullptr);   // known-answer test and the key (Step 2 code)
    if (!e2_ready) {
      Serial.printf("ERROR,%s,known-answer test or key generation failed; skipped\n", a->name);
      a->free_bench_key();
      continue;
    }
    for (int i = 0; i < E5_RATE_COUNT; i++) {
      e5_run(r, a, a->name, E5_SIG1, false, E5_RATE_LIST[i], late, sign, age, cap);
      e5_run(r, a, a->name, E5_SIGN_BATCH, false, E5_RATE_LIST[i], late, sign, age, cap);
    }
    e5_run(r, a, a->name, E5_SIG1, true, E5_INLINE_RATE, late, sign, age, cap);
    a->free_bench_key();
    Serial.printf("LEAK,%s,free_before=%u,free_after=%u\n", a->name, (unsigned)free_before,
                  (unsigned)ESP.getFreeHeap());
  }

  // 3. MAVLink 2 signing with a shared key on every sample (after a one-time authentication)
  for (int k = 0; k < E5_RATE_COUNT; k++) e5_run(r, nullptr, "MAVLink2-sign", E5_MAVSIGN, false, E5_RATE_LIST[k], late, sign, age, cap);
  e5_run(r, nullptr, "MAVLink2-sign", E5_MAVSIGN, true, E5_INLINE_RATE, late, sign, age, cap);

  free(late); free(sign); free(age); free(r);
  Serial.printf("META,total_seconds,%.1f\n", (esp_timer_get_time() - t_start) / 1e6);
  Serial.println("### END TELEMETRY_BENCH");
  Serial.println("Done. Analyse with: python3 tools/analyze_telemetry.py <log file>");
}
