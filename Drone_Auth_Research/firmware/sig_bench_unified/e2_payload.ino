// e2_payload.ino - Step 2 (experiment E2): how the message size changes the cost of signing,
// and the largest message the ESP32 can sign. Started by sending "P".
//
// Uses the same algorithms, timer, statistics and task helpers as Step 1 (main tab).
//
// Part A  Time vs message size. Every algorithm signs and verifies the same messages of
//         64 B ... 64 KB (E2_SIZES), E2_RUNS times per size.
// Part B  Largest message. A binary search finds the biggest message (in bytes) that can still
//         be held in RAM, signed and verified. As in a real drone firmware, each algorithm runs
//         in a task with only the stack it was measured to need (+ E2_STACK_MARGIN), and the
//         message buffer is allocated inside that task. The limit that was hit is reported.
// Every algorithm uses the same messages and starts from the same free memory.
//
// Output (between "### BEGIN PAYLOAD_BENCH" and "### END PAYLOAD_BENCH"):
//   KAT, E2STACK, RAW (operation names sign_<bytes>, verify_<bytes>), SUM, MAXMSG, LEAK

static const uint32_t E2_SIZE_LIST[] = E2_SIZES;
static const int E2_SIZE_COUNT = sizeof(E2_SIZE_LIST) / sizeof(E2_SIZE_LIST[0]);
static_assert(E2_RUNS <= BENCH_RUNS, "E2_RUNS must not exceed BENCH_RUNS (sample arrays)");

// Same message content for every algorithm: a fixed xorshift32 stream. The run number goes
// into the first 4 bytes, so every run signs a different message.
static void e2_fill(uint8_t* buf, uint32_t len) {
  uint32_t x = 0x2545F491u;
  for (uint32_t k = 0; k < len; k++) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    buf[k] = (uint8_t)x;
  }
}

static void e2_set_run(uint8_t* buf, uint32_t len, uint32_t i) {
  for (uint32_t b = 0; b < 4 && b < len; b++) buf[b] = (uint8_t)(i >> (8 * b));
}

// ---- Preparation: known-answer test and the key, in a large task -----------------------
static volatile bool e2_ready = false;

static void e2_prepare_task(void* p) {
  const SigAlgorithm* a = (const SigAlgorithm*)p;
  bool kat = a->kat();
  Serial.printf("KAT,%s,%s\n", a->name, kat ? "PASS" : "FAIL");
  e2_ready = kat && a->make_bench_key() == 0;
}

// ---- Part A: time vs message size --------------------------------------------------------
struct E2Sweep {
  const SigAlgorithm* a;
  uint8_t* buf;
  uint32_t len;
  int sfails, vfails;
};

static void e2_sweep_task(void* p) {
  E2Sweep* w = (E2Sweep*)p;
  for (int i = 0; i < 3; i++) {                  // warm-up with run numbers outside the timed set
    e2_set_run(w->buf, w->len, E2_RUNS + i);
    w->a->sign(w->buf, w->len, g_sig, &g_siglen);
    w->a->verify(w->buf, w->len, g_sig, g_siglen);
  }
  w->sfails = w->vfails = 0;
  for (int i = 0; i < E2_RUNS; i++) {
    e2_set_run(w->buf, w->len, i);
    vTaskDelay(1);
    uint32_t t0 = cycles();
    int rc = w->a->sign(w->buf, w->len, g_sig, &g_siglen);
    s_sign[i] = cycles() - t0;
    if (rc != 0) w->sfails++;
    t0 = cycles();
    rc = w->a->verify(w->buf, w->len, g_sig, g_siglen);
    s_verify[i] = cycles() - t0;
    if (rc != 0) w->vfails++;
  }
}

// ---- Part B: largest message --------------------------------------------------------------
enum { TRIAL_OK = 0, TRIAL_NO_BUFFER, TRIAL_NO_TASK, TRIAL_SIGN_FAILED, TRIAL_VERIFY_FAILED };
static const char* const TRIAL_REASON[] = {"ok", "message_buffer_did_not_fit", "task_stack_did_not_fit",
                                           "sign_failed", "verify_failed"};

struct E2Trial {
  const SigAlgorithm* a;
  uint32_t len;
  int result;
  uint32_t sign_cycles;
};

static void e2_trial_task(void* p) {
  E2Trial* t = (E2Trial*)p;
  uint8_t* buf = (uint8_t*)heap_caps_malloc(t->len, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (!buf) {
    t->result = TRIAL_NO_BUFFER;
    return;
  }
  e2_fill(buf, t->len);
  uint32_t t0 = cycles();
  int rc = t->a->sign(buf, t->len, g_sig, &g_siglen);
  t->sign_cycles = cycles() - t0;
  if (rc != 0) t->result = TRIAL_SIGN_FAILED;
  else t->result = t->a->verify(buf, t->len, g_sig, g_siglen) == 0 ? TRIAL_OK : TRIAL_VERIFY_FAILED;
  heap_caps_free(buf);
}

static int e2_trial(const SigAlgorithm* a, uint32_t len, uint32_t stack, uint32_t* sign_cycles) {
  E2Trial t = {a, len, TRIAL_NO_TASK, 0};
  if (!run_in_task_stack(e2_trial_task, &t, stack, nullptr, true)) return TRIAL_NO_TASK;
  if (sign_cycles) *sign_cycles = t.sign_cycles;
  return t.result;
}

static void e2_largest(const SigAlgorithm* a, uint32_t stack) {
  size_t free0 = ESP.getFreeHeap();
  size_t largest0 = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  uint32_t lo = 64, hi = (uint32_t)largest0 + E2_SEARCH_STEP;   // lo must work, hi cannot fit
  uint32_t sc = 0, sc_lo = 0;
  int r = e2_trial(a, lo, stack, &sc_lo);
  if (r != TRIAL_OK) {
    Serial.printf("MAXMSG,%s,max_ok=0,first_fail=%u,reason=%s,stack_given=%u,free_heap=%u,largest_block=%u,"
                  "sign_ms_at_max=0\n", a->name, (unsigned)lo, TRIAL_REASON[r], (unsigned)stack,
                  (unsigned)free0, (unsigned)largest0);
    return;
  }
  while (hi - lo > E2_SEARCH_STEP) {
    uint32_t mid = lo + (hi - lo) / 2;
    if (e2_trial(a, mid, stack, &sc) == TRIAL_OK) {
      lo = mid;
      sc_lo = sc;
    } else {
      hi = mid;
    }
  }
  int reason = e2_trial(a, hi, stack, nullptr);
  Serial.printf("MAXMSG,%s,max_ok=%u,first_fail=%u,reason=%s,stack_given=%u,free_heap=%u,largest_block=%u,"
                "sign_ms_at_max=%.3f\n", a->name, (unsigned)lo, (unsigned)hi, TRIAL_REASON[reason],
                (unsigned)stack, (unsigned)free0, (unsigned)largest0, sc_lo / (CPU_MHZ * 1000.0));
}

// ---- Step 2 main -------------------------------------------------------------------------
void run_e2() {
  print_meta_common();
  Serial.printf("META,e2_runs,%d\n", E2_RUNS);
  Serial.print("META,e2_sizes,");
  for (int s = 0; s < E2_SIZE_COUNT; s++) Serial.printf(s ? " %u" : "%u", (unsigned)E2_SIZE_LIST[s]);
  Serial.println();
  Serial.printf("META,e2_stack_margin,%d\n", E2_STACK_MARGIN);
  Serial.printf("META,e2_search_step,%d\n", E2_SEARCH_STEP);
  Serial.println("META,timer,CPU cycle counter. RAW values are CPU cycles");

  uint32_t maxlen = 0;
  for (int s = 0; s < E2_SIZE_COUNT; s++) if (E2_SIZE_LIST[s] > maxlen) maxlen = E2_SIZE_LIST[s];

  int64_t t_start = esp_timer_get_time();
  for (int k = 0; k < ALGORITHM_COUNT; k++) {
    const SigAlgorithm* a = ALGORITHMS[k];
    Serial.printf("PROGRESS,%s,start (%s; %s)\n", a->name, a->library, a->security);
    size_t free_before = ESP.getFreeHeap();

    e2_ready = false;
    run_in_task(e2_prepare_task, (void*)a, nullptr);
    if (!e2_ready) {
      Serial.printf("ERROR,%s,known-answer test or key generation failed; skipped\n", a->name);
      a->free_bench_key();
      continue;
    }

    // Stack this algorithm needs for signing and verifying (measured), plus a margin
    uint32_t us = 0, uv = 0;
    g_probe_alg = a;
    run_in_task(probe_sign, nullptr, &us);
    run_in_task(probe_verify, nullptr, &uv);
    uint32_t need = us > uv ? us : uv;
    uint32_t stack = ((need + E2_STACK_MARGIN + 1023) / 1024) * 1024;
    Serial.printf("E2STACK,%s,measured=%u,given=%u\n", a->name, (unsigned)need, (unsigned)stack);

    // Part A
    uint8_t* buf = (uint8_t*)heap_caps_malloc(maxlen, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!buf) {
      Serial.printf("ERROR,%s,could not allocate the %u-byte message buffer\n", a->name, (unsigned)maxlen);
    } else {
      for (int s = 0; s < E2_SIZE_COUNT; s++) {
        uint32_t len = E2_SIZE_LIST[s];
        e2_fill(buf, len);
        E2Sweep w = {a, buf, len, 0, 0};
        Serial.printf("PROGRESS,%s,timing %d signatures and verifications of %u-byte messages\n",
                      a->name, E2_RUNS, (unsigned)len);
        Serial.flush();
        if (!run_in_task_stack(e2_sweep_task, &w, stack, nullptr)) continue;
        char op_s[24], op_v[24];
        snprintf(op_s, sizeof op_s, "sign_%u", (unsigned)len);
        snprintf(op_v, sizeof op_v, "verify_%u", (unsigned)len);
        print_raw(a->name, op_s, s_sign, E2_RUNS);
        print_raw(a->name, op_v, s_verify, E2_RUNS);
        print_stats(a->name, op_s, compute_stats(s_sign, E2_RUNS, w.sfails));
        print_stats(a->name, op_v, compute_stats(s_verify, E2_RUNS, w.vfails));
      }
      heap_caps_free(buf);
    }

    // Part B
    Serial.printf("PROGRESS,%s,searching for the largest message\n", a->name);
    Serial.flush();
    e2_largest(a, stack);

    a->free_bench_key();
    Serial.printf("LEAK,%s,free_before=%u,free_after=%u\n", a->name, (unsigned)free_before,
                  (unsigned)ESP.getFreeHeap());
  }
  Serial.printf("META,total_seconds,%.1f\n", (esp_timer_get_time() - t_start) / 1e6);
  Serial.println("### END PAYLOAD_BENCH");
}
