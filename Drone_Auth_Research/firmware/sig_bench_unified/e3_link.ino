// e3_link.ino - Step 3 (experiment E3): drone authentication over a real Wi-Fi link.
// Started by sending "W". Needs ENABLE_LINK_TEST 1 (bench_config.h) and the Wi-Fi settings in
// link_config.h. The ground station is tools/gcs_link_test.py on the laptop.
//
// The ESP32 plays the drone. The ground station sends a random challenge; the drone signs
// [header | challenge, drone id, drone clock, data] and sends it back, either as ONE UDP datagram
// (style "udp": the IP layer splits it if it is bigger than a Wi-Fi packet) or cut into
// MAVLink-sized frames of at most 255 payload bytes (style "mav"). The ground station verifies
// it. Wireshark on the laptop records every packet. Message formats: link_protocol.h.
//
// Signing runs in a task with a 64 KB stack on core 1; Wi-Fi runs on core 0. Wi-Fi power
// saving is switched off, so the radio answers at once.

#include "link_protocol.h"

#if ENABLE_LINK_TEST
#include <WiFi.h>
#include "lwip/sockets.h"
#include "link_config.h"

static int s_sock = -1;
static uint8_t s_tx[HDR_LEN + MAX_DATA_LEN + MAX_SIG_BYTES];   // one whole message
static uint8_t s_rx[1500];
static uint8_t s_frame[FRAME_HDR_LEN + MAV_PAYLOAD];
static int s_cur_alg = -1;
static uint32_t s_send_retries = 0, s_auth_sent = 0, s_accepted = 0, s_rejected = 0;

static void put16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t* p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (24 - 8 * i)); }
static uint16_t get16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

static void put_header(uint8_t* m, uint8_t type, uint8_t alg, uint8_t style, uint16_t seq, uint16_t dlen,
                       uint16_t slen) {
  m[0] = 'D'; m[1] = 'A'; m[2] = LINK_VERSION; m[3] = type; m[4] = alg; m[5] = style;
  put16(m + 6, seq); put16(m + 8, dlen); put16(m + 10, slen);
}

// sendto, waiting briefly whenever the Wi-Fi driver has no free buffer (counted as a retry)
static int send_datagram(const sockaddr_in* to, const uint8_t* buf, size_t len) {
  for (int attempt = 0; attempt < 500; attempt++) {
    int r = sendto(s_sock, buf, len, 0, (const sockaddr*)to, sizeof(*to));
    if (r == (int)len) return 0;
    s_send_retries++;
    vTaskDelay(1);
  }
  return -1;
}

static int send_message(const sockaddr_in* to, const uint8_t* msg, size_t len, uint8_t style) {
  if (style == 0) return send_datagram(to, msg, len);
  uint8_t count = (uint8_t)((len + MAV_PAYLOAD - 1) / MAV_PAYLOAD);
  for (uint8_t idx = 0; idx < count; idx++) {
    size_t off = (size_t)idx * MAV_PAYLOAD;
    size_t n = len - off < MAV_PAYLOAD ? len - off : MAV_PAYLOAD;
    s_frame[0] = 'D'; s_frame[1] = 'F'; s_frame[2] = msg[3]; s_frame[3] = msg[4];
    s_frame[4] = msg[6]; s_frame[5] = msg[7];             // sequence of the whole message
    s_frame[6] = idx; s_frame[7] = count;
    put16(s_frame + 8, (uint16_t)n);
    memcpy(s_frame + FRAME_HDR_LEN, msg + off, n);
    if (send_datagram(to, s_frame, FRAME_HDR_LEN + n) != 0) return -1;
  }
  return 0;
}

// Make the key for one algorithm (after its known-answer test) and send the public key
static void handle_getkey(const sockaddr_in* from, uint8_t alg, uint16_t seq) {
  if (alg >= ALGORITHM_COUNT) return;
  if (s_cur_alg >= 0) ALGORITHMS[s_cur_alg]->free_bench_key();
  s_cur_alg = -1;
  const SigAlgorithm* a = ALGORITHMS[alg];
  bool kat = a->kat();
  Serial.printf("KAT,%s,%s\n", a->name, kat ? "PASS" : "FAIL");
  if (!kat || a->make_bench_key() != 0) {
    Serial.printf("ERROR,%s,known-answer test or key generation failed\n", a->name);
    return;
  }
  s_cur_alg = alg;
  size_t pklen = a->export_pk(s_tx + HDR_LEN, MAX_SIG_BYTES);
  put_header(s_tx, MSG_PUBKEY, alg, 0, seq, 0, (uint16_t)pklen);
  send_datagram(from, s_tx, HDR_LEN + pklen);
  Serial.printf("KEY,%s,public_key_bytes=%u\n", a->name, (unsigned)pklen);
}

// Answer one challenge: build the data, sign it, send it, then send the drone-side timings
static void handle_challenge(const sockaddr_in* from, const uint8_t* rx, int n) {
  uint8_t alg = rx[4], style = rx[5];
  uint16_t seq = get16(rx + 6), dlen = get16(rx + 8);
  if (alg != s_cur_alg || n < HDR_LEN + 32 || dlen < MIN_DATA_LEN || dlen > MAX_DATA_LEN || style > 1) return;
  int64_t t_rx = esp_timer_get_time();
  const SigAlgorithm* a = ALGORITHMS[alg];

  // data = challenge (32) | drone id (16) | drone clock in us (8) | data bytes up to dlen
  uint8_t* d = s_tx + HDR_LEN;
  memcpy(d, rx + HDR_LEN, 32);
  memset(d + 32, 0, 16);
  strncpy((char*)d + 32, LINK_DRONE_ID, 16);
  uint64_t clk = (uint64_t)t_rx;
  for (int i = 0; i < 8; i++) d[48 + i] = (uint8_t)(clk >> (56 - 8 * i));
  e2_fill(d + MIN_DATA_LEN, dlen - MIN_DATA_LEN);      // stands in for telemetry / sensor data

  // Signed: the header with the signature-length field set to 0, followed by the data
  put_header(s_tx, MSG_AUTH, alg, style, seq, dlen, 0);
  size_t siglen = 0;
  uint32_t c0 = cycles();
  int rc = a->sign(s_tx, HDR_LEN + dlen, s_tx + HDR_LEN + dlen, &siglen);
  uint32_t sign_cycles = cycles() - c0;
  if (rc != 0) return;
  put16(s_tx + 10, (uint16_t)siglen);

  uint32_t retries_before = s_send_retries;
  send_message(from, s_tx, HDR_LEN + dlen + siglen, style);
  int64_t t_sent = esp_timer_get_time();
  s_auth_sent++;

  // Drone-side timings (measurement only, not part of the protocol)
  uint8_t st[HDR_LEN + 16];
  put_header(st, MSG_STAT, alg, style, seq, 16, 0);
  put32(st + HDR_LEN, (uint32_t)(sign_cycles / CPU_MHZ));             // signing time, us
  put32(st + HDR_LEN + 4, (uint32_t)(t_sent - t_rx));                 // challenge in -> last byte out, us
  put32(st + HDR_LEN + 8, s_send_retries - retries_before);           // waits for a Wi-Fi buffer
  put32(st + HDR_LEN + 12, (uint32_t)ESP.getFreeHeap());
  send_datagram(from, st, sizeof st);
}

static void e3_server_task(void*) {
  sockaddr_in bcast = {};
  bcast.sin_family = AF_INET;
  bcast.sin_port = htons(LINK_PORT);
  bcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);
  bool gcs_known = false;
  uint32_t last_hello = 0;
  while (true) {
    if (!gcs_known && millis() - last_hello > 1000) {
      uint8_t h[HDR_LEN + 16] = {};
      put_header(h, MSG_HELLO, (uint8_t)ALGORITHM_COUNT, 0, 0, 16, 0);
      strncpy((char*)h + HDR_LEN, LINK_DRONE_ID, 16);
      sendto(s_sock, h, sizeof h, 0, (const sockaddr*)&bcast, sizeof bcast);
      last_hello = millis();
    }
    sockaddr_in from = {};
    socklen_t flen = sizeof from;
    int n = recvfrom(s_sock, s_rx, sizeof s_rx, 0, (sockaddr*)&from, &flen);
    if (n < HDR_LEN || s_rx[0] != 'D' || s_rx[1] != 'A' || s_rx[2] != LINK_VERSION) continue;
    if (!gcs_known) {
      gcs_known = true;
      Serial.printf("LINK,ground station %s\n", inet_ntoa(from.sin_addr));
    }
    uint8_t type = s_rx[3];
    if (type == MSG_GETKEY) handle_getkey(&from, s_rx[4], get16(s_rx + 6));
    else if (type == MSG_CHALLENGE) handle_challenge(&from, s_rx, n);
    else if (type == MSG_RESULT) (s_rx[HDR_LEN] == 1 ? s_accepted : s_rejected)++;
    else if (type == MSG_DONE) break;
  }
  if (s_cur_alg >= 0) ALGORITHMS[s_cur_alg]->free_bench_key();
}

void run_e3() {
  print_meta_common();
  Serial.printf("META,link,udp port %d, MAVLink-sized frames of %d payload bytes\n", LINK_PORT, MAV_PAYLOAD);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(LINK_WIFI_SSID, LINK_WIFI_PASSWORD);
  Serial.printf("PROGRESS,link,connecting to Wi-Fi \"%s\"\n", LINK_WIFI_SSID);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) delay(200);
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("ERROR,link,could not connect to Wi-Fi (check link_config.h)");
    Serial.println("### END LINK_TEST");
    return;
  }
  Serial.printf("META,drone_ip,%s\n", WiFi.localIP().toString().c_str());
  Serial.printf("META,wifi_rssi_dbm,%d\n", (int)WiFi.RSSI());
  Serial.printf("META,wifi_channel,%d\n", (int)WiFi.channel());

  s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  int yes = 1;
  setsockopt(s_sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof yes);
  timeval tv = {1, 0};
  setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  sockaddr_in me = {};
  me.sin_family = AF_INET;
  me.sin_port = htons(LINK_PORT);
  me.sin_addr.s_addr = htonl(INADDR_ANY);
  if (s_sock < 0 || bind(s_sock, (const sockaddr*)&me, sizeof me) != 0) {
    Serial.println("ERROR,link,could not open the UDP socket");
    Serial.println("### END LINK_TEST");
    return;
  }
  Serial.println("PROGRESS,link,waiting for the ground station (start tools/gcs_link_test.py)");
  Serial.flush();
  int64_t t_start = esp_timer_get_time();
  run_in_task_stack(e3_server_task, nullptr, 64 * 1024, nullptr);
  close(s_sock);
  Serial.printf("LINKSUM,auth_sent=%u,accepted=%u,rejected=%u,send_retries=%u\n", (unsigned)s_auth_sent,
                (unsigned)s_accepted, (unsigned)s_rejected, (unsigned)s_send_retries);
  Serial.printf("META,total_seconds,%.1f\n", (esp_timer_get_time() - t_start) / 1e6);
  Serial.println("### END LINK_TEST");
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
}

#else   // ENABLE_LINK_TEST == 0: Wi-Fi is not built in

void run_e3() {
  Serial.println("ERROR,link,Step 3 is not built in. Set ENABLE_LINK_TEST to 1 in bench_config.h "
                 "and the Wi-Fi settings in link_config.h, then upload again.");
  Serial.println("### END LINK_TEST");
}

#endif
