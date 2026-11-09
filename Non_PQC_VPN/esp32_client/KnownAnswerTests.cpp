#include "KnownAnswerTests.h"
#include <Arduino.h>
#include <sodium.h>
#include "mbedtls/gcm.h"

static int gPassed = 0, gTotal = 0;

static void hexToBytes(const char* hex, uint8_t* out) {
  for (size_t i = 0; hex[2 * i]; i++) {
    char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
    out[i] = (uint8_t)strtoul(b, nullptr, 16);
  }
}

static bool equalsHex(const uint8_t* data, const char* hex) {
  uint8_t expected[64];
  size_t n = strlen(hex) / 2;
  hexToBytes(hex, expected);
  return memcmp(data, expected, n) == 0;
}

static void result(const char* name, const char* source, bool ok) {
  gTotal++;
  if (ok) gPassed++;
  Serial.printf("  %-44s %-34s %s\n", name, source, ok ? "PASS" : "FAIL");
  Serial.printf("BENCH,B0,kat_%s,1,%d,%d,%d,0,%d,%d,pass\n", name, ok, ok, ok, ok, ok);  // n,mean,median,p95,std,min,max
}

// SHA-256 of "abc" (FIPS 180-4 example)
static void katSha256() {
  uint8_t out[32];
  crypto_hash_sha256(out, (const uint8_t*)"abc", 3);
  result("sha256", "FIPS 180-4 example \"abc\"",
         equalsHex(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

// HMAC-SHA256, RFC 4231 test case 2 (key "Jefe")
static void katHmac() {
  uint8_t out[32];
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, (const uint8_t*)"Jefe", 4);
  crypto_auth_hmacsha256_update(&st, (const uint8_t*)"what do ya want for nothing?", 28);
  crypto_auth_hmacsha256_final(&st, out);
  result("hmac_sha256", "RFC 4231 test case 2",
         equalsHex(out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

// AES-256-GCM, NIST GCM spec test case 16 (with AAD), plus a 1-bit tamper check
static void katAesGcm() {
  static uint8_t key[32], iv[12], pt[60], aad[20], expCt[60], expTag[16], ct[60], tag[16], back[60];
  hexToBytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", key);
  hexToBytes("cafebabefacedbaddecaf888", iv);
  hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
             "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", pt);
  hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
  hexToBytes("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
             "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", expCt);
  hexToBytes("76fc6ece0f4e1768cddf8853bb2d551b", expTag);
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
  mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(pt), iv, 12, aad, sizeof(aad), pt, ct, 16, tag);
  bool enc = memcmp(ct, expCt, sizeof(ct)) == 0 && memcmp(tag, expTag, 16) == 0;
  bool dec = mbedtls_gcm_auth_decrypt(&ctx, sizeof(ct), iv, 12, aad, sizeof(aad), tag, 16, ct, back) == 0 &&
             memcmp(back, pt, sizeof(pt)) == 0;
  tag[0] ^= 0x01;
  bool tamper = mbedtls_gcm_auth_decrypt(&ctx, sizeof(ct), iv, 12, aad, sizeof(aad), tag, 16, ct, back) != 0;
  mbedtls_gcm_free(&ctx);
  result("aes256_gcm_encrypt", "NIST GCM test case 16", enc);
  result("aes256_gcm_decrypt", "NIST GCM test case 16", dec);
  result("aes256_gcm_tamper_rejected", "1 flipped tag bit", tamper);
}

// Ed25519, RFC 8032 section 7.1 test 1 (empty message)
static void katEd25519() {
  uint8_t seed[32], pk[32], sk[64], sig[64];
  hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed);
  crypto_sign_seed_keypair(pk, sk, seed);
  unsigned long long sigLen = 0;
  crypto_sign_detached(sig, &sigLen, (const uint8_t*)"", 0, sk);
  result("ed25519_keygen", "RFC 8032 7.1 test 1",
         equalsHex(pk, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
  result("ed25519_sign", "RFC 8032 7.1 test 1",
         equalsHex(sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155") &&
         equalsHex(sig + 32, "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));
  bool ok = crypto_sign_verify_detached(sig, (const uint8_t*)"", 0, pk) == 0;
  sig[10] ^= 0x01;
  bool tamper = crypto_sign_verify_detached(sig, (const uint8_t*)"", 0, pk) != 0;
  result("ed25519_verify_and_tamper", "RFC 8032 7.1 test 1", ok && tamper);
  sodium_memzero(sk, sizeof(sk));
}

// X25519, RFC 7748 section 5.2 first test vector
static void katX25519() {
  uint8_t scalar[32], u[32], out[32];
  hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar);
  hexToBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
  bool ok = crypto_scalarmult(out, scalar, u) == 0 &&
            equalsHex(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
  result("x25519", "RFC 7748 5.2 vector 1", ok);
}

bool runKnownAnswerTests() {
  gPassed = gTotal = 0;
  katSha256();
  katHmac();
  katAesGcm();
  katEd25519();
  katX25519();
  Serial.printf("  => %d / %d known-answer tests passed\n", gPassed, gTotal);
  return gPassed == gTotal;
}
