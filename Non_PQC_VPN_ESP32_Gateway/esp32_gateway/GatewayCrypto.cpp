#include "GatewayCrypto.h"
#include "gateway_config.h"

void GatewayCrypto::begin(const uint8_t seed[32]) {
  crypto_sign_seed_keypair(_publicKey, _secretKey, seed);
}

void GatewayCrypto::sign(const uint8_t* digest, size_t len, uint8_t signatureOut[64]) const {
  unsigned long long sigLen = 0;
  crypto_sign_detached(signatureOut, &sigLen, digest, len, _secretKey);
}

bool GatewayCrypto::verify(const uint8_t* publicKey, const uint8_t* signature,
                           const uint8_t* digest, size_t len) {
  return crypto_sign_verify_detached(signature, digest, len, publicKey) == 0;
}

void GatewayCrypto::serverTranscript(const uint8_t* msg1, const uint8_t* serverNonce,
                                     const uint8_t* serverEphPk, uint8_t out[32]) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)SERVER_TRANSCRIPT_LABEL, strlen(SERVER_TRANSCRIPT_LABEL));
  crypto_hash_sha256_update(&state, msg1, MSG1_CLIENT_HELLO_SIZE);
  crypto_hash_sha256_update(&state, serverNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_update(&state, serverEphPk, KEY_SHARE_LENGTH);
  crypto_hash_sha256_final(&state, out);
}

void GatewayCrypto::clientTranscript(const uint8_t* msg1, const uint8_t* msg2, uint8_t out[32]) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)CLIENT_TRANSCRIPT_LABEL, strlen(CLIENT_TRANSCRIPT_LABEL));
  crypto_hash_sha256_update(&state, msg1, MSG1_CLIENT_HELLO_SIZE);
  crypto_hash_sha256_update(&state, msg2, MSG2_SERVER_PROOF_SIZE);
  crypto_hash_sha256_final(&state, out);
}

void GatewayCrypto::deriveSessionKeys(const uint8_t sharedSecret[32], const uint8_t* clientNonce,
                                      const uint8_t* serverNonce, uint8_t kConfirm[32], uint8_t kSession[32]) {
  // salt = SHA-256(ClientNonce || ServerNonce)
  uint8_t salt[32];
  crypto_hash_sha256_state hState;
  crypto_hash_sha256_init(&hState);
  crypto_hash_sha256_update(&hState, clientNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_update(&hState, serverNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_final(&hState, salt);

  // PRK = HMAC-SHA256(salt, shared_secret)
  uint8_t prk[32];
  crypto_auth_hmacsha256(prk, sharedSecret, 32, salt);

  const size_t infoLen = strlen(KEY_DERIVATION_INFO);
  crypto_auth_hmacsha256_state hmacState;

  // T1 = HMAC-SHA256(PRK, info || 0x01) -> K_confirm
  const uint8_t c1 = 0x01;
  crypto_auth_hmacsha256_init(&hmacState, prk, sizeof(prk));
  crypto_auth_hmacsha256_update(&hmacState, (const unsigned char*)KEY_DERIVATION_INFO, infoLen);
  crypto_auth_hmacsha256_update(&hmacState, &c1, 1);
  crypto_auth_hmacsha256_final(&hmacState, kConfirm);

  // T2 = HMAC-SHA256(PRK, T1 || info || 0x02) -> K_session
  const uint8_t c2 = 0x02;
  crypto_auth_hmacsha256_init(&hmacState, prk, sizeof(prk));
  crypto_auth_hmacsha256_update(&hmacState, kConfirm, 32);
  crypto_auth_hmacsha256_update(&hmacState, (const unsigned char*)KEY_DERIVATION_INFO, infoLen);
  crypto_auth_hmacsha256_update(&hmacState, &c2, 1);
  crypto_auth_hmacsha256_final(&hmacState, kSession);

  sodium_memzero(prk, sizeof(prk));
  sodium_memzero(&hmacState, sizeof(hmacState));
}

void GatewayCrypto::confirmationTag(const uint8_t kConfirm[32], const char* roleLabel,
                                    const uint8_t transcriptDigest[32], uint8_t out[32]) {
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init(&state, kConfirm, 32);
  crypto_auth_hmacsha256_update(&state, (const unsigned char*)roleLabel, strlen(roleLabel));
  crypto_auth_hmacsha256_update(&state, transcriptDigest, 32);
  crypto_auth_hmacsha256_final(&state, out);
  sodium_memzero(&state, sizeof(state));
}
