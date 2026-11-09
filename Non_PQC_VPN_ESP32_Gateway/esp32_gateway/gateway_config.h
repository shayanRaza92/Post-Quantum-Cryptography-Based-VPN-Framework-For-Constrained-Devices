#ifndef GATEWAY_CONFIG_H
#define GATEWAY_CONFIG_H

#include <Arduino.h>

// ============================================================================
// ESP32 GATEWAY CONFIGURATION
// This ESP32 replaces the laptop gateway (laptop_server/server.py).
// It creates its own Wi-Fi network and runs the server side of the same
// 4-message handshake, so the ESP32 clients need no protocol changes.
// ============================================================================

// --- Wi-Fi Access Point (the gateway creates its own network, no router needed) ---
const char* const AP_SSID         = "ESP32-VPN-GW";   // Network name the clients join
const char* const AP_PASSWORD     = "vpngw2026";      // WPA2 password (must be at least 8 characters)
const uint8_t     AP_CHANNEL      = 6;                // Wi-Fi channel 1..13
const uint8_t     AP_MAX_STATIONS = 8;                // Max ESP32 clients joined to the AP (ESP32 limit: 10)
// Gateway IP is the ESP32 SoftAP default: 192.168.4.1 (put this in the clients' config.h)

// --- Server Network Settings ---
const uint16_t GATEWAY_PORT = 9000;                   // TCP port the gateway listens on

// --- Protocol Version & Algorithm Identifiers (must match the clients) ---
const uint8_t PROTOCOL_VERSION = 0x01;                // Protocol Version 1
const uint8_t ALGORITHM_ID     = 0x01;                // Suite 1: Ed25519-Auth + X25519-KEX + HKDF-SHA256

// --- Protocol Packet Sizes ---
const size_t DEVICE_ID_LENGTH       = 16;             // Fixed 16-byte zero-padded device ID field
const size_t CHALLENGE_NONCE_LENGTH = 32;             // 32-byte fresh random nonce
const size_t KEY_SHARE_LENGTH       = 32;             // 32-byte X25519 ephemeral public key
const size_t KEY_CONFIRM_LENGTH     = 32;             // 32-byte HMAC-SHA256 confirmation tag
const size_t SIGNATURE_LENGTH       = 64;             // 64-byte Ed25519 signature

const size_t MSG1_CLIENT_HELLO_SIZE = 82;             // 1B Ver + 1B AlgID + 16B ID + 32B Nonce + 32B X25519 Share
const size_t MSG2_SERVER_PROOF_SIZE = 128;            // 32B Nonce + 32B X25519 Share + 64B Ed25519 Signature
const size_t MSG3_CLIENT_PROOF_SIZE = 96;             // 64B Ed25519 Signature + 32B Key Confirmation Tag
const size_t MSG4_TOKEN_SIZE        = 8;              // "AUTH_OK\n" or "AUTH_NO\n"

const char* const AUTH_OK_TOKEN   = "AUTH_OK\n";
const char* const AUTH_FAIL_TOKEN = "AUTH_NO\n";

// --- Transcript Role Labels (domain separation, identical to the laptop gateway) ---
const char* const SERVER_TRANSCRIPT_LABEL = "VPN-v1|SERVER|";
const char* const CLIENT_TRANSCRIPT_LABEL = "VPN-v1|CLIENT|";
const char* const CLIENT_CONFIRM_LABEL    = "VPN-v1|CLIENT-CONFIRM|";
const char* const SERVER_CONFIRM_LABEL    = "VPN-v1|SERVER-CONFIRM|";
const char* const KEY_DERIVATION_INFO     = "VPN-v1|KEY-DERIVATION";

// --- Gateway Identity (Ed25519) ---
// Same 32-byte seed as the laptop gateway (SERVER_PRIVATE_SEED_HEX in laptop_server/config.py).
// It produces public key 191A242D...B17673BA, which is already pinned in every client's
// TRUSTED_GATEWAY_PUBLIC_KEY, so the clients trust this ESP32 gateway without any key change.
// NOTE: anyone who reads this seed can impersonate the gateway. For a real deployment,
// generate a new seed, keep it out of the repository, and update the clients' pinned key.
const uint8_t GATEWAY_PRIVATE_SEED[32] = {
  0xc7, 0x65, 0x81, 0x2d, 0x5a, 0x94, 0x05, 0x4c,
  0xbb, 0xea, 0xd0, 0xe4, 0x33, 0x5b, 0x24, 0x83,
  0x29, 0x89, 0x1f, 0xbc, 0x03, 0x43, 0xfb, 0xee,
  0x33, 0x7d, 0x23, 0x99, 0xdb, 0x11, 0x86, 0xfb
};

// --- Allowlist (replaces laptop_server/authorized_devices.json) ---
// Each client prints its "Device Public Key" on the Serial Monitor at boot: copy it here.
// Devices can also be revoked / re-allowed at runtime with Serial commands (see README);
// that choice is saved in flash and survives a reboot.
struct AuthorizedDevice {
  const char* deviceId;      // 1..16 chars: letters, digits, '-' or '_'
  uint8_t     publicKey[32]; // Device's Ed25519 identity public key
};

const AuthorizedDevice AUTHORIZED_DEVICES[] = {
  { "esp32-01", {
      0xcc, 0x2a, 0x07, 0xf4, 0x6b, 0xf5, 0xa9, 0xaa,
      0x5f, 0x77, 0x8f, 0x3f, 0x56, 0x26, 0x79, 0xe2,
      0x2a, 0x07, 0x8f, 0xf7, 0xa3, 0xfb, 0x30, 0x6d,
      0xd7, 0x18, 0xbf, 0xce, 0x43, 0xb1, 0x67, 0xa8 } },
  { "esp32-02", {
      0xa7, 0x42, 0xa7, 0xf4, 0x5f, 0x15, 0xe6, 0x8e,
      0x69, 0x67, 0xa4, 0x14, 0x2a, 0x3e, 0xf8, 0x72,
      0x74, 0x75, 0xad, 0xed, 0x9b, 0xd8, 0xf6, 0x99,
      0xa1, 0x12, 0xd5, 0x1c, 0x6e, 0xe2, 0xd6, 0x9f } },
  { "esp32-03", {
      0xd6, 0xf8, 0x6a, 0x48, 0x93, 0x8a, 0x76, 0xaa,
      0xde, 0x9b, 0xdf, 0x8e, 0x95, 0x94, 0x28, 0x59,
      0xfc, 0x3b, 0x5f, 0xe8, 0xe3, 0xd7, 0x45, 0xdf,
      0x99, 0x85, 0x47, 0x33, 0x28, 0x4f, 0x1d, 0x38 } },
};
const size_t AUTHORIZED_DEVICE_COUNT = sizeof(AUTHORIZED_DEVICES) / sizeof(AUTHORIZED_DEVICES[0]);

// --- Multi-Device Limits (one bad client must never affect the others) ---
const uint8_t       MAX_SESSIONS              = 6;      // Max TCP connections at once (handshaking + tunnels)
const uint8_t       MAX_CONCURRENT_HANDSHAKES = 4;      // Max handshakes in progress at once (global)
const uint8_t       MAX_HANDSHAKES_PER_IP     = 2;      // Max handshakes in progress from one client IP
const unsigned long HANDSHAKE_TIMEOUT_MS      = 10000;  // Whole handshake must finish within 10 s
const unsigned long TUNNEL_IDLE_TIMEOUT_MS    = 30000;  // Close a tunnel after 30 s with no data
const unsigned long TUNNEL_POLL_MS            = 1000;   // Tunnel read timeout (drives revocation/idle checks)
const uint32_t      SESSION_TASK_STACK_BYTES  = 12288;  // Per-session FreeRTOS task stack (Ed25519 needs ~4 KB)

// --- In-Tunnel Rekeying Policy (enforced per client; the clients rekey at 100 messages / 300 s) ---
const uint64_t      REKEY_MAX_MESSAGES        = 200;     // Max frames a client may send with one key
const unsigned long REKEY_MAX_MS              = 600000;  // Max age of one key (10 minutes)
const unsigned long REKEY_MIN_INTERVAL_MS     = 5000;    // Rekey requests closer together => close (anti-flooding)

#endif // GATEWAY_CONFIG_H
