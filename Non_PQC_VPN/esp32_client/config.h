#ifndef VPN_CONFIG_H
#define VPN_CONFIG_H

#include <Arduino.h>

// --- Wi-Fi Network Credentials ---
const char* const WIFI_SSID     = "Redmi 13C";     // Name of your Wi-Fi network
const char* const WIFI_PASSWORD = "92144444";      // Password of your Wi-Fi network

// --- Server Network Settings ---
const char* const GATEWAY_IP      = "10.202.171.216"; // IP address of your laptop running the server
const uint16_t    GATEWAY_PORT    = 9000;             // Port number the server is listening on

// --- Device Identity Name ---
const char* const DEVICE_ID       = "esp32-01";       // Device ID name sent to check the allowlist

// --- Protocol Packet Sizes and Tokens ---
const size_t DEVICE_ID_LENGTH        = 16;  // Fixed 16-byte buffer for device ID packet
const size_t CHALLENGE_NONCE_LENGTH  = 32;  // 32-byte fresh random challenge nonce
const size_t SIGNATURE_LENGTH        = 64;  // 64-byte Ed25519 digital signature length
const char* const AUTH_CONFIRM_TOKEN = "AUTH_OK"; // 7-byte confirmation sent to server after verifying gateway

// --- Pinned Server Public Key ---
// Server's fixed public key saved here so ESP32 only trusts your laptop and ignores fake servers
const uint8_t TRUSTED_GATEWAY_PUBLIC_KEY[32] = {
  0x19, 0x1a, 0x24, 0x2d, 0xdd, 0x26, 0x7e, 0x20,
  0x58, 0x8d, 0x07, 0x6b, 0x12, 0xf4, 0x4c, 0x83,
  0x4f, 0xdd, 0xc7, 0xc5, 0x3d, 0x86, 0x78, 0x92,
  0x2e, 0xb1, 0x77, 0x59, 0xb1, 0x76, 0x73, 0xba
};

#endif // VPN_CONFIG_H
