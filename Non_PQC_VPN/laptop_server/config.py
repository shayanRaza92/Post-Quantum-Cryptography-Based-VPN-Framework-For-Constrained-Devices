from pathlib import Path  # Helps safely find file paths regardless of the operating system

# --- Network Configuration ---
HOST = "0.0.0.0"          # Listen on all network adapters (Wi-Fi, Ethernet, localhost)
PORT = 9000               # Port number where the VPN gateway listens for ESP32 clients
HANDSHAKE_TIMEOUT = 10.0  # Seconds allowed for an incoming client to complete the handshake

# --- Protocol Packet Sizes and Tokens ---
DEVICE_ID_LENGTH = 16        # ESP32 sends a 16-byte fixed-width name string (e.g. "esp32-01")
CHALLENGE_NONCE_LENGTH = 32  # 32-byte fresh random challenge number
SIGNATURE_LENGTH = 64        # Ed25519 digital signatures are always exactly 64 bytes long
CONFIRMATION_TAG_LENGTH = 32  # 32-byte SHA-256 confirmation tag sent by client after verifying server proof

# --- Path to Allowlist File ---
ALLOWLIST_FILE = Path(__file__).parent / "authorized_devices.json"  # File with approved ESP32 public keys

# --- Server Identity Configuration ---
# Fixed 32-byte secret seed used to generate the laptop gateway's private and public keys
SERVER_PRIVATE_SEED_HEX = "c765812d5a94054cbbead0e4335b248329891fbc0343fbee337d2399db1186fb"
