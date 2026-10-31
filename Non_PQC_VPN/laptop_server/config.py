from pathlib import Path  # Helps safely find file paths regardless of the operating system

# --- Network Configuration ---
HOST = "0.0.0.0"          # Listen on all network adapters (Wi-Fi, Ethernet, localhost)
PORT = 9000               # Port number where the VPN gateway listens for ESP32 clients
HANDSHAKE_TIMEOUT = 10.0  # Overall seconds allowed for an incoming client to complete the handshake
TUNNEL_IDLE_TIMEOUT = 30.0 # Inactivity timeout in seconds before closing an idle authenticated tunnel

# --- Protocol Version & Algorithm Identifiers ---
PROTOCOL_VERSION = 0x01   # Protocol Version 1
ALGORITHM_ID = 0x01       # Suite 1: Ed25519-Auth + X25519-KEX + HKDF-SHA256

# --- Protocol Packet Sizes and Tokens (4-Way Mutual Auth with Ephemeral X25519 Key Exchange) ---
DEVICE_ID_LENGTH = 16        # ESP32 sends a 16-byte fixed-width name string (e.g. "esp32-01")
CHALLENGE_NONCE_LENGTH = 32  # 32-byte fresh random challenge number
KEY_SHARE_LENGTH = 32        # 32-byte X25519 ephemeral public key share
KEY_CONFIRM_LENGTH = 32      # 32-byte HMAC-SHA256 key confirmation tag
SIGNATURE_LENGTH = 64        # Ed25519 digital signatures are always exactly 64 bytes long

MSG1_CLIENT_HELLO_SIZE = 82  # 1B Ver + 1B AlgID + 16B ID + 32B Nonce + 32B X25519 Share
MSG2_SERVER_PROOF_SIZE = 128 # 32B Nonce + 32B X25519 Share + 64B Ed25519 Signature
MSG3_CLIENT_PROOF_SIZE = 96  # 64B Ed25519 Signature + 32B Key Confirmation Tag
MSG4_AUTH_VERDICT_SIZE = 40  # 8B "AUTH_OK\n" token + 32B Server Confirmation Tag
AUTH_OK_TOKEN = b"AUTH_OK\n" # 8-byte confirmation token
AUTH_FAIL_TOKEN = b"AUTH_NO\n" # 8-byte rejection token (sent when client proof fails)

# --- Transcript Role Labels (domain separation) ---
SERVER_TRANSCRIPT_LABEL = b"VPN-v1|SERVER|"
CLIENT_TRANSCRIPT_LABEL = b"VPN-v1|CLIENT|"
CLIENT_CONFIRM_LABEL = b"VPN-v1|CLIENT-CONFIRM|"
SERVER_CONFIRM_LABEL = b"VPN-v1|SERVER-CONFIRM|"
KEY_DERIVATION_INFO = b"VPN-v1|KEY-DERIVATION"

# --- Handshake DoS Limits (server signs before the client proves anything) ---
MAX_CONCURRENT_HANDSHAKES = 8     # Max sessions handshaking at the same time (global)
RATE_LIMIT_WINDOW_SEC = 10.0      # Sliding window for per-IP rate limiting
RATE_LIMIT_MAX_PER_IP = 5         # Max new connections per IP within the window

# --- Path to Allowlist File ---
ALLOWLIST_FILE = Path(__file__).parent / "authorized_devices.json"  # File with approved ESP32 public keys

# --- Server Identity Configuration ---
# Fixed 32-byte secret seed used to generate the laptop gateway's private and public keys
SERVER_PRIVATE_SEED_HEX = "c765812d5a94054cbbead0e4335b248329891fbc0343fbee337d2399db1186fb"
