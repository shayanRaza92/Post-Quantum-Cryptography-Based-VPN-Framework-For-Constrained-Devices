from pathlib import Path  # Helps safely find file paths regardless of the operating system

# --- Network Configuration ---
HOST = "0.0.0.0"           # Listen on all network adapters (Wi-Fi, Ethernet, localhost)
PORT = 9000                # Port number where the VPN gateway listens for ESP32 clients
HANDSHAKE_TIMEOUT = 15.0   # Overall seconds allowed for an incoming client to complete the PQC handshake
TUNNEL_IDLE_TIMEOUT = 30.0 # Inactivity timeout in seconds before closing an idle authenticated tunnel

# --- Protocol Version & Algorithm Identifiers ---
PROTOCOL_VERSION = 0x01    # Protocol Version 1
ALGORITHM_ID = 0x03        # Suite 3: ML-DSA-44-Auth (FIPS 204) + ML-KEM-512-KEX (FIPS 203) + HKDF-SHA256

# --- Protocol Packet Sizes and Tokens (4-Way Mutual Auth with ML-DSA-44 & Ephemeral ML-KEM-512 KEX) ---
DEVICE_ID_LENGTH = 16         # ESP32 sends a 16-byte fixed-width name string (e.g. "esp32-01")
CHALLENGE_NONCE_LENGTH = 32   # 32-byte fresh random challenge number
KEM_PUBLIC_KEY_LENGTH = 800   # NIST FIPS 203 ML-KEM-512 encapsulation key ek (800 bytes)
KEM_SECRET_KEY_LENGTH = 1632  # NIST FIPS 203 ML-KEM-512 decapsulation key dk (1,632 bytes)
KEM_CIPHERTEXT_LENGTH = 768   # NIST FIPS 203 ML-KEM-512 ciphertext ct (768 bytes)
KEM_SHARED_SECRET_LENGTH = 32 # ML-KEM shared secret K (32 bytes)
KEY_CONFIRM_LENGTH = 32       # 32-byte HMAC-SHA256 key confirmation tag
PUBLIC_KEY_LENGTH = 1312      # NIST FIPS 204 ML-DSA-44 public key length (1,312 bytes)
SECRET_KEY_LENGTH = 2560      # NIST FIPS 204 ML-DSA-44 secret key length (2,560 bytes)
SIGNATURE_LENGTH = 2420       # NIST FIPS 204 ML-DSA-44 signature length (2,420 bytes)

MSG1_CLIENT_HELLO_SIZE = 850   # 1B Ver + 1B AlgID + 16B ID + 32B Nonce + 800B ML-KEM-512 ek
MSG2_SERVER_PROOF_SIZE = 3220  # 32B Nonce + 768B ML-KEM-512 ct + 2420B ML-DSA-44 Signature
MSG3_CLIENT_PROOF_SIZE = 2452  # 2420B ML-DSA-44 Signature + 32B Key Confirmation Tag
MSG4_AUTH_VERDICT_SIZE = 40    # 8B "AUTH_OK\n" token + 32B Server Confirmation Tag
AUTH_OK_TOKEN = b"AUTH_OK\n"   # 8-byte confirmation token
AUTH_FAIL_TOKEN = b"AUTH_NO\n" # 8-byte rejection token (sent when client proof fails)

# --- Transcript Role Labels (domain separation) ---
SERVER_TRANSCRIPT_LABEL = b"VPN-v1|SERVER|"
CLIENT_TRANSCRIPT_LABEL = b"VPN-v1|CLIENT|"
CLIENT_CONFIRM_LABEL = b"VPN-v1|CLIENT-CONFIRM|"
SERVER_CONFIRM_LABEL = b"VPN-v1|SERVER-CONFIRM|"
KEY_DERIVATION_INFO = b"VPN-v1|KEY-DERIVATION"

# --- Handshake DoS Limits ---
MAX_CONCURRENT_HANDSHAKES = 8     # Max sessions handshaking at the same time (global)
RATE_LIMIT_WINDOW_SEC = 10.0      # Sliding window for per-IP rate limiting
RATE_LIMIT_MAX_PER_IP = 5         # Max new connections per IP within the window
MAX_HANDSHAKES_PER_IP = 2         # Max simultaneous in-progress handshakes from one IP
                                  # (stops one host from holding every global handshake slot)

# --- Multi-Device Tunnel Limits ---
ALLOWLIST_RECHECK_INTERVAL = 5.0  # Seconds between allowlist re-checks for live tunnels (revocation)
TUNNEL_POLL_INTERVAL = 1.0        # Socket read timeout inside the tunnel loop (drives the checks above)

# --- In-Tunnel Rekeying Policy (enforced per device; the ESP32 rekeys at 1000 messages / 300 s) ---
REKEY_MAX_MESSAGES = 2000         # Max frames a device may send with one key; more => close that session
REKEY_MAX_SECONDS = 600.0         # Max age of one key; older => close that session
REKEY_MIN_INTERVAL = 5.0          # Rekey requests closer together than this => close (stops rekey flooding)

# --- Paths to Allowlist File & Native mldsa-native / mlkem-native Shared Libraries ---
# Build both with ./build_native_libs.sh (or copy your existing libmldsa44.so from PQC_VPN/laptop_server)
ALLOWLIST_FILE = Path(__file__).parent / "authorized_devices.json"
MLDSA44_SO_PATH = Path(__file__).parent / "libmldsa44.so"
MLKEM512_SO_PATH = Path(__file__).parent / "libmlkem512.so"

# --- Server Identity Configuration ---
# Fixed 32-byte secret seed used to deterministically derive the laptop gateway's ML-DSA-44 keypair
SERVER_PRIVATE_SEED_HEX = "c765812d5a94054cbbead0e4335b248329891fbc0343fbee337d2399db1186fb"

