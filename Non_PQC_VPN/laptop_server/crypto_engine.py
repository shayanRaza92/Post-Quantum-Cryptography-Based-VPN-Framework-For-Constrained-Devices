import os    # System library for generating cryptographically secure random bytes
import json  # Library to parse and read the JSON allowlist file
from cryptography.hazmat.primitives.asymmetric import ed25519  # Ed25519 signature algorithm library
from config import ALLOWLIST_FILE, SERVER_PRIVATE_SEED_HEX, CHALLENGE_NONCE_LENGTH  # Import config settings


class DeviceAllowlist:
    """Manages reading and verifying registered ESP32 devices from authorized_devices.json."""

    def __init__(self, file_path=ALLOWLIST_FILE):  # Constructor accepting allowlist file path
        self.file_path = file_path                 # Store the path to the JSON file

    def load_authorized_devices(self):  # Reads the allowlist JSON and returns {device_id: public_key_bytes}
        if not self.file_path.exists():  # Check if the allowlist file is missing on disk
            print(f"[WARN] Allowlist file not found: {self.file_path}")  # Show warning
            return {}  # Return empty dictionary if file doesn't exist

        try:  # Try opening and parsing the file
            with open(self.file_path, "r") as f:  # Open allowlist file for reading
                data = json.load(f)                # Parse JSON text into dictionary
                devices = {}                       # Dictionary to store clean 32-byte keys

                for device_id, hex_key in data.items():  # Iterate over each registered device entry
                    if device_id.startswith("_"):        # Skip comment or metadata entries
                        continue
                    try:
                        raw_key = bytes.fromhex(hex_key)  # Convert hex string (upper or lower) to raw bytes
                        if len(raw_key) == 32:             # Public keys must be exactly 32 bytes
                            devices[device_id] = raw_key   # Store valid public key under device_id
                    except ValueError:
                        pass                               # Ignore any malformed hex strings
                return devices                             # Return dictionary of authorized devices
        except Exception as e:
            print(f"[ERROR] Failed to read allowlist: {e}")  # Print error on failure
            return {}

    def get_device_public_key(self, device_id):  # Retrieves the registered public key for a device ID
        devices = self.load_authorized_devices()  # Reload allowlist so changes on disk are seen immediately
        return devices.get(device_id)             # Returns 32-byte public key or None if not registered


class GatewayCrypto:
    """Encapsulates the server's cryptographic keys and signature operations."""

    def __init__(self, private_seed_hex=SERVER_PRIVATE_SEED_HEX):  # Initialize server crypto engine
        seed_bytes = bytes.fromhex(private_seed_hex)                # Convert private seed hex to 32 bytes
        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes)  # Private key object
        self._public_key = self._private_key.public_key()          # Matching public key object
        self._public_bytes = self._public_key.public_bytes_raw()   # Raw 32 bytes of public key

    @property
    def public_bytes(self):  # Getter for raw public key bytes
        return self._public_bytes

    @property
    def public_hex(self):  # Getter for public key formatted as hexadecimal text
        return self._public_bytes.hex()

    def generate_challenge(self):  # Generates 32 fresh random bytes for a challenge nonce
        return os.urandom(CHALLENGE_NONCE_LENGTH)  # True random bytes from operating system

    def sign_challenge(self, nonce_bytes):  # Signs a client challenge nonce using server's private key
        return self._private_key.sign(nonce_bytes)  # Returns 64-byte Ed25519 signature

    def verify_client_signature(self, client_public_bytes, signature_bytes, challenge_nonce):
        """Verifies that the client signature was created by the owner of client_public_bytes."""
        try:
            client_pubkey_obj = ed25519.Ed25519PublicKey.from_public_bytes(client_public_bytes)
            client_pubkey_obj.verify(signature_bytes, challenge_nonce)  # Verify signature mathematically
            return True   # Math verified: client holds the real private key
        except Exception:
            return False  # Math failed: invalid signature or wrong key
