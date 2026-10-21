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

    @staticmethod
    def build_transcript_hash(role: str, device_id: str, server_nonce: bytes, client_nonce: bytes) -> bytes:
        """
        Constructs a domain-separated cryptographic transcript hash (SHA-256).
        Format: "VPN-AUTH-v1|" + role + "|" + device_id + "|" + server_nonce + "|" + client_nonce
        Prevents blind signing, relay attacks, and cross-protocol replay.
        """
        import hashlib
        hasher = hashlib.sha256()
        hasher.update(b"VPN-AUTH-v1|")
        hasher.update(role.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(device_id.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(server_nonce)
        hasher.update(b"|")
        hasher.update(client_nonce)
        return hasher.digest()

    def sign_transcript(self, role: str, device_id: str, server_nonce: bytes, client_nonce: bytes) -> bytes:
        """Signs the domain-separated transcript hash for this session using server's private key."""
        digest = self.build_transcript_hash(role, device_id, server_nonce, client_nonce)
        return self._private_key.sign(digest)

    def verify_client_transcript(self, client_public_bytes: bytes, signature_bytes: bytes, device_id: str, server_nonce: bytes, client_nonce: bytes) -> bool:
        """Verifies that the client's signature matches the domain-separated transcript hash."""
        digest = self.build_transcript_hash("CLIENT", device_id, server_nonce, client_nonce)
        try:
            client_pubkey_obj = ed25519.Ed25519PublicKey.from_public_bytes(client_public_bytes)
            client_pubkey_obj.verify(signature_bytes, digest)
            return True
        except Exception:
            return False

    def sign_challenge(self, nonce_bytes):  # Legacy fallback: signs raw nonce
        return self._private_key.sign(nonce_bytes)

    def verify_client_signature(self, client_public_bytes, signature_bytes, challenge_nonce):
        """Legacy fallback: verifies signature over raw nonce."""
        try:
            client_pubkey_obj = ed25519.Ed25519PublicKey.from_public_bytes(client_public_bytes)
            client_pubkey_obj.verify(signature_bytes, challenge_nonce)
            return True
        except Exception:
            return False
