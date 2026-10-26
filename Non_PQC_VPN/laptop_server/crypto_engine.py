import os    # System library for generating cryptographically secure random bytes
import json  # Library to parse and read the JSON allowlist file
import hashlib # Standard SHA-256 digest library
import threading # Lock protecting the shared allowlist cache across session threads
from cryptography.hazmat.primitives.asymmetric import ed25519  # Ed25519 signature algorithm library
from config import (ALLOWLIST_FILE, SERVER_PRIVATE_SEED_HEX, CHALLENGE_NONCE_LENGTH,  # Import config settings
                    SERVER_TRANSCRIPT_LABEL, CLIENT_TRANSCRIPT_LABEL)


class DeviceAllowlist:
    """Manages reading and verifying registered ESP32 devices from authorized_devices.json.
    The parsed file is cached and only re-read when its modification time changes."""

    def __init__(self, file_path=ALLOWLIST_FILE):
        self.file_path = file_path
        self._lock = threading.Lock()
        self._cache = {}
        self._cache_mtime = None

    def load_authorized_devices(self):
        """Returns {device_id: public_key_bytes}, reloading from disk only if the file changed."""
        if not self.file_path.exists():
            print(f"[WARN] Allowlist file not found: {self.file_path}")
            return {}

        with self._lock:
            mtime = self.file_path.stat().st_mtime
            if self._cache_mtime != mtime:
                self._cache = self._read_file()
                self._cache_mtime = mtime
            return dict(self._cache)

    def _read_file(self):
        """Reads allowlist JSON from disk and returns {device_id: public_key_bytes}."""
        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)
                devices = {}

                for device_id, hex_key in data.items():
                    if device_id.startswith("_"):
                        continue
                    try:
                        raw_key = bytes.fromhex(hex_key)
                        if len(raw_key) == 32:
                            devices[device_id] = raw_key
                    except ValueError:
                        pass
                return devices
        except Exception as e:
            print(f"[ERROR] Failed to read allowlist: {e}")
            return {}

    def get_device_public_key(self, device_id):
        """Retrieves the registered public key for a device ID."""
        devices = self.load_authorized_devices()
        return devices.get(device_id)


class GatewayCrypto:
    """Encapsulates the server's cryptographic keys and signature operations for Option A."""

    def __init__(self, private_seed_hex=SERVER_PRIVATE_SEED_HEX):
        seed_bytes = bytes.fromhex(private_seed_hex)
        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes)
        self._public_key = self._private_key.public_key()
        self._public_bytes = self._public_key.public_bytes_raw()

    @property
    def public_bytes(self):
        return self._public_bytes

    @property
    def public_hex(self):
        return self._public_bytes.hex()

    def generate_challenge(self):
        """Generates 32 fresh random bytes for a challenge nonce."""
        return os.urandom(CHALLENGE_NONCE_LENGTH)

    # -------------------------------------------------------------------------
    # RUNNING TRANSCRIPT HASH (TLS 1.3 style)
    # Each party signs a hash of a role label followed by the exact wire bytes
    # exchanged so far. Every wire field is fixed-length (Device ID is zero-padded
    # to 16 B), so no delimiters or length prefixes are needed and parsing is
    # unambiguous. Any future message field (e.g. key shares) is covered automatically.
    # -------------------------------------------------------------------------
    @staticmethod
    def build_server_transcript(msg1: bytes, server_nonce: bytes) -> bytes:
        """
        Server Transcript (signed in MSG 2):
        SHA-256( "VPN-v1|SERVER|" (14 B) || MSG1 (50 B) || ServerNonce (32 B) )  -> 96 B input
        """
        h = hashlib.sha256()
        h.update(SERVER_TRANSCRIPT_LABEL)
        h.update(msg1)
        h.update(server_nonce)
        return h.digest()

    @staticmethod
    def build_client_transcript(msg1: bytes, msg2: bytes) -> bytes:
        """
        Client Transcript (signed in MSG 3):
        SHA-256( "VPN-v1|CLIENT|" (14 B) || MSG1 (50 B) || MSG2 (96 B) )  -> 160 B input
        MSG2 = ServerNonce || ServerSig, so the client's signature covers every byte
        of the handshake it has seen. Note: this proves the client *received* MSG2;
        it does not by itself prove the client *verified* it.
        """
        h = hashlib.sha256()
        h.update(CLIENT_TRANSCRIPT_LABEL)
        h.update(msg1)
        h.update(msg2)
        return h.digest()

    def sign_server_transcript(self, msg1: bytes, server_nonce: bytes) -> bytes:
        """Signs the Server Transcript hash using the server's Ed25519 private key."""
        digest = self.build_server_transcript(msg1, server_nonce)
        return self._private_key.sign(digest)

    def verify_client_transcript(self, client_public_bytes: bytes, signature_bytes: bytes,
                                 msg1: bytes, msg2: bytes) -> bool:
        """Verifies the client's Ed25519 signature over the Client Transcript."""
        digest = self.build_client_transcript(msg1, msg2)
        try:
            client_pubkey_obj = ed25519.Ed25519PublicKey.from_public_bytes(client_public_bytes)
            client_pubkey_obj.verify(signature_bytes, digest)
            return True
        except Exception:
            return False
