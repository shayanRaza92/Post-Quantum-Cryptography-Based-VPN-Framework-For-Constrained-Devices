import os
import json
import hashlib
import hmac
import threading
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from config import (
    ALLOWLIST_FILE, SERVER_PRIVATE_SEED_HEX, CHALLENGE_NONCE_LENGTH,
    SERVER_TRANSCRIPT_LABEL, CLIENT_TRANSCRIPT_LABEL,
    CLIENT_CONFIRM_LABEL, SERVER_CONFIRM_LABEL, KEY_DERIVATION_INFO
)


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
    """Encapsulates server identity keys (Ed25519), ephemeral key exchange (X25519),
    HKDF-SHA256 session key derivation, and transcript signing."""

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
        return self._public_bytes.hex().upper()

    def generate_challenge(self):
        """Generates 32 fresh random bytes for a challenge nonce."""
        return os.urandom(CHALLENGE_NONCE_LENGTH)

    # -------------------------------------------------------------------------
    # EPHEMERAL X25519 KEY EXCHANGE & HKDF KEY DERIVATION
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_ephemeral_keypair():
        """Generates fresh ephemeral X25519 private key and 32-byte public key."""
        priv = x25519.X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv, pub_bytes

    @staticmethod
    def compute_shared_secret(priv_key: x25519.X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
        """Performs Curve25519 Diffie-Hellman scalar multiplication to derive 32-byte shared secret."""
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        return priv_key.exchange(peer_pub)

    @staticmethod
    def derive_session_keys(shared_secret: bytes, client_nonce: bytes, server_nonce: bytes):
        """
        Derives K_confirm (32B) and K_session (32B) using HKDF-SHA256 (RFC 5869):
        salt = SHA-256(ClientNonce || ServerNonce)
        PRK  = HMAC-SHA256(salt, shared_secret)
        T1   = HMAC-SHA256(PRK, info || 0x01) -> K_confirm
        T2   = HMAC-SHA256(PRK, T1 || info || 0x02) -> K_session
        """
        salt = hashlib.sha256(client_nonce + server_nonce).digest()
        prk = hmac.new(salt, shared_secret, hashlib.sha256).digest()

        info = KEY_DERIVATION_INFO
        t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        t2 = hmac.new(prk, t1 + info + b"\x02", hashlib.sha256).digest()
        return t1, t2

    @staticmethod
    def compute_confirmation_tag(k_confirm: bytes, role_label: bytes, transcript_digest: bytes) -> bytes:
        """Computes 32-byte HMAC-SHA256 key confirmation tag."""
        return hmac.new(k_confirm, role_label + transcript_digest, hashlib.sha256).digest()

    # -------------------------------------------------------------------------
    # RUNNING TRANSCRIPT HASH (TLS 1.3 style)
    # -------------------------------------------------------------------------
    @staticmethod
    def build_server_transcript(msg1: bytes, server_nonce: bytes, server_eph_pk: bytes) -> bytes:
        """
        Server Transcript (signed in MSG 2):
        SHA-256( "VPN-v1|SERVER|" (14B) || MSG1 (82B) || ServerNonce (32B) || ServerEphPk (32B) ) -> 160B input
        """
        h = hashlib.sha256()
        h.update(SERVER_TRANSCRIPT_LABEL)
        h.update(msg1)
        h.update(server_nonce)
        h.update(server_eph_pk)
        return h.digest()

    @staticmethod
    def build_client_transcript(msg1: bytes, msg2: bytes) -> bytes:
        """
        Client Transcript (signed in MSG 3):
        SHA-256( "VPN-v1|CLIENT|" (14B) || MSG1 (82B) || MSG2 (128B) ) -> 224B input
        """
        h = hashlib.sha256()
        h.update(CLIENT_TRANSCRIPT_LABEL)
        h.update(msg1)
        h.update(msg2)
        return h.digest()

    def sign_server_transcript(self, msg1: bytes, server_nonce: bytes, server_eph_pk: bytes) -> bytes:
        """Signs Server Transcript hash using server's Ed25519 identity key."""
        digest = self.build_server_transcript(msg1, server_nonce, server_eph_pk)
        return self._private_key.sign(digest)

    def verify_client_transcript(self, client_public_bytes: bytes, signature_bytes: bytes,
                                 msg1: bytes, msg2: bytes) -> bool:
        """Verifies client's Ed25519 signature over Client Transcript."""
        digest = self.build_client_transcript(msg1, msg2)
        try:
            client_pubkey_obj = ed25519.Ed25519PublicKey.from_public_bytes(client_public_bytes)
            client_pubkey_obj.verify(signature_bytes, digest)
            return True
        except Exception:
            return False
