import os
import json
import ctypes
import hashlib
import hmac
import threading
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from config import (
    ALLOWLIST_FILE, MLDSA44_SO_PATH, SERVER_PRIVATE_SEED_HEX,
    CHALLENGE_NONCE_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
    SERVER_TRANSCRIPT_LABEL, CLIENT_TRANSCRIPT_LABEL,
    CLIENT_CONFIRM_LABEL, SERVER_CONFIRM_LABEL, KEY_DERIVATION_INFO
)


def _load_mldsa44_lib():
    """Loads the compiled mldsa-native C shared library (libmldsa44.so) via ctypes."""
    if not MLDSA44_SO_PATH.exists():
        raise FileNotFoundError(
            f"ML-DSA-44 shared library not found at {MLDSA44_SO_PATH}"
        )
    lib = ctypes.CDLL(str(MLDSA44_SO_PATH))

    # int PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
    lib.PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
    ]
    lib.PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal.restype = ctypes.c_int

    # int PQCP_MLDSA_NATIVE_MLDSA44_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
    #                                         const uint8_t *ctx, size_t ctxlen, const uint8_t *sk)
    lib.PQCP_MLDSA_NATIVE_MLDSA44_signature.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p
    ]
    lib.PQCP_MLDSA_NATIVE_MLDSA44_signature.restype = ctypes.c_int

    # int PQCP_MLDSA_NATIVE_MLDSA44_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
    #                                      const uint8_t *ctx, size_t ctxlen, const uint8_t *pk)
    lib.PQCP_MLDSA_NATIVE_MLDSA44_verify.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p
    ]
    lib.PQCP_MLDSA_NATIVE_MLDSA44_verify.restype = ctypes.c_int

    return lib


_MLDSA_LIB = _load_mldsa44_lib()


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
        """Reads allowlist JSON from disk and returns {device_id: public_key_bytes (1312 B)}."""
        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)
                devices = {}

                for device_id, hex_key in data.items():
                    if device_id.startswith("_"):
                        continue
                    try:
                        raw_key = bytes.fromhex(hex_key.strip())
                        if len(raw_key) == PUBLIC_KEY_LENGTH:
                            devices[device_id] = raw_key
                        else:
                            print(
                                f"[WARN] Skipping '{device_id}': expected {PUBLIC_KEY_LENGTH}B "
                                f"ML-DSA-44 public key, got {len(raw_key)}B."
                            )
                    except ValueError:
                        pass
                return devices
        except Exception as e:
            print(f"[ERROR] Failed to read allowlist: {e}")
            return {}

    def get_device_public_key(self, device_id):
        """Retrieves the registered 1,312-byte ML-DSA-44 public key for a device ID."""
        devices = self.load_authorized_devices()
        return devices.get(device_id)


class GatewayCrypto:
    """Encapsulates server post-quantum identity keys (ML-DSA-44 via mldsa-native),
    ephemeral key exchange (X25519), HKDF-SHA256 session key derivation, and transcript signing."""

    def __init__(self, private_seed_hex=SERVER_PRIVATE_SEED_HEX):
        seed_bytes = bytes.fromhex(private_seed_hex)
        if len(seed_bytes) != 32:
            raise ValueError("SERVER_PRIVATE_SEED_HEX must be 32 bytes (64 hex chars)")

        pk_buf = ctypes.create_string_buffer(PUBLIC_KEY_LENGTH)
        sk_buf = ctypes.create_string_buffer(SECRET_KEY_LENGTH)
        rc = _MLDSA_LIB.PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(pk_buf, sk_buf, seed_bytes)
        if rc != 0:
            raise RuntimeError(f"ML-DSA-44 deterministic keypair generation failed (rc={rc})")

        self._public_bytes = pk_buf.raw
        self._secret_bytes = sk_buf.raw

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
        SHA-256( "VPN-v1|CLIENT|" (14B) || MSG1 (82B) || MSG2 (2484B) ) -> 2580B input
        """
        h = hashlib.sha256()
        h.update(CLIENT_TRANSCRIPT_LABEL)
        h.update(msg1)
        h.update(msg2)
        return h.digest()

    def sign_server_transcript(self, msg1: bytes, server_nonce: bytes, server_eph_pk: bytes) -> bytes:
        """Signs 32-byte Server Transcript digest using server's ML-DSA-44 secret key (2,420B signature)."""
        digest = self.build_server_transcript(msg1, server_nonce, server_eph_pk)
        sig_buf = ctypes.create_string_buffer(SIGNATURE_LENGTH)
        sig_len = ctypes.c_size_t(0)
        rc = _MLDSA_LIB.PQCP_MLDSA_NATIVE_MLDSA44_signature(
            sig_buf, ctypes.byref(sig_len),
            digest, len(digest),
            None, 0,
            self._secret_bytes
        )
        if rc != 0 or sig_len.value != SIGNATURE_LENGTH:
            raise RuntimeError(f"ML-DSA-44 server signing failed (rc={rc})")
        return sig_buf.raw

    def verify_client_transcript(self, client_public_bytes: bytes, signature_bytes: bytes,
                                 msg1: bytes, msg2: bytes) -> bool:
        """Verifies client's 2,420-byte ML-DSA-44 signature over the 32-byte Client Transcript digest."""
        if len(client_public_bytes) != PUBLIC_KEY_LENGTH or len(signature_bytes) != SIGNATURE_LENGTH:
            return False
        digest = self.build_client_transcript(msg1, msg2)
        rc = _MLDSA_LIB.PQCP_MLDSA_NATIVE_MLDSA44_verify(
            signature_bytes, len(signature_bytes),
            digest, len(digest),
            None, 0,
            client_public_bytes
        )
        return (rc == 0)

