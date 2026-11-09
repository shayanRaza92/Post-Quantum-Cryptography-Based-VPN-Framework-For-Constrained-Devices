import os
import json
import ctypes
import hashlib
import hmac
import threading
from console import safe_print as print  # Thread-safe printing
from config import (
    ALLOWLIST_FILE, MLDSA44_SO_PATH, MLKEM512_SO_PATH, SERVER_PRIVATE_SEED_HEX,
    CHALLENGE_NONCE_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
    KEM_PUBLIC_KEY_LENGTH, KEM_CIPHERTEXT_LENGTH, KEM_SHARED_SECRET_LENGTH,
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


def _load_mlkem512_lib():
    """Loads the compiled mlkem-native C shared library (libmlkem512.so) via ctypes.
    Built with MLK_CONFIG_PARAMETER_SET=512 and MLK_CONFIG_NO_RANDOMIZED_API, so the
    server supplies encapsulation randomness itself from os.urandom (the OS CSPRNG)."""
    if not MLKEM512_SO_PATH.exists():
        raise FileNotFoundError(
            f"ML-KEM-512 shared library not found at {MLKEM512_SO_PATH} (run ./build_native_libs.sh)"
        )
    lib = ctypes.CDLL(str(MLKEM512_SO_PATH))

    # int PQCP_MLKEM_NATIVE_MLKEM512_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins)
    lib.PQCP_MLKEM_NATIVE_MLKEM512_enc_derand.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
    ]
    lib.PQCP_MLKEM_NATIVE_MLKEM512_enc_derand.restype = ctypes.c_int

    # int PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins)
    lib.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
    ]
    lib.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand.restype = ctypes.c_int

    # int PQCP_MLKEM_NATIVE_MLKEM512_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
    lib.PQCP_MLKEM_NATIVE_MLKEM512_dec.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
    ]
    lib.PQCP_MLKEM_NATIVE_MLKEM512_dec.restype = ctypes.c_int

    return lib


_MLKEM_LIB = _load_mlkem512_lib()


class DeviceAllowlist:
    """Manages reading and verifying registered ESP32 devices from authorized_devices.json.
    The parsed file is cached and only re-read when its modification time changes."""

    def __init__(self, file_path=ALLOWLIST_FILE):
        self.file_path = file_path
        self._lock = threading.Lock()
        self._cache = {}
        self._cache_mtime = None
        self._bad_mtime = None

    def load_authorized_devices(self):
        """Returns {device_id: public_key_bytes}, reloading from disk only if the file changed."""
        if not self.file_path.exists():
            print(f"[WARN] Allowlist file not found: {self.file_path}")
            return {}

        with self._lock:
            try:
                mtime = self.file_path.stat().st_mtime
            except OSError:
                return {}
            if self._cache_mtime != mtime:
                devices = self._read_file(report_error=(mtime != self._bad_mtime))
                if devices is None:
                    # File is mid-edit or has a JSON typo: keep the last good allowlist instead of
                    # treating it as empty (which would revoke every connected device at once).
                    # _cache_mtime is not updated, so the file is retried on the next lookup.
                    self._bad_mtime = mtime  # Report each broken version of the file only once
                    return dict(self._cache)
                self._cache = devices
                self._cache_mtime = mtime
            return dict(self._cache)

    def _read_file(self, report_error=True):
        """Reads allowlist JSON from disk. Returns {device_id: public_key_bytes (1312 B)}, or None on error."""
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
            if report_error:
                print(f"[ERROR] Failed to read allowlist (keeping previous version): {e}")
            return None

    def get_device_public_key(self, device_id):
        """Retrieves the registered 1,312-byte ML-DSA-44 public key for a device ID."""
        devices = self.load_authorized_devices()
        return devices.get(device_id)


class GatewayCrypto:
    """Encapsulates server post-quantum identity keys (ML-DSA-44 via mldsa-native),
    ephemeral key encapsulation (ML-KEM-512 via mlkem-native), HKDF-SHA256 session key
    derivation, and transcript signing."""

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
    # EPHEMERAL ML-KEM-512 KEY ENCAPSULATION (FIPS 203) & HKDF KEY DERIVATION
    # -------------------------------------------------------------------------
    @staticmethod
    def encapsulate(client_ek: bytes):
        """
        ML-KEM-512.Encaps(ek) -> (ct (768B), K (32B)).
        mlkem-native performs the FIPS 203 encapsulation-key modulus check and returns
        non-zero for a malformed ek, in which case ValueError is raised.
        """
        if len(client_ek) != KEM_PUBLIC_KEY_LENGTH:
            raise ValueError(f"ML-KEM-512 ek must be {KEM_PUBLIC_KEY_LENGTH} bytes, got {len(client_ek)}")
        ct_buf = ctypes.create_string_buffer(KEM_CIPHERTEXT_LENGTH)
        ss_buf = ctypes.create_string_buffer(KEM_SHARED_SECRET_LENGTH)
        coins = os.urandom(32)  # FIPS 203 Alg. 20 step 1: m <- B^32 from an approved RBG
        rc = _MLKEM_LIB.PQCP_MLKEM_NATIVE_MLKEM512_enc_derand(ct_buf, ss_buf, client_ek, coins)
        if rc != 0:
            raise ValueError(f"ML-KEM-512 encapsulation rejected client ek (rc={rc})")
        return ct_buf.raw, ss_buf.raw

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
    def build_server_transcript(msg1: bytes, server_nonce: bytes, kem_ciphertext: bytes) -> bytes:
        """
        Server Transcript (signed in MSG 2):
        SHA-256( "VPN-v1|SERVER|" (14B) || MSG1 (850B) || ServerNonce (32B) || KEM_ct (768B) ) -> 1664B input
        """
        h = hashlib.sha256()
        h.update(SERVER_TRANSCRIPT_LABEL)
        h.update(msg1)
        h.update(server_nonce)
        h.update(kem_ciphertext)
        return h.digest()

    @staticmethod
    def build_client_transcript(msg1: bytes, msg2: bytes) -> bytes:
        """
        Client Transcript (signed in MSG 3):
        SHA-256( "VPN-v1|CLIENT|" (14B) || MSG1 (850B) || MSG2 (3220B) ) -> 4084B input
        """
        h = hashlib.sha256()
        h.update(CLIENT_TRANSCRIPT_LABEL)
        h.update(msg1)
        h.update(msg2)
        return h.digest()

    def sign_server_transcript(self, msg1: bytes, server_nonce: bytes, kem_ciphertext: bytes) -> bytes:
        """Signs 32-byte Server Transcript digest using server's ML-DSA-44 secret key (2,420B signature)."""
        digest = self.build_server_transcript(msg1, server_nonce, kem_ciphertext)
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

