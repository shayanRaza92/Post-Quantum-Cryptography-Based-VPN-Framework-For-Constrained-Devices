"""
AES-256-GCM encrypted data tunnel keyed from the handshake's K_session, with in-tunnel
rekeying (mirror of esp32_client/SecureTunnel).

Directional keys (HKDF-Expand, RFC 5869, PRK = K_session):
  K_c2s = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|C2S" || 0x01)   ESP32 -> laptop
  K_s2c = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|S2C" || 0x01)   laptop -> ESP32

Wire frame:  [2B LEN (BE)] [8B SEQ (BE)] [N B CIPHERTEXT] [16B GCM TAG]
  LEN   = 8 + N + 16
  Nonce = 4B direction ID (C2S=1, S2C=2) || 8B SEQ
  AAD   = LEN || SEQ
  SEQ starts at 0 and must increase by exactly 1 per direction (replay / reorder protection).

Plaintext of every frame:  [1B TYPE] [payload]  (payload is at least 1 byte)
  0x01 DATA        application message
  0x02 REKEY_REQ   [4B epoch (BE)] [client ephemeral public key]   (ESP32 -> gateway)
  0x03 REKEY_RESP  [4B epoch (BE)] [gateway key share]            (gateway -> ESP32)

Rekey (new keys from a fresh key exchange done inside the authenticated tunnel):
  PRK       = HMAC-SHA256(key = K_session_old, SS_new)
  K_session = HMAC-SHA256(PRK, "VPN-v1|REKEY" || epoch (4B BE) || 0x01)
  then new K_c2s / K_s2c, SEQ = 0 in both directions.
"""
import hashlib
import hmac
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from console import safe_print as print  # Thread-safe printing

DIR_C2S = 1
DIR_S2C = 2
HEADER_SIZE = 10
TAG_SIZE = 16
MAX_PLAINTEXT = 1024               # TYPE byte + payload
MAX_PAYLOAD = MAX_PLAINTEXT - 1

MSG_DATA = 0x01
MSG_REKEY_REQ = 0x02
MSG_REKEY_RESP = 0x03
MSG_NAMES = {MSG_DATA: "DATA", MSG_REKEY_REQ: "REKEY_REQ", MSG_REKEY_RESP: "REKEY_RESP"}

REKEY_INFO = b"VPN-v1|REKEY"


class TunnelError(Exception):
    """Raised on authentication failure, replay, or malformed framing. The session must be dropped."""


def _hkdf_expand_one_block(prk: bytes, label: bytes) -> bytes:
    return hmac.new(prk, label + b"\x01", hashlib.sha256).digest()


def _nonce(direction: int, seq: int) -> bytes:
    return struct.pack(">IQ", direction, seq)


def derive_rekeyed_session_key(old_k_session: bytes, shared_secret: bytes, epoch: int) -> bytes:
    """K_session for `epoch` = HKDF(salt = old K_session, IKM = fresh shared secret, info = label || epoch)."""
    prk = hmac.new(old_k_session, shared_secret, hashlib.sha256).digest()
    return hmac.new(prk, REKEY_INFO + struct.pack(">I", epoch) + b"\x01", hashlib.sha256).digest()


class SecureTunnel:
    def __init__(self, k_session: bytes, role: str = "server"):
        if len(k_session) != 32:
            raise ValueError("K_session must be 32 bytes")
        self.role = role
        self.epoch = 0
        self._install(k_session)
        self._buf = bytearray()
        self.last_tx = None

    def _install(self, k_session: bytes):
        """Derives both direction keys from k_session and resets the counters."""
        self._k_session = k_session
        self.k_c2s = _hkdf_expand_one_block(k_session, b"VPN-v1|TUNNEL|C2S")
        self.k_s2c = _hkdf_expand_one_block(k_session, b"VPN-v1|TUNNEL|S2C")
        if self.role == "server":
            self._tx, self._tx_dir = AESGCM(self.k_s2c), DIR_S2C
            self._rx, self._rx_dir = AESGCM(self.k_c2s), DIR_C2S
        else:  # "client" (used by tests)
            self._tx, self._tx_dir = AESGCM(self.k_c2s), DIR_C2S
            self._rx, self._rx_dir = AESGCM(self.k_s2c), DIR_S2C
        self.tx_seq = 0
        self.rx_seq = 0
        self.key_started = time.monotonic()

    def rekey(self, shared_secret: bytes, epoch: int):
        """Switches to the keys of `epoch`; both sequence counters restart at 0."""
        if len(shared_secret) != 32:
            raise ValueError("shared secret must be 32 bytes")
        self._install(derive_rekeyed_session_key(self._k_session, shared_secret, epoch))
        self.epoch = epoch

    @property
    def key_age(self) -> float:
        return time.monotonic() - self.key_started

    def print_keys(self):
        print("+-----------------------------------------------------------------------------+")
        print("| AES-256-GCM TUNNEL KEYS (HKDF-Expand from K_session)                        |")
        print("+-----------------------------------------------------------------------------+")
        print("| K_c2s = HMAC-SHA256(K_session, \"VPN-v1|TUNNEL|C2S\" || 0x01)  ESP32->Laptop  |")
        print(f"| {self.k_c2s.hex().upper():<75} |")
        print("+-----------------------------------------------------------------------------+")
        print("| K_s2c = HMAC-SHA256(K_session, \"VPN-v1|TUNNEL|S2C\" || 0x01)  Laptop->ESP32  |")
        print(f"| {self.k_s2c.hex().upper():<75} |")
        print("+-----------------------------------------------------------------------------+")
        print("| Frame: [2B LEN][8B SEQ][CIPHERTEXT][16B TAG]  Nonce = DIR(4B) || SEQ(8B)    |")
        print("| Plaintext: [1B TYPE: DATA / REKEY_REQ / REKEY_RESP] [payload]               |")
        print("+-----------------------------------------------------------------------------+\n")

    def seal(self, payload: bytes, msg_type: int = MSG_DATA) -> bytes:
        """Encrypts one message (TYPE || payload) into a wire frame."""
        if not 0 < len(payload) <= MAX_PAYLOAD:
            raise ValueError("payload length out of range")
        plaintext = bytes([msg_type]) + payload
        header = struct.pack(">HQ", 8 + len(plaintext) + TAG_SIZE, self.tx_seq)
        nonce = _nonce(self._tx_dir, self.tx_seq)
        ct_tag = self._tx.encrypt(nonce, plaintext, header)
        self.last_tx = (self.tx_seq, nonce, ct_tag[:-TAG_SIZE], ct_tag[-TAG_SIZE:])
        self.tx_seq += 1
        return header + ct_tag

    def feed(self, data: bytes):
        """Feeds received bytes; yields (seq, ciphertext, tag, msg_type, payload) per authenticated frame.
        Keys may be switched with rekey() between two yielded frames."""
        self._buf.extend(data)
        while len(self._buf) >= 2:
            body_len = struct.unpack(">H", self._buf[:2])[0]
            if not (8 + 2 + TAG_SIZE <= body_len <= 8 + MAX_PLAINTEXT + TAG_SIZE):
                raise TunnelError(f"invalid frame length {body_len}")
            if len(self._buf) < 2 + body_len:
                return
            frame = bytes(self._buf[:2 + body_len])
            del self._buf[:2 + body_len]

            header, ct_tag = frame[:HEADER_SIZE], frame[HEADER_SIZE:]
            seq = struct.unpack(">Q", header[2:])[0]
            if seq != self.rx_seq:
                raise TunnelError(f"replay/reorder detected (got seq={seq}, expected {self.rx_seq})")
            try:
                plaintext = self._rx.decrypt(_nonce(self._rx_dir, seq), ct_tag, header)
            except InvalidTag:
                raise TunnelError("AES-GCM authentication FAILED (tampered frame)") from None
            self.rx_seq += 1
            msg_type = plaintext[0]
            if msg_type not in MSG_NAMES:
                raise TunnelError(f"unknown message type 0x{msg_type:02X}")
            yield seq, ct_tag[:-TAG_SIZE], ct_tag[-TAG_SIZE:], msg_type, plaintext[1:]
