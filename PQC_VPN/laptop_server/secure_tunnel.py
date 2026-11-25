"""
AES-256-GCM encrypted data tunnel, run as a SECURITY ASSOCIATION (SA) bound to the authenticated
handshake, with in-tunnel rekeying (mirror of esp32_client/SecureTunnel).

SA binding. After MSG 4 both sides compute the handshake hash (handshake_hash() below)
  TH = SHA-256("VPN-v1|SA-BIND|" || MSG1 || MSG2 || MSG3 || MSG4 || PK_client || PK_gateway)
and derive every SA from TH and the current session key K (HKDF-SHA256, RFC 5869):
  PRK   = HMAC-SHA256(key = TH, K)
  SPI   = first 4 B of HMAC-SHA256(PRK, "VPN-v1|SA|SPI" || epoch (4B BE) || 0x01)
  K_c2s = HMAC-SHA256(PRK, "VPN-v1|SA|C2S" || epoch (4B BE) || 0x01)   ESP32 -> laptop
  K_s2c = HMAC-SHA256(PRK, "VPN-v1|SA|S2C" || epoch (4B BE) || 0x01)   laptop -> ESP32
The SPI is not sent; it is authenticated in every frame (AAD).

Wire frame:  [2B LEN (BE)] [8B SEQ (BE)] [N B CIPHERTEXT] [16B GCM TAG]
  LEN   = 8 + N + 16
  Nonce = 4B direction ID (C2S=1, S2C=2) || 8B SEQ
  AAD   = SPI (4) || epoch (4B BE) || LEN || SEQ
  SEQ starts at 0 and must increase by exactly 1 per direction (replay / reorder protection).

Plaintext of every frame:  [1B TYPE] [payload]  (payload is at least 1 byte)
  0x01 DATA        application message
  0x02 REKEY_REQ   [4B epoch (BE)] [client ephemeral public key]   (ESP32 -> gateway)
  0x03 REKEY_RESP  [4B epoch (BE)] [gateway key share]            (gateway -> ESP32)

Rekey (new keys from a fresh key exchange done inside the authenticated tunnel):
  PRK       = HMAC-SHA256(key = K_session_old, SS_new)
  K_session = HMAC-SHA256(PRK, "VPN-v1|REKEY" || epoch (4B BE) || 0x01)
  then a NEW SA (new SPI, new K_c2s / K_s2c, still bound to TH), SEQ = 0 in both directions,
  and the old SA is deleted.
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
SA_BIND_LABEL = b"VPN-v1|SA-BIND|"


class TunnelError(Exception):
    """Raised on authentication failure, replay, or malformed framing. The session must be dropped."""


def _hkdf_expand_one_block(prk: bytes, label: bytes) -> bytes:
    return hmac.new(prk, label + b"\x01", hashlib.sha256).digest()


def handshake_hash(msg1: bytes, msg2: bytes, msg3: bytes, msg4: bytes,
                   client_pk: bytes, gateway_pk: bytes) -> bytes:
    """TH = SHA-256("VPN-v1|SA-BIND|" || MSG1 || MSG2 || MSG3 || MSG4 || PK_client || PK_gateway)."""
    return hashlib.sha256(SA_BIND_LABEL + msg1 + msg2 + msg3 + msg4 + client_pk + gateway_pk).digest()


def _nonce(direction: int, seq: int) -> bytes:
    return struct.pack(">IQ", direction, seq)


def derive_rekeyed_session_key(old_k_session: bytes, shared_secret: bytes, epoch: int) -> bytes:
    """K_session for `epoch` = HKDF(salt = old K_session, IKM = fresh shared secret, info = label || epoch)."""
    prk = hmac.new(old_k_session, shared_secret, hashlib.sha256).digest()
    return hmac.new(prk, REKEY_INFO + struct.pack(">I", epoch) + b"\x01", hashlib.sha256).digest()


class SecureTunnel:
    def __init__(self, k_session: bytes, handshake_hash: bytes, role: str = "server"):
        if len(k_session) != 32 or len(handshake_hash) != 32:
            raise ValueError("K_session and the handshake hash must be 32 bytes")
        self.role = role
        self.handshake_hash = handshake_hash      # TH: every SA of this tunnel is bound to it
        self._install(k_session, 0)
        self._buf = bytearray()
        self.last_tx = None

    def _install(self, k_session: bytes, epoch: int):
        """Installs the SA of `epoch` (SPI + both direction keys) and resets the counters."""
        self._k_session = k_session
        self.epoch = epoch
        prk = hmac.new(self.handshake_hash, k_session, hashlib.sha256).digest()   # salt = TH
        ep = struct.pack(">I", epoch)
        self.spi = struct.unpack(">I", _hkdf_expand_one_block(prk, b"VPN-v1|SA|SPI" + ep)[:4])[0]
        self.k_c2s = _hkdf_expand_one_block(prk, b"VPN-v1|SA|C2S" + ep)
        self.k_s2c = _hkdf_expand_one_block(prk, b"VPN-v1|SA|S2C" + ep)
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
        """Installs the new SA of `epoch` (new SPI and keys) and deletes the old one; counters restart at 0."""
        if len(shared_secret) != 32:
            raise ValueError("shared secret must be 32 bytes")
        self._install(derive_rekeyed_session_key(self._k_session, shared_secret, epoch), epoch)

    def _aad(self, header: bytes) -> bytes:
        """AAD = SPI || epoch || LEN || SEQ: a frame is only valid in its own SA."""
        return struct.pack(">II", self.spi, self.epoch) + header

    @property
    def key_age(self) -> float:
        return time.monotonic() - self.key_started

    def print_keys(self, peer: str = "ESP32"):
        print("+-----------------------------------------------------------------------------+")
        print("| SECURITY ASSOCIATION (SA) INSTALLED - bound to this handshake               |")
        print("+-----------------------------------------------------------------------------+")
        print("| TH = SHA-256(\"VPN-v1|SA-BIND|\" || MSG1..MSG4 || PK_client || PK_gateway)    |")
        print(f"| {self.handshake_hash.hex().upper():<75} |")
        print("+-----------------------------------------------------------------------------+")
        sa_line = f"SPI 0x{self.spi:08X}   epoch {self.epoch}   peer: {peer}   AES-256-GCM, msg # from 0"
        print(f"| {sa_line:<75} |")
        print("+-----------------------------------------------------------------------------+")
        print("| K_c2s = HKDF(salt TH, K_session, \"VPN-v1|SA|C2S\"||epoch)   ESP32->Laptop    |")
        print(f"| {self.k_c2s.hex().upper():<75} |")
        print("+-----------------------------------------------------------------------------+")
        print("| K_s2c = HKDF(salt TH, K_session, \"VPN-v1|SA|S2C\"||epoch)   Laptop->ESP32    |")
        print(f"| {self.k_s2c.hex().upper():<75} |")
        print("+-----------------------------------------------------------------------------+")
        print("| Frame: [2B LEN][8B SEQ][CIPHERTEXT][16B TAG]  AAD = SPI||epoch||LEN||SEQ    |")
        print("| Plaintext: [1B TYPE: DATA / REKEY_REQ / REKEY_RESP] [payload]               |")
        print("+-----------------------------------------------------------------------------+\n")

    def seal(self, payload: bytes, msg_type: int = MSG_DATA) -> bytes:
        """Encrypts one message (TYPE || payload) into a wire frame."""
        if not 0 < len(payload) <= MAX_PAYLOAD:
            raise ValueError("payload length out of range")
        plaintext = bytes([msg_type]) + payload
        header = struct.pack(">HQ", 8 + len(plaintext) + TAG_SIZE, self.tx_seq)
        nonce = _nonce(self._tx_dir, self.tx_seq)
        ct_tag = self._tx.encrypt(nonce, plaintext, self._aad(header))
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
                plaintext = self._rx.decrypt(_nonce(self._rx_dir, seq), ct_tag, self._aad(header))
            except InvalidTag:
                raise TunnelError("AES-GCM authentication FAILED (tampered frame)") from None
            self.rx_seq += 1
            msg_type = plaintext[0]
            if msg_type not in MSG_NAMES:
                raise TunnelError(f"unknown message type 0x{msg_type:02X}")
            yield seq, ct_tag[:-TAG_SIZE], ct_tag[-TAG_SIZE:], msg_type, plaintext[1:]
