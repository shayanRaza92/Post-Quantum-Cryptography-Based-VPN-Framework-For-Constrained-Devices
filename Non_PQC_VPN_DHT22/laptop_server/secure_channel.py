"""
Encrypted record layer for the data tunnel, keyed from the handshake's K_session.
Mirror of esp32_dht22_client/SecureChannel.cpp.

Directional keys (a different key per direction, so nonces never collide):
    K_c2s = HMAC-SHA256(K_session, "VPN-v1|DATA|C2S")   ESP32 -> Server
    K_s2c = HMAC-SHA256(K_session, "VPN-v1|DATA|S2C")   Server -> ESP32

Wire record:
    [2B Length (big-endian)] [8B Sequence (big-endian)] [Ciphertext || 16B GCM Tag]
    Length = number of bytes after the length field (8 + ciphertext + 16)

Cipher : AES-256-GCM (NIST SP 800-38D), 96-bit IV, 128-bit tag
IV     : 4 zero bytes || 8B Sequence (unique per key: the sequence never repeats)
AAD    : the 10-byte header (Length || Sequence)
Replay : the receiver only accepts the exact next sequence number
"""
import hashlib
import hmac
import struct
from collections import namedtuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import MAX_RECORD_PLAINTEXT, DATA_KEY_LABEL_C2S, DATA_KEY_LABEL_S2C

LEN_FIELD = 2
SEQ_FIELD = 8
HEADER_LEN = LEN_FIELD + SEQ_FIELD
TAG_LEN = 16
MAX_RECORD_BODY = SEQ_FIELD + MAX_RECORD_PLAINTEXT + TAG_LEN


# One authenticated record: parsed header fields, raw wire bytes, and the decrypted payload
Record = namedtuple("Record", "seq length nonce ciphertext tag wire plaintext")


def split_record(wire: bytes):
    """Splits wire bytes into (length, seq, nonce, ciphertext, tag) for printing."""
    (length, seq) = struct.unpack(">HQ", wire[:HEADER_LEN])
    return length, seq, _nonce(seq), wire[HEADER_LEN:-TAG_LEN], wire[-TAG_LEN:]


class RecordError(Exception):
    """A received record is malformed, out of sequence (replay/drop), or failed authentication."""


def _nonce(seq):
    return b"\x00\x00\x00\x00" + struct.pack(">Q", seq)


def derive_data_key(k_session, label):
    return hmac.new(k_session, label, hashlib.sha256).digest()


class SecureChannel:
    def __init__(self, k_session, rx_label=DATA_KEY_LABEL_C2S, tx_label=DATA_KEY_LABEL_S2C):
        # The gateway receives on C2S and sends on S2C (a test client swaps the labels)
        self.rx_key = derive_data_key(k_session, rx_label)
        self.tx_key = derive_data_key(k_session, tx_label)
        self._rx = AESGCM(self.rx_key)  # 32-byte key -> AES-256
        self._tx = AESGCM(self.tx_key)
        self._rx_seq = 0
        self._tx_seq = 0
        self._buffer = bytearray()

    @staticmethod
    def wire_size(plaintext_len):
        return HEADER_LEN + plaintext_len + TAG_LEN

    def seal(self, plaintext: bytes) -> bytes:
        """Encrypts one record and returns its wire bytes."""
        if len(plaintext) > MAX_RECORD_PLAINTEXT:
            raise ValueError(f"record payload exceeds {MAX_RECORD_PLAINTEXT} bytes")
        body_len = SEQ_FIELD + len(plaintext) + TAG_LEN
        header = struct.pack(">HQ", body_len, self._tx_seq)
        ciphertext = self._tx.encrypt(_nonce(self._tx_seq), plaintext, header)
        self._tx_seq += 1
        return header + ciphertext

    def feed(self, data: bytes):
        """
        Adds received bytes and returns a list of Record for every complete record.
        Raises RecordError on any malformed, replayed, reordered, or tampered record.
        The internal buffer never holds more than one partial record (bounded memory).
        """
        self._buffer.extend(data)
        records = []
        while len(self._buffer) >= LEN_FIELD:
            (body_len,) = struct.unpack(">H", self._buffer[:LEN_FIELD])
            if body_len < SEQ_FIELD + TAG_LEN or body_len > MAX_RECORD_BODY:
                raise RecordError(f"invalid record length {body_len}")
            if len(self._buffer) < LEN_FIELD + body_len:
                break

            record = bytes(self._buffer[:LEN_FIELD + body_len])
            del self._buffer[:LEN_FIELD + body_len]

            header = record[:HEADER_LEN]
            (seq,) = struct.unpack(">Q", record[LEN_FIELD:HEADER_LEN])
            if seq != self._rx_seq:
                raise RecordError(f"unexpected sequence {seq} (expected {self._rx_seq}): replay or dropped record")
            try:
                plaintext = self._rx.decrypt(_nonce(seq), record[HEADER_LEN:], header)
            except InvalidTag:
                raise RecordError(f"authentication tag mismatch on record {seq}: tampered or wrong key")
            self._rx_seq += 1
            records.append(Record(seq, body_len, _nonce(seq), record[HEADER_LEN:-TAG_LEN],
                                  record[-TAG_LEN:], record, plaintext))
        return records
