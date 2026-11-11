"""
Minimal honest-client / network helper shared by all Test 3 attack scripts (no duplication).

Responsibilities:
  * build a correct MSG 1 (Client Hello) using the REAL ML-KEM-512 keygen from PQC_VPN, so the
    only thing an attack script changes is the one field it is testing;
  * open a TCP connection and exchange the four handshake messages with a live LAB gateway;
  * parse MSG 2 / MSG 4 verdict.

SAFETY: constructing messages is pure computation and always allowed. Anything that opens a
socket goes through `connect()`, which REQUIRES the caller to have already passed the
common.target_config safety gate (authorised + --run). Importing this module sends nothing.

This is a test harness for authorised lab use; it is not a full client and intentionally omits
MSG 3 signing unless given a client secret key (the honest-client path), so most attack scripts
can drive just the parts they need.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import protocol_constants as P  # noqa: E402

# Access the real ML-KEM keygen so MSG 1 carries a valid ephemeral ek.
import pqc_paths  # noqa: E402  (already importable via protocol_constants' path setup)
import ctypes  # noqa: E402

_LAPTOP = pqc_paths.add_laptop_server_to_path()


def native_mlkem_available() -> bool:
    return pqc_paths.native_libs_present()["mlkem512"]


def _load_mlkem():
    lib = ctypes.CDLL(str(_LAPTOP / "libmlkem512.so"))
    lib.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
    ]
    lib.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand.restype = ctypes.c_int
    return lib


def generate_ephemeral_kem_keypair() -> tuple[bytes, bytes]:
    """Returns (ek 800B, dk 1632B) using the project's real ML-KEM-512 keygen.

    Requires libmlkem512.so to be built in PQC_VPN/laptop_server (build_native_libs.sh).
    """
    lib = _load_mlkem()
    ek = ctypes.create_string_buffer(P.KEM_PUBLIC_KEY_LENGTH)
    dk = ctypes.create_string_buffer(1632)
    coins = os.urandom(64)  # ML-KEM keygen derandomised API: 2x32B coins
    rc = lib.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand(ek, dk, coins)
    if rc != 0:
        raise RuntimeError(f"ML-KEM-512 keypair generation failed (rc={rc})")
    return ek.raw, dk.raw


def encode_device_id(device_id: str) -> bytes:
    """ASCII, zero-padded to 16 bytes, as the gateway expects."""
    raw = device_id.encode("ascii")
    if len(raw) > P.DEVICE_ID_LENGTH:
        raise ValueError("device_id too long (max 16)")
    return raw + b"\x00" * (P.DEVICE_ID_LENGTH - len(raw))


def build_client_hello(device_id: str, client_ek: bytes,
                       version: int = P.PROTOCOL_VERSION,
                       alg_id: int = P.ALGORITHM_ID,
                       client_nonce: bytes | None = None) -> bytes:
    """Builds an 850-byte MSG 1. version/alg_id are parameters so the DOWNGRADE test can vary them."""
    if client_nonce is None:
        client_nonce = os.urandom(P.CHALLENGE_NONCE_LENGTH)
    msg = bytes([version & 0xFF, alg_id & 0xFF]) + encode_device_id(device_id) + client_nonce + client_ek
    assert len(msg) == P.MSG1_CLIENT_HELLO_SIZE, f"MSG1 is {len(msg)}B, expected 850"
    return msg


def parse_server_proof(msg2: bytes) -> dict:
    """Splits MSG 2 into its fields for inspection by attack scripts."""
    if len(msg2) != P.MSG2_SERVER_PROOF_SIZE:
        raise ValueError(f"MSG2 is {len(msg2)}B, expected {P.MSG2_SERVER_PROOF_SIZE}")
    return {
        "server_nonce": msg2[P.OFF_SERVER_NONCE],
        "kem_ct": msg2[P.OFF_KEM_CT],
        "server_sig": msg2[P.OFF_SERVER_SIG],
    }


def verdict_is_ok(msg4: bytes) -> bool:
    return msg4[:8] == P.AUTH_OK_TOKEN


class GatewayConnection:
    """Thin socket wrapper. Only instantiate AFTER passing common.target_config's safety gate."""

    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock: socket.socket | None = None

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def send(self, data: bytes) -> None:
        assert self.sock is not None, "connect() first"
        self.sock.sendall(data)

    def recv_exact(self, n: int) -> bytes | None:
        assert self.sock is not None, "connect() first"
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
