"""
Shared harness for Test 4: drives the REAL SecureTunnel from PQC_VPN/laptop_server offline.

Test 4 is an OFFLINE cryptographic analysis: it imports the project's actual
secure_tunnel.SecureTunnel and exercises it with a known K_session, so the results reflect the
real implementation's framing, nonce construction, replay check and rekeying. No network, no
gateway, no ESP32 — nothing is sent anywhere.

A matched pair of tunnels (client + server) sharing one K_session reproduces both directions:
  * server.seal() -> client.feed()   (S2C)
  * client.seal() -> server.feed()   (C2S)

Helpers let the attack scripts tamper a frame, replay/reorder it, or rekey, and observe how the
real SecureTunnel reacts (it raises TunnelError on any violation).
"""
from __future__ import annotations

import sys
from pathlib import Path

_COMMON = Path(__file__).resolve().parents[3] / "PEN_Testing" / "common"
if str(_COMMON) not in sys.path:
    sys.path.insert(0, str(_COMMON))
import pqc_paths  # noqa: E402

pqc_paths.add_laptop_server_to_path()

# Real implementation under test:
import secure_tunnel as st  # PQC_VPN/laptop_server/secure_tunnel.py  # noqa: E402

TunnelError = st.TunnelError
TAG_SIZE = st.TAG_SIZE
HEADER_SIZE = st.HEADER_SIZE
MSG_DATA = st.MSG_DATA
MSG_REKEY_REQ = st.MSG_REKEY_REQ


def make_tunnel_pair(k_session: bytes | None = None):
    """Returns (server_tunnel, client_tunnel) sharing one K_session."""
    if k_session is None:
        k_session = b"\x42" * 32  # fixed test key; offline only, never a real session key
    server = st.SecureTunnel(k_session, role="server")
    client = st.SecureTunnel(k_session, role="client")
    return server, client


def flip_frame_byte(frame: bytes, index: int) -> bytes:
    """Flips one bit of a sealed frame (to test ciphertext/tag tamper detection)."""
    b = bytearray(frame)
    b[index] ^= 0x01
    return bytes(b)


def collect(feed_gen) -> list:
    """Drains a SecureTunnel.feed() generator into a list of yielded frames."""
    return list(feed_gen)
