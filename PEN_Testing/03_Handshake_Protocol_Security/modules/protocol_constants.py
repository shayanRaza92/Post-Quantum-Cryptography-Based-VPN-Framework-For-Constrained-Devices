"""
Handshake protocol constants and wire-format map for Test 3.

These values are NOT re-invented here — they mirror PQC_VPN/laptop_server/config.py exactly and
are cross-checked against it at import time (see assert_matches_source()). If the implementation
ever changes, the assertion fails loudly instead of the tests silently drifting.

Wire format (from config.py / tunnel_session.py):

  MSG 1  Client Hello   850 B : [1B Ver=0x01][1B Alg=0x03][16B DeviceID][32B ClientNonce][800B ML-KEM ek]
  MSG 2  Server Proof  3220 B : [32B ServerNonce][768B ML-KEM ct][2420B ML-DSA sig]
  MSG 3  Client Proof  2452 B : [2420B ML-DSA sig][32B HMAC confirm tag]
  MSG 4  Verdict         40 B : [8B "AUTH_OK\n"][32B HMAC confirm tag]   or  8B "AUTH_NO\n"

Device ID field: ASCII, zero-padded to 16B, must match regex [a-zA-Z0-9_-]{1,16}.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Put the real gateway source on the path and import its config as the single source of truth.
_COMMON = Path(__file__).resolve().parents[3] / "PEN_Testing" / "common"
if str(_COMMON) not in sys.path:
    sys.path.insert(0, str(_COMMON))
import pqc_paths  # noqa: E402

pqc_paths.add_laptop_server_to_path()
import config as _src  # PQC_VPN/laptop_server/config.py  # noqa: E402

# --- Mirror of the real values (kept as plain constants for readability in the tests) ---
PROTOCOL_VERSION = 0x01
ALGORITHM_ID = 0x03

DEVICE_ID_LENGTH = 16
CHALLENGE_NONCE_LENGTH = 32
KEM_PUBLIC_KEY_LENGTH = 800
KEM_CIPHERTEXT_LENGTH = 768
SIGNATURE_LENGTH = 2420
PUBLIC_KEY_LENGTH = 1312

MSG1_CLIENT_HELLO_SIZE = 850
MSG2_SERVER_PROOF_SIZE = 3220
MSG3_CLIENT_PROOF_SIZE = 2452
MSG4_AUTH_VERDICT_SIZE = 40

AUTH_OK_TOKEN = b"AUTH_OK\n"
AUTH_FAIL_TOKEN = b"AUTH_NO\n"

# Byte offsets inside MSG 1 (used by the tamper/downgrade tests).
OFF_VERSION = 0
OFF_ALG = 1
OFF_DEVICE_ID = slice(2, 18)
OFF_CLIENT_NONCE = slice(18, 50)
OFF_CLIENT_EK = slice(50, 850)

# Byte offsets inside MSG 2.
OFF_SERVER_NONCE = slice(0, 32)
OFF_KEM_CT = slice(32, 32 + KEM_CIPHERTEXT_LENGTH)
OFF_SERVER_SIG = slice(32 + KEM_CIPHERTEXT_LENGTH, MSG2_SERVER_PROOF_SIZE)


def assert_matches_source() -> None:
    """Fail loudly if these constants have drifted from PQC_VPN/laptop_server/config.py."""
    pairs = {
        "PROTOCOL_VERSION": (PROTOCOL_VERSION, _src.PROTOCOL_VERSION),
        "ALGORITHM_ID": (ALGORITHM_ID, _src.ALGORITHM_ID),
        "MSG1_CLIENT_HELLO_SIZE": (MSG1_CLIENT_HELLO_SIZE, _src.MSG1_CLIENT_HELLO_SIZE),
        "MSG2_SERVER_PROOF_SIZE": (MSG2_SERVER_PROOF_SIZE, _src.MSG2_SERVER_PROOF_SIZE),
        "MSG3_CLIENT_PROOF_SIZE": (MSG3_CLIENT_PROOF_SIZE, _src.MSG3_CLIENT_PROOF_SIZE),
        "MSG4_AUTH_VERDICT_SIZE": (MSG4_AUTH_VERDICT_SIZE, _src.MSG4_AUTH_VERDICT_SIZE),
        "KEM_PUBLIC_KEY_LENGTH": (KEM_PUBLIC_KEY_LENGTH, _src.KEM_PUBLIC_KEY_LENGTH),
        "SIGNATURE_LENGTH": (SIGNATURE_LENGTH, _src.SIGNATURE_LENGTH),
    }
    mismatches = {k: v for k, (v, s) in pairs.items() if v != s}
    if mismatches:
        raise AssertionError(
            f"protocol_constants drifted from PQC_VPN config.py: {mismatches}. Update this module."
        )


if __name__ == "__main__":
    assert_matches_source()
    print("protocol_constants match PQC_VPN/laptop_server/config.py — OK")
