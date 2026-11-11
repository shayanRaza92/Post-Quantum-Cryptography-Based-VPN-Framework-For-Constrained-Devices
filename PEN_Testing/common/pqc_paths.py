"""
Locates the real PQC VPN source so tests can import the ACTUAL crypto/tunnel code instead of
re-implementing (and possibly mis-stating) the protocol.

Why import the real code? Tests 3 and 4 build genuine handshake messages and tunnel frames. If
they hand-rolled the framing they could drift from the implementation and give false results.
By importing `config`, `crypto_engine` and `secure_tunnel` straight from
`../PQC_VPN/laptop_server/`, the tests always match what the gateway actually does.

This module only manipulates sys.path (read-only use of the source). It does not modify, build,
or move anything under PQC_VPN/. Tests that need the native ML-KEM/ML-DSA libraries expect
`libmlkem512.so` / `libmldsa44.so` to already exist there (built by the project's own
build_native_libs.sh); this module does not build them.
"""
from __future__ import annotations

import sys
from pathlib import Path

PEN_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PEN_ROOT.parent
LAPTOP_SERVER = REPO_ROOT / "PQC_VPN" / "laptop_server"
ESP32_CLIENT = REPO_ROOT / "PQC_VPN" / "esp32_client"


def add_laptop_server_to_path() -> Path:
    """Puts PQC_VPN/laptop_server on sys.path so `import config/crypto_engine/secure_tunnel` work.

    Returns the path. Raises FileNotFoundError if the source is not where we expect.
    """
    if not LAPTOP_SERVER.is_dir():
        raise FileNotFoundError(f"PQC_VPN gateway source not found at {LAPTOP_SERVER}")
    p = str(LAPTOP_SERVER)
    if p not in sys.path:
        sys.path.insert(0, p)
    return LAPTOP_SERVER


def native_libs_present() -> dict:
    """Reports whether the compiled ML-KEM / ML-DSA shared libs exist (needed for real crypto).

    Returns {'mlkem512': bool, 'mldsa44': bool}. Tests that need them should check this and
    print a clear 'build_native_libs.sh first' message rather than crashing on import.
    """
    return {
        "mlkem512": (LAPTOP_SERVER / "libmlkem512.so").exists(),
        "mldsa44": (LAPTOP_SERVER / "libmldsa44.so").exists(),
    }


if __name__ == "__main__":
    print("repo root     :", REPO_ROOT)
    print("laptop_server :", LAPTOP_SERVER, "(exists)" if LAPTOP_SERVER.is_dir() else "(MISSING)")
    print("esp32_client  :", ESP32_CLIENT, "(exists)" if ESP32_CLIENT.is_dir() else "(MISSING)")
    print("native libs   :", native_libs_present())
