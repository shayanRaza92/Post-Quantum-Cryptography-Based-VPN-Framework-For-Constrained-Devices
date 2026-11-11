#!/usr/bin/env python3
"""
Test 4 — cross-direction injection (OFFLINE).

Each direction has its own key (K_c2s for ESP32->laptop, K_s2c for laptop->ESP32) and its own
DIR value in the nonce. A frame sealed for one direction must NOT decrypt when fed to the same
role that produced it (i.e. reflected back). This confirms an attacker cannot reflect a captured
S2C frame to the server as if it were a C2S frame.

Method: the server seals an S2C frame; feed it back into the SERVER's own feed() (which expects
C2S). It must raise TunnelError (wrong key + wrong DIR => auth failure).

Dry-run by default; --run performs the offline analysis.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys

import target_config as tc
import tunnel_harness as th


def analyse() -> int:
    server, client = th.make_tunnel_pair()
    s2c_frame = server.seal(b"downstream", th.MSG_DATA)

    # Reflect the S2C frame back to the server, which decrypts with the C2S key/DIR.
    reflector = th.make_tunnel_pair()[0]  # fresh server, rx_seq=0
    try:
        list(reflector.feed(s2c_frame))
        print("  reflect S2C frame to server -> ACCEPTED  ** VULNERABLE **")
        rc = 1
    except th.TunnelError as e:
        print(f"  reflect S2C frame to server -> rejected ({e})")
        rc = 0

    # Control: the intended client decrypts it fine.
    ok = list(client.feed(s2c_frame))
    print(f"  control (client decrypts)   -> {'ok' if ok else 'FAILED (unexpected)'}")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="Cross-direction injection (offline).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    tc.banner("Test 4 — cross-direction (OFFLINE)", run_flag=args.run, cfg={})
    if not args.run:
        print("\nWould seal an S2C frame and reflect it back to the server; it must be rejected")
        print("because each direction uses a distinct key and DIR. No network. Re-run with --run.")
        return 0
    return analyse()


if __name__ == "__main__":
    sys.exit(main())
