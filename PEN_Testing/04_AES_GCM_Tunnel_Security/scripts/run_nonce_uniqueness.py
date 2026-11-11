#!/usr/bin/env python3
"""
Test 4 — AES-GCM nonce uniqueness (OFFLINE).

GCM is broken if a (key, nonce) pair ever repeats. The real SecureTunnel builds the nonce as
DIR(4B) || SEQ(8B). This checks:
  * within one key, sealing N frames yields N distinct nonces (SEQ increments);
  * the two directions use different DIR values (C2S=1, S2C=2), so they never collide even at
    the same SEQ;
  * a rekey installs a NEW key and resets SEQ to 0, so the reused nonce is paired with a fresh
    key (no (key, nonce) repeat).

Dry-run by default; --run performs the offline analysis.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import struct
import sys

import target_config as tc
import tunnel_harness as th

N = 50


def nonce_of(tunnel, seq):
    # Mirror of SecureTunnel._nonce for inspection (DIR from the tx direction).
    return struct.pack(">IQ", tunnel._tx_dir, seq)


def analyse() -> int:
    server, client = th.make_tunnel_pair()
    problems = []

    # (1) uniqueness within one key, server direction
    nonces = set()
    for _ in range(N):
        seq = server.tx_seq
        server.seal(b"x", th.MSG_DATA)
        nonces.add(nonce_of(server, seq))
    print(f"  server sealed {N} frames -> {len(nonces)} distinct nonces "
          f"({'OK' if len(nonces) == N else '** REPEAT **'})")
    if len(nonces) != N:
        problems.append("intra-key repeat")

    # (2) directions differ
    print(f"  DIR server(S2C)={server._tx_dir}  DIR client(C2S)={client._tx_dir} "
          f"({'OK (distinct)' if server._tx_dir != client._tx_dir else '** SAME **'})")
    if server._tx_dir == client._tx_dir:
        problems.append("same direction id")

    # (3) rekey resets seq under a new key
    before_key = server.k_s2c
    server.rekey(b"\x07" * 32, epoch=1)
    after_key = server.k_s2c
    print(f"  after rekey: tx_seq={server.tx_seq} (expect 0), "
          f"key changed={'yes' if before_key != after_key else 'NO ** VULNERABLE **'}")
    if server.tx_seq != 0 or before_key == after_key:
        problems.append("rekey did not refresh key/seq")

    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Nonce uniqueness (offline).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    tc.banner("Test 4 — nonce uniqueness (OFFLINE)", run_flag=args.run, cfg={})
    if not args.run:
        print(f"\nWould seal {N} frames, check all nonces distinct, confirm C2S/S2C use different")
        print("DIR values, and that rekey resets SEQ under a new key. No network. Re-run with --run.")
        return 0
    return analyse()


if __name__ == "__main__":
    sys.exit(main())
