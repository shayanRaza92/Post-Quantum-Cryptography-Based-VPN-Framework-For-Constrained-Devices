#!/usr/bin/env python3
"""
Test 5 — per-IP rate-limit probe (BOUNDED, lab only).

Makes a small, clamped burst of brief connect-then-close attempts to observe the sliding-window
rate limiter: RATE_LIMIT_MAX_PER_IP = 5 connections per RATE_LIMIT_WINDOW_SEC = 10 s. Attempts
beyond the 5th within the window should be dropped by the gateway ([RATE-LIMIT] in its log).

It makes at most `requests` attempts (clamped) once — no loop, no sustained pressure.

Dry-run by default; --run needs config.json authorised + a lab target.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys
import time

import target_config as tc
import dos_common as dc


def run_live(cfg: dict, requested: int) -> int:
    host, port = tc.require_live_authorisation(cfg, run_flag=True)
    n, _ = dc.resolve_limits(cfg, requested, None)
    print(f"[{dc.timestamp()}] making {n} brief connections to {host}:{port} within ~{n*0.2:.1f}s")
    accepted = 0
    for i in range(n):
        s = dc.open_connection(host, port, timeout=3.0)
        if s is not None:
            accepted += 1
            s.close()
        print(f"  attempt {i+1}/{n}: {'connected' if s else 'refused/dropped'}")
        time.sleep(0.2)
    print(f"[{dc.timestamp()}] {accepted}/{n} TCP connects succeeded. Expect the gateway to start")
    print("  dropping after ~5 within a 10s window (see [RATE-LIMIT] in its log).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Per-IP rate-limit probe (bounded, lab only).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--requests", type=int, default=8, help="attempts in the burst (clamped)")
    args = ap.parse_args()

    cfg = tc.load_target()
    tc.banner("Test 5 — rate-limit probe", run_flag=args.run, cfg=cfg)

    if not args.run:
        req, _ = dc.resolve_limits(cfg, args.requests, None)
        print(f"\nWould make {req} brief connections (clamped) to observe the 5-per-10s per-IP")
        print("limit. Single bounded burst, no loop. Re-run with --run on an authorised target.")
        return 0
    try:
        return run_live(cfg, args.requests)
    except tc.AuthorisationError as exc:
        print(f"[BLOCKED] {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
