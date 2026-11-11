"""
Shared, SAFETY-FIRST helpers for the Test 5 DoS probes.

Design goals (mandated by TESTING_METHODOLOGY.md):
  * one place that loads the authorised target and clamps every probe to a small ceiling;
  * a single bounded connection helper — there is deliberately no "flood" primitive;
  * nothing here runs on import.

The hard ceiling comes from config.json (limits.dos_max_requests / dos_max_concurrent) and is
ALSO capped by ABSOLUTE_MAX below, so even a mis-edited config cannot turn these into a flood.
"""
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

_COMMON = Path(__file__).resolve().parents[3] / "PEN_Testing" / "common"
if str(_COMMON) not in sys.path:
    sys.path.insert(0, str(_COMMON))
import target_config as tc  # noqa: E402

# Absolute safety cap: no probe may ever exceed these, regardless of config.json.
ABSOLUTE_MAX_REQUESTS = 50
ABSOLUTE_MAX_CONCURRENT = 20


def resolve_limits(cfg: dict, requested: int | None, concurrent: int | None) -> tuple[int, int]:
    """Clamps requested counts to min(config ceiling, absolute max). Returns (requests, concurrent)."""
    cfg_req, cfg_conc = tc.dos_ceiling(cfg)
    req = min(requested or cfg_req, cfg_req, ABSOLUTE_MAX_REQUESTS)
    conc = min(concurrent or cfg_conc, cfg_conc, ABSOLUTE_MAX_CONCURRENT)
    return max(1, req), max(1, conc)


def open_connection(host: str, port: int, timeout: float = 5.0) -> socket.socket | None:
    """Opens ONE TCP connection and returns the socket, or None on failure. Caller closes it."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        return s
    except OSError:
        return None


def close_all(socks) -> None:
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


def timestamp() -> str:
    return time.strftime("%H:%M:%S")
