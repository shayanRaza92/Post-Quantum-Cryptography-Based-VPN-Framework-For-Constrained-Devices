"""
Shared target-configuration loader and SAFETY GATE for the PQC VPN pen-test framework.

Every active script imports `load_target()` and calls `require_live_authorisation()` before it
is ever allowed to touch a live target. This centralises the rules of engagement so no single
script can accidentally send traffic to an unauthorised host:

  * config.json must exist and set  "authorised": true
  * a target host and port must be present
  * the script must additionally be invoked with --run (dry-run is the default everywhere)

Nothing in this module sends packets. It only reads JSON and decides whether a later action is
permitted. Importing it has no side effects.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# config.json lives at the PEN_Testing root (one level above common/).
PEN_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PEN_ROOT / "config.json"
EXAMPLE_PATH = PEN_ROOT / "config.example.json"


class AuthorisationError(RuntimeError):
    """Raised when a script tries to act on a live target without passing the safety gate."""


def load_target() -> dict:
    """Loads config.json (never the example). Returns the parsed dict, or {} if absent.

    A missing config.json is NOT an error: scripts can still run in --dry-run mode, which does
    not need a real target.
    """
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise AuthorisationError(f"config.json is present but unreadable: {exc}") from None


def describe_target(cfg: dict) -> str:
    tgt = cfg.get("target", {})
    host = tgt.get("host", "<unset>")
    port = tgt.get("port", "<unset>")
    return f"{host}:{port}"


def require_live_authorisation(cfg: dict, run_flag: bool) -> tuple[str, int]:
    """The single choke point every active test must pass before touching a live target.

    Returns (host, port) only if ALL of these hold:
      * run_flag is True          (operator explicitly passed --run)
      * cfg['authorised'] is True (operator confirmed they own the lab target)
      * target host and port set

    Otherwise raises AuthorisationError. In dry-run mode (run_flag False) scripts must not call
    this; they describe their plan and exit.
    """
    if not run_flag:
        raise AuthorisationError(
            "Internal error: require_live_authorisation() called without --run. "
            "Dry-run code paths must never reach the network."
        )
    if not cfg:
        raise AuthorisationError(
            f"No config.json found. Copy {EXAMPLE_PATH.name} to config.json and set your "
            "authorised lab target before using --run."
        )
    if not cfg.get("authorised") is True:
        raise AuthorisationError(
            'config.json must set "authorised": true to confirm you own/operate the target. '
            "Refusing to send any traffic."
        )
    tgt = cfg.get("target", {})
    host, port = tgt.get("host"), tgt.get("port")
    if not host or not port:
        raise AuthorisationError('config.json "target.host" and "target.port" must be set.')
    return host, int(port)


def dos_ceiling(cfg: dict) -> tuple[int, int]:
    """Returns (max_requests, max_concurrent) hard caps for Test 5, defaulting conservatively."""
    limits = cfg.get("limits", {})
    return int(limits.get("dos_max_requests", 20)), int(limits.get("dos_max_concurrent", 10))


def banner(script_name: str, run_flag: bool, cfg: dict) -> None:
    """Prints a consistent header so every run records its mode and target."""
    mode = "LIVE (--run)" if run_flag else "DRY-RUN (no traffic will be sent)"
    print("=" * 72)
    print(f"  {script_name}")
    print(f"  Mode   : {mode}")
    print(f"  Target : {describe_target(cfg) if cfg else '<no config.json>'}")
    print("=" * 72)


if __name__ == "__main__":
    # Lets you sanity-check your config without running any test.
    cfg = load_target()
    banner("target_config self-check", run_flag=False, cfg=cfg)
    if not cfg:
        print("No config.json yet. Copy config.example.json -> config.json.")
        sys.exit(0)
    print("authorised :", cfg.get("authorised"))
    print("target     :", describe_target(cfg))
    print("dos ceiling:", dos_ceiling(cfg))
