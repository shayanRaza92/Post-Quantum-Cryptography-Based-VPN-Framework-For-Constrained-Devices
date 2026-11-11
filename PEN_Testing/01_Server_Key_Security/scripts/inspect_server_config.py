#!/usr/bin/env python3
"""
Test 1 — static configuration review (READ-ONLY, no network, always safe to run).

Checks the gateway and ESP32 configuration for exposed secrets and insecure key handling, and
prints a findings table. It reads files only; it never derives or prints the private key.

What it checks, matched to the real implementation:
  * PQC_VPN/laptop_server/config.py : is SERVER_PRIVATE_SEED_HEX a hard-coded 64-hex literal?
                                      is it loaded from the environment instead?
  * PQC_VPN/esp32_client/config.h   : are WIFI_SSID / WIFI_PASSWORD still placeholders?
  * .gitignore                      : is *.so (the compiled key-bearing lib) ignored?

Usage:
    python scripts/inspect_server_config.py
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG_PY = REPO_ROOT / "PQC_VPN" / "laptop_server" / "config.py"
CONFIG_H = REPO_ROOT / "PQC_VPN" / "esp32_client" / "config.h"
GITIGNORE = REPO_ROOT / ".gitignore"

PLACEHOLDER_WIFI = {"YOUR_WIFI_SSID", "YOUR_WIFI_PASSWORD", "YOUR_LAPTOP_IP"}

findings: list[tuple[str, str, str]] = []  # (severity, check, detail)


def add(severity: str, check: str, detail: str) -> None:
    findings.append((severity, check, detail))


def check_server_seed() -> None:
    if not CONFIG_PY.exists():
        add("ERROR", "server seed", f"{CONFIG_PY} not found")
        return
    text = CONFIG_PY.read_text()

    # Is the seed read from the environment (secure) ...
    env_loaded = bool(re.search(r"os\.environ|getenv", text)) and "SEED" in text
    # ... or hard-coded as a 64-hex-char literal (insecure)?
    m = re.search(r'SERVER_PRIVATE_SEED_HEX\s*=\s*["\']([0-9a-fA-F]{64})["\']', text)

    if m:
        seed_hex = m.group(1)
        add(
            "CRITICAL",
            "server seed hard-coded",
            f"SERVER_PRIVATE_SEED_HEX is a committed 64-hex literal in config.py "
            f"(starts {seed_hex[:8]}..., ends ...{seed_hex[-8:]}). Anyone with the repo can "
            f"rebuild the gateway's ML-DSA-44 private key. Move it to an env var / untracked "
            f"file and rotate the key.",
        )
    elif env_loaded:
        add("OK", "server seed", "seed appears to be loaded from the environment — good.")
    else:
        add("WARN", "server seed", "could not classify how the seed is loaded; review manually.")


def check_wifi_credentials() -> None:
    if not CONFIG_H.exists():
        add("ERROR", "wifi creds", f"{CONFIG_H} not found")
        return
    text = CONFIG_H.read_text()
    for field in ("WIFI_SSID", "WIFI_PASSWORD"):
        m = re.search(rf'{field}\s*=\s*"([^"]*)"', text)
        if not m:
            add("WARN", f"{field}", "not found in config.h")
            continue
        value = m.group(1)
        if value in PLACEHOLDER_WIFI or value == "":
            add("OK", field, f'placeholder value ("{value}") — no real credential committed.')
        else:
            add(
                "HIGH",
                field,
                f'config.h contains a non-placeholder {field} ("{value}"). If this is a real '
                f"credential it must not be committed.",
            )


def check_gitignore() -> None:
    if not GITIGNORE.exists():
        add("WARN", ".gitignore", "no .gitignore at repo root")
        return
    text = GITIGNORE.read_text()
    if "*.so" in text:
        add("OK", ".gitignore", "*.so is ignored — the compiled key-bearing library is not shipped.")
    else:
        add("WARN", ".gitignore", "*.so not ignored; compiled libs could be committed.")


def main() -> None:
    print("=" * 72)
    print("  Test 1 — Static server/ESP32 configuration review (read-only)")
    print("=" * 72)
    check_server_seed()
    check_wifi_credentials()
    check_gitignore()

    width = max(len(s) for s, _, _ in findings)
    print(f"\n{'SEVERITY':<{width}}  CHECK")
    print("-" * 72)
    for severity, check, detail in findings:
        print(f"{severity:<{width}}  {check}")
        print(f"{'':<{width}}    {detail}")
    print("-" * 72)
    worst = next((s for s in ("CRITICAL", "HIGH", "WARN", "ERROR") if any(f[0] == s for f in findings)), "OK")
    print(f"Overall: {worst}. Record this in reports/ using TEST_RESULTS_TEMPLATE.md.")


if __name__ == "__main__":
    main()
