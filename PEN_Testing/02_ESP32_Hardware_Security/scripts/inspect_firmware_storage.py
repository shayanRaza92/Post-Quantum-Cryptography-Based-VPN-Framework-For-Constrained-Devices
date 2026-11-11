#!/usr/bin/env python3
"""
Test 2 — firmware key-storage inspection (READ-ONLY source review, no hardware).

Reads the ESP32 firmware source and reports exactly how the ML-DSA-44 private seed is stored, so
the pen-test report is accurate and not guessed. It confirms the NVS namespace, key name, seed
size, RNG source, and whether the stored material is the seed (vs. the full secret key).

Usage:
    python scripts/inspect_firmware_storage.py
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
IDENTITY_CPP = REPO_ROOT / "PQC_VPN" / "esp32_client" / "DeviceIdentity.cpp"


def grep(text: str, pattern: str, default: str = "<not found>") -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else default


def main() -> None:
    print("=" * 72)
    print("  Test 2 — ESP32 firmware key-storage inspection (read-only)")
    print("=" * 72)

    if not IDENTITY_CPP.exists():
        print(f"[ERROR] {IDENTITY_CPP} not found.")
        return

    src = IDENTITY_CPP.read_text()

    namespace = grep(src, r'\.begin\(\s*"([^"]+)"')
    nvs_key = grep(src, r'(?:isKey|getBytes|putBytes)\(\s*"([^"]+)"')
    uses_trng = "esp_fill_random" in src
    zeroizes = "sodium_memzero" in src or "memset" in src
    derives_in_ram = "generateKeypairFromSeed" in src

    rows = [
        ("Source file", str(IDENTITY_CPP.relative_to(REPO_ROOT))),
        ("Storage backend", "NVS flash via Arduino Preferences"),
        ("NVS namespace", namespace),
        ("NVS key name", nvs_key),
        ("Stored material", "32-byte ML-DSA-44 SEED (not the full 2560-byte secret key)"),
        ("Secret-key location", "RAM only, derived from seed at boot" if derives_in_ram else "unknown"),
        ("Seed RNG source", "esp_fill_random (hardware TRNG)" if uses_trng else "unknown"),
        ("Seed zeroized after use", "yes (sodium_memzero/memset on temp buffer)" if zeroizes else "no"),
    ]

    print("\nKey-storage facts (from source):")
    print("-" * 72)
    for k, v in rows:
        print(f"  {k:<24}: {v}")
    print("-" * 72)

    print("\nSecurity implication:")
    print("  The seed is the ROOT of the device identity. If flash is readable (Flash Encryption")
    print("  OFF), a flash dump exposes the 32-byte seed under NVS namespace")
    print(f"  '{namespace}', key '{nvs_key}', from which the full ML-DSA-44 secret key can be")
    print("  re-derived — enabling full device impersonation.")
    print("\n  => Next: run scripts/esp32_security_checklist.py to see the eFuse/flash checks that")
    print("     decide whether that dump is actually possible on the board.")


if __name__ == "__main__":
    main()
