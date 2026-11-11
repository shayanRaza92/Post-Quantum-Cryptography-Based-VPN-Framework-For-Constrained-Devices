#!/usr/bin/env python3
"""
Test 2 — ESP32 hardware-security checklist (DRY-RUN by default; NON-destructive).

Prints the esptool.py / espefuse.py commands that reveal whether the board's defences against
key extraction are enabled (Flash Encryption, Secure Boot v2, JTAG/UART-download restriction),
along with how to interpret each result.

SAFETY:
  * Default mode prints commands only; it does NOT talk to any board.
  * Even with --run, this script only runs the READ-ONLY inspection commands
    (`flash_id`, `espefuse summary`). It never reads/writes flash contents and never burns an
    eFuse. Destructive operations (read_flash, burn_efuse) are intentionally NOT implemented.

Usage:
    python scripts/esp32_security_checklist.py                 # dry-run: print commands
    python scripts/esp32_security_checklist.py --run --port /dev/ttyUSB0
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

READONLY_CHECKS = [
    {
        "name": "Chip / flash identification",
        "argv_tmpl": ["esptool.py", "--port", "{port}", "flash_id"],
        "interpret": "Confirms chip revision and flash size. Baseline inventory only.",
    },
    {
        "name": "eFuse summary (the important one)",
        "argv_tmpl": ["espefuse.py", "--port", "{port}", "summary"],
        "interpret": (
            "Look for:\n"
            "       FLASH_CRYPT_CNT / SPI_BOOT_CRYPT_CNT -> Flash Encryption state\n"
            "       ABS_DONE_1 / SECURE_BOOT_EN          -> Secure Boot v2 state\n"
            "       JTAG_DISABLE / DISABLE_DL_* (download mode restrictions)\n"
            "     Encryption+SecureBoot OFF  => seed is extractable  => VULNERABLE\n"
            "     Encryption ON (release)    => flash dump is ciphertext => seed protected"
        ),
    },
]

# Documented for the report, but deliberately NOT runnable here (destructive / extraction):
OUT_OF_SCOPE = [
    "esptool.py --port <port> read_flash 0 0x400000 flash.bin   # (flash DUMP — not performed)",
    "espefuse.py --port <port> burn_efuse ...                   # (irreversible — not performed)",
]


def print_plan(port: str) -> None:
    print("\nRead-only inspection commands (DRY-RUN — nothing executed):\n")
    for chk in READONLY_CHECKS:
        cmd = " ".join(chk["argv_tmpl"]).replace("{port}", port)
        print(f"  # {chk['name']}")
        print(f"  {cmd}")
        print(f"    interpret: {chk['interpret']}\n")
    print("Explicitly OUT OF SCOPE for this phase (shown for the report only, never run here):")
    for line in OUT_OF_SCOPE:
        print(f"  # {line}")
    print("\nRe-run with --run --port <serial> to execute ONLY the read-only checks above.")


def run_checks(port: str) -> int:
    worst = 0
    for chk in READONLY_CHECKS:
        tool = chk["argv_tmpl"][0]
        if shutil.which(tool) is None:
            print(f"[SKIP] '{tool}' not in PATH. `pip install esptool` first.")
            worst = max(worst, 2)
            continue
        argv = [a.replace("{port}", port) for a in chk["argv_tmpl"]]
        print(f"\n[RUN] {chk['name']}: {' '.join(argv)}")
        try:
            worst = max(worst, subprocess.run(argv, check=False).returncode)
        except OSError as exc:
            print(f"[ERROR] {exc}")
            worst = max(worst, 2)
    print("\nRecord espefuse summary output in reports/ (TEST_RESULTS_TEMPLATE.md).")
    return worst


def main() -> int:
    ap = argparse.ArgumentParser(description="ESP32 read-only hardware-security checklist.")
    ap.add_argument("--run", action="store_true", help="execute the read-only checks on a board")
    ap.add_argument("--port", default="<serial-port>", help="serial port, e.g. /dev/ttyUSB0")
    args = ap.parse_args()

    print("=" * 72)
    print("  Test 2 — ESP32 hardware-security checklist")
    print(f"  Mode : {'LIVE read-only (--run)' if args.run else 'DRY-RUN'}   Port: {args.port}")
    print("=" * 72)

    if not args.run:
        print_plan(args.port)
        return 0
    if args.port == "<serial-port>":
        print("[ABORT] --run requires --port <serial>. No board contacted.")
        return 2
    return run_checks(args.port)


if __name__ == "__main__":
    sys.exit(main())
