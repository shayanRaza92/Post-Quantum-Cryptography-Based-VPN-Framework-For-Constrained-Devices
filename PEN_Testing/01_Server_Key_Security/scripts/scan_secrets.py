#!/usr/bin/env python3
"""
Test 1 — secret scanning orchestrator for gitleaks and trufflehog.

Runs industry-standard secret scanners over the repository WORKING TREE and FULL GIT HISTORY to
find the ML-DSA seed, Wi-Fi credentials, or any other secret ever committed. Results are written
as JSON under ../reports/.

SAFETY: dry-run is the default. With no flag (or --dry-run) it only PRINTS the commands it would
run and does not execute anything. Pass --run to actually invoke the scanners. The scanners are
read-only analysers of the local repo; this script sends nothing over the network.

Usage:
    python scripts/scan_secrets.py            # dry-run: print the commands
    python scripts/scan_secrets.py --dry-run  # same
    python scripts/scan_secrets.py --run      # execute gitleaks + trufflehog, write reports/
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEST_DIR = HERE.parent
REPO_ROOT = HERE.parents[3]
REPORTS = TEST_DIR / "reports"
RULES = TEST_DIR / "scripts" / "gitleaks.toml"


def build_jobs(stamp: str) -> list[dict]:
    """Returns the scanner invocations as structured jobs (tool, argv, output file)."""
    return [
        {
            "tool": "gitleaks",
            "desc": "Scan full git history for committed secrets using project rules",
            "argv": [
                "gitleaks", "detect",
                "--source", str(REPO_ROOT),
                "--config", str(RULES),
                "--report-format", "json",
                "--report-path", str(REPORTS / f"gitleaks_{stamp}.json"),
                "--redact",
            ],
        },
        {
            "tool": "trufflehog",
            "desc": "Scan git history with trufflehog's detectors (verification off = offline)",
            "argv": [
                "trufflehog", "git", f"file://{REPO_ROOT}",
                "--json", "--no-verification",
            ],
            "stdout_to": str(REPORTS / f"trufflehog_{stamp}.json"),
        },
    ]


def print_plan(jobs: list[dict]) -> None:
    print("\nPlanned commands (DRY-RUN — nothing executed):\n")
    for job in jobs:
        print(f"  # {job['desc']}")
        line = " ".join(job["argv"])
        if "stdout_to" in job:
            line += f" > {job['stdout_to']}"
        print(f"  {line}\n")
    print("Re-run with --run to execute. Install gitleaks/trufflehog first (see requirements.txt).")


def run_jobs(jobs: list[dict]) -> int:
    REPORTS.mkdir(exist_ok=True)
    worst_rc = 0
    for job in jobs:
        tool = job["tool"]
        if shutil.which(tool) is None:
            print(f"[SKIP] '{tool}' not installed/in PATH. Install it and re-run.")
            worst_rc = max(worst_rc, 2)
            continue
        print(f"[RUN] {tool}: {job['desc']}")
        try:
            if "stdout_to" in job:
                with open(job["stdout_to"], "w") as out:
                    rc = subprocess.run(job["argv"], stdout=out, check=False).returncode
            else:
                rc = subprocess.run(job["argv"], check=False).returncode
        except OSError as exc:
            print(f"[ERROR] could not launch {tool}: {exc}")
            worst_rc = max(worst_rc, 2)
            continue
        # Both tools exit non-zero when they FIND secrets; that is an expected finding, not a crash.
        print(f"[DONE] {tool} exit={rc} "
              f"({'secrets found — review report' if rc == 1 else 'no secrets / see output'})")
        worst_rc = max(worst_rc, 0 if rc in (0, 1) else rc)
    print(f"\nReports written to: {REPORTS}")
    return worst_rc


def main() -> int:
    ap = argparse.ArgumentParser(description="Run gitleaks + trufflehog over the PQC VPN repo.")
    ap.add_argument("--run", action="store_true", help="actually execute the scanners")
    ap.add_argument("--dry-run", action="store_true", help="print commands only (default)")
    args = ap.parse_args()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jobs = build_jobs(stamp)

    print("=" * 72)
    print("  Test 1 — secret scanning (gitleaks + trufflehog)")
    print(f"  Repo   : {REPO_ROOT}")
    print(f"  Mode   : {'LIVE (--run)' if args.run else 'DRY-RUN'}")
    print("=" * 72)

    if not args.run:
        print_plan(jobs)
        return 0
    return run_jobs(jobs)


if __name__ == "__main__":
    sys.exit(main())
