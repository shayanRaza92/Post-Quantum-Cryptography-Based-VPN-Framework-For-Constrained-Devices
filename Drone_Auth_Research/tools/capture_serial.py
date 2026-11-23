#!/usr/bin/env python3
"""Save the benchmark output from the ESP32 to a log file (and start the run).

Close the Arduino Serial Monitor first: only one program can use the port.

    python3 tools/capture_serial.py --port /dev/ttyUSB0

What it does:
  * opens the port (this usually resets the ESP32), waits for "Ready." and sends "S";
  * writes every line to results/e1/raw/sig_bench_<date>_<time>.log;
  * adds HOST lines with the date, the git commit and the port, for reproducibility;
  * shows progress (not the RAW sample lines) and stops a few seconds after the end.
"""
import argparse
import datetime as dt
import subprocess
import sys
import time
from pathlib import Path

try:
    import serial
except ImportError:
    sys.exit("pyserial is missing. Install it with: pip install pyserial")

ROOT = Path(__file__).resolve().parents[1]
SHOW = ("PROGRESS", "KAT", "SUM", "SIZE", "STACK", "HEAP", "LEAK", "ERROR", "WARN", "META,total", "###")


def git_info():
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "."], cwd=ROOT,
                               capture_output=True, text=True).stdout.strip()
        return commit or "unknown", "yes" if dirty else "no"
    except OSError:
        return "unknown", "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="serial port, e.g. /dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--out", default=str(ROOT / "results" / "e1" / "raw"), help="folder for the log file")
    ap.add_argument("--marker", default="SIG_BENCH", help="name after '### BEGIN'/'### END'")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"{args.marker.lower()}_{stamp}.log"
    commit, dirty = git_info()

    with serial.Serial(args.port, args.baud, timeout=1) as port, open(log_path, "w") as log:
        log.write(f"HOST,date,{dt.datetime.now().isoformat(timespec='seconds')}\n")
        log.write(f"HOST,git_commit,{commit}\nHOST,git_uncommitted_changes,{dirty}\nHOST,port,{args.port}\n")
        print(f"Logging to {log_path}\nWaiting for the ESP32 (press its EN/RESET button if nothing happens)...")
        started = ended = False
        end_time = None
        last_data = time.time()
        while True:
            raw = port.readline()
            now = time.time()
            if raw:
                last_data = now
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                log.write(line + "\n")
                log.flush()
                if not started and line.startswith("Ready."):
                    port.write(b"S\n")
                    started = True
                    print("Sent start command.")
                elif line.startswith(SHOW):
                    print(line)
                if line.startswith(f"### END {args.marker}"):
                    ended, end_time = True, now
            if ended and now - end_time > 5:
                break
            if now - last_data > 600:
                print("No data for 10 minutes. Is the board still running? (Ctrl+C to stop)")
                last_data = now
    print(f"\nDone. Log saved to {log_path}")
    print(f"Next: python3 tools/analyze_sig_bench.py {log_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user. The log so far was saved.")
