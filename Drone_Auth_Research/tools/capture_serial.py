#!/usr/bin/env python3
"""Save the benchmark output from the ESP32 to a log file (and start the run).

Close the Arduino Serial Monitor first: only one program can use the port.

    python3 tools/capture_serial.py --port /dev/ttyUSB0                   # Step 1
    python3 tools/capture_serial.py --port /dev/ttyUSB0 --experiment e2   # Step 2
    python3 tools/capture_serial.py --port /dev/ttyUSB0 --experiment e3   # Step 3 (then gcs_link_test.py)
    python3 tools/capture_serial.py --port /dev/ttyUSB0 --experiment e5   # Step 5

What it does:
  * opens the port (this usually resets the ESP32), waits for "Ready." and sends the start
    command ("S" for Step 1, "P" for Step 2, "W" for Step 3, "T" for Step 5);
  * writes every line to results/<experiment>/raw/<name>_<date>_<time>.log;
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
SHOW = ("PROGRESS", "KAT", "SUM", "SIZE", "STACK", "HEAP", "LEAK", "MAXMSG", "E2STACK", "ERROR", "WARN",
        "META,total", "META,drone_ip", "META,wifi", "META,sensor", "SENSOR", "E5RUN", "LINK", "KEY", "###")
CRASH = ("Guru Meditation", "CORRUPT HEAP", "assert failed", "Backtrace", "Rebooting", "rst:", "Ready.")
EXPERIMENTS = {"e1": ("S", "SIG_BENCH"), "e2": ("P", "PAYLOAD_BENCH"), "e3": ("W", "LINK_TEST"), "e5": ("T", "TELEMETRY_BENCH")}


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
    ap.add_argument("--experiment", choices=sorted(EXPERIMENTS), default="e1", help="e1 = Step 1, e2 = Step 2, e3 = Step 3, e5 = Step 5")
    ap.add_argument("--out", help="folder for the log file (default: results/<experiment>/raw)")
    args = ap.parse_args()
    command, args.marker = EXPERIMENTS[args.experiment]

    out_dir = Path(args.out) if args.out else ROOT / "results" / args.experiment / "raw"
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
                    port.write(command.encode() + b"\n")
                    started = True
                    print("Sent start command.")
                elif started and not ended and line.startswith(CRASH):
                    print(line)
                    if line.startswith("Ready."):
                        print("\nThe ESP32 restarted in the middle of the run (see the lines above). "
                              "Stopping; the log was saved.")
                        break
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
    if args.experiment == "e3":
        print("Next: python3 tools/analyze_link.py results/e3/raw/link_<date>_<time>  (the folder gcs_link_test.py made)")
    else:
        tool = {"e1": "analyze_sig_bench.py", "e2": "analyze_payload.py", "e5": "analyze_telemetry.py"}[args.experiment]
        print(f"Next: python3 tools/{tool} {log_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user. The log so far was saved.")
