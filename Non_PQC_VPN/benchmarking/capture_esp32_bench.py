#!/usr/bin/env python3
"""
Saves an ESP32 benchmark run to files, so nothing has to be copied from the Serial Monitor by hand.

    python3 capture_esp32_bench.py --port /dev/ttyUSB0 --out system_benchmark/results --name esp32_results_run1
    python3 capture_esp32_bench.py --port /dev/ttyUSB0 --out mutual_auth_benchmark/results --name sig_bench_run1

Close the Arduino Serial Monitor first (only one program can use the port). Opening the port resets
the ESP32, so the benchmark starts from the beginning.

Writes:
  <out>/<name>.log   every line the ESP32 printed, plus HOST lines (date, git commit, port)
  <out>/<name>.csv   only the "BENCH,..." lines, without the "BENCH," prefix (system benchmark)
It stops when the ESP32 prints "BENCHMARK COMPLETE" (or after --timeout minutes).
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
    sys.exit("pyserial is missing: pip install pyserial")

END_MARK = "BENCHMARK COMPLETE"
SHOW = ("SYSTEM BENCHMARK", "META", "BENCH,B0", "[B", "  ...", "SIG-", "ERROR", "FAIL", "Could not", "[KAT", "CPU Frequency",
        "Arduino core", "ESP-IDF")


def git_commit():
    try:
        root = Path(__file__).resolve().parents[2]
        c = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
        d = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True)
        return c.stdout.strip() or "unknown", "yes" if d.stdout.strip() else "no"
    except OSError:
        return "unknown", "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--out", required=True, help="folder for the .log and .csv")
    ap.add_argument("--name", required=True, help="file name without extension, e.g. esp32_results_run1")
    ap.add_argument("--timeout", type=float, default=40, help="minutes before giving up")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    log_path, csv_path = out / f"{args.name}.log", out / f"{args.name}.csv"
    for p in (log_path, csv_path):
        if p.exists():
            sys.exit(f"{p} already exists: choose another --name (e.g. run2) so no result is overwritten")

    commit, dirty = git_commit()
    bench_lines, done = [], False
    deadline = time.time() + args.timeout * 60
    with serial.Serial(args.port, args.baud, timeout=1) as port, open(log_path, "w") as log:
        port.setDTR(False); port.setRTS(True); time.sleep(0.1); port.setRTS(False)   # reset the ESP32
        log.write(f"HOST,date,{dt.datetime.now().isoformat(timespec='seconds')}\n")
        log.write(f"HOST,git_commit,{commit}\nHOST,git_uncommitted_changes,{dirty}\nHOST,port,{args.port}\n")
        print(f"Logging to {log_path}  (waiting for the ESP32; press EN/RESET if nothing appears)")
        while time.time() < deadline:
            raw = port.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            log.write(line + "\n")
            log.flush()
            if line.startswith("BENCH,"):
                bench_lines.append(line[len("BENCH,"):])
            if line.startswith(SHOW) or END_MARK in line:
                print(line)
            if END_MARK in line:
                done = True
                break
    if bench_lines:
        csv_path.write_text("\n".join(bench_lines) + "\n")
    print(f"\n{'Finished' if done else 'STOPPED (timeout, run incomplete)'}: {log_path}"
          + (f" and {csv_path} ({len(bench_lines) - 1} results)" if bench_lines else ""))


if __name__ == "__main__":
    main()
