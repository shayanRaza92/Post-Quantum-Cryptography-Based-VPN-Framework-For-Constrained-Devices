#!/usr/bin/env python3
"""
Combines several benchmark runs into one table: for every KPI, the value of each run and the
mean over the runs with a 95% confidence interval (Student t, as in the project's test plan).

    python3 aggregate_runs.py esp32 \
        --classical ../../../Non_PQC_VPN/benchmarking/system_benchmark/results/esp32_results_run{1,2,3}.csv \
        --pqc results/esp32_results_run{1,2,3}.csv
    python3 aggregate_runs.py laptop \
        --classical ../../../Non_PQC_VPN/benchmarking/system_benchmark/results/laptop_gateway_results_run{1,2,3}.csv \
        --pqc results/laptop_gateway_results_run{1,2,3}.csv

For a KPI that is itself a median (e.g. handshake time), each run contributes its median, and the
table shows the mean of those medians +- the 95% CI over runs. Memory is in KB with 1 KB = 1,024 bytes.
Writes results/<kind>_summary.md and results/<kind>_summary.csv.
"""
import argparse
import csv
import math
import statistics
from pathlib import Path

OUT = Path(__file__).resolve().parent / "results"
T95 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262}

# (test id, metric, column, label, scale, unit)
ESP32_KPIS = [
    ("B1", "aes_gcm_encrypt_plus_decrypt_64B_per_KB", "mean", "AES-256-GCM enc+dec, 64 B message", 1, "ms/KB"),
    ("B1", "aes_gcm_encrypt_plus_decrypt_1023B_per_KB", "mean", "AES-256-GCM enc+dec, 1,023 B message", 1, "ms/KB"),
    ("B2", "handshake_msg1_to_msg4", "median", "Handshake (MSG 1-4), median", 1, "ms"),
    ("B2", "handshake_msg1_to_msg4", "p95", "Handshake (MSG 1-4), p95", 1, "ms"),
    ("B2", "tcp_connect_time", "median", "TCP connect, median", 1, "ms"),
    ("B2", "handshake_failures", "mean", "Failed handshakes (of 100)", 1, ""),
    ("B2", "handshake_bytes_on_wire", "mean", "Handshake bytes on the wire", 1, "B"),
    ("B3", "added_latency_median_64B", "mean", "Added round-trip delay, 64 B (median VPN - median plain)", 1, "ms"),
    ("B3", "added_latency_median_1023B", "mean", "Added round-trip delay, 1,023 B (median VPN - median plain)", 1, "ms"),
    ("B4a", "max_goodput_application_data", "mean", "Maximum goodput (application data)", 1, "kbps"),
    ("B4b", "delivered_rate_gateway_acked", "mean", "Delivered at 102.4 kbps offered", 1, "kbps"),
    ("B4b", "ack_latency_under_load", "median", "Reply time during the 102.4 kbps stream, median", 1, "ms"),
    ("B4b", "ack_latency_under_load", "p95", "Reply time during the 102.4 kbps stream, p95", 1, "ms"),
    ("B5", "rekey_time", "median", "Rekey, median", 1, "ms"),
    ("B5", "rekey_time", "p95", "Rekey, p95", 1, "ms"),
    ("B6", "cpu_idle_tunnel_average", "mean", "CPU, tunnel open and quiet", 1, "%"),
    ("B6", "cpu_normal_ping_average", "mean", "CPU, one ping every 1.5 s", 1, "%"),
    ("B6", "cpu_sustained_512B_average", "mean", "CPU, 102.4 kbps stream", 1, "%"),
    ("B7", "heap_peak_used", "mean", "Peak heap used", 1 / 1024, "KB"),
    ("B7", "heap_free_now", "mean", "Heap still free after the run", 1 / 1024, "KB"),
    ("B7", "task_stack_never_used", "mean", "Task stack never used", 1 / 1024, "KB"),
    ("B7", "flash_firmware_size", "mean", "Program size (benchmark build)", 1 / 1024, "KB"),
]
LAPTOP_KPIS = [
    ("L2", "seal_1023B", "median", "Gateway encrypt, 1,023 B, median", 1000, "us"),
    ("L2", "open_1023B", "median", "Gateway decrypt, 1,023 B, median", 1000, "us"),
    ("L3", "handshake_total_loopback", "median", "Full handshake on the laptop, median", 1, "ms"),
    ("L3", "handshake_total_loopback", "p95", "Full handshake on the laptop, p95", 1, "ms"),
    ("L4", "rekey_round_trip_loopback", "median", "Rekey on the laptop, median", 1, "ms"),
    ("L5", "burst_10_devices_accepted", "mean", "10 devices at once: accepted", 1, ""),
    ("L5", "burst_40_devices_accepted", "mean", "40 devices at once: accepted", 1, ""),
    ("L6", "tunnels_1_aggregate_messages_per_s", "mean", "1 device: messages per second", 1, "msg/s"),
    ("L6", "tunnels_10_aggregate_messages_per_s", "mean", "10 devices: messages per second", 1, "msg/s"),
    ("L6", "tunnels_40_aggregate_messages_per_s", "mean", "40 devices: messages per second", 1, "msg/s"),
    ("L6", "tunnels_40_round_trip", "median", "40 devices: reply time, median", 1, "ms"),
    ("L6", "tunnels_40_sessions_dropped", "mean", "40 devices: sessions dropped", 1, ""),
]


def load(path):
    rows = {}
    with open(path) as f:
        for r in csv.DictReader(f):
            rows[(r["id"], r["metric"])] = r
    return rows


def values(runs, tid, metric, col, scale):
    out = []
    for rows in runs:
        r = rows.get((tid, metric))
        if r is not None and r.get(col) not in (None, ""):
            out.append(float(r[col]) * scale)
    return out


def summary(vals):
    if not vals:
        return None, None
    m = statistics.fmean(vals)
    if len(vals) < 2:
        return m, None
    return m, T95.get(len(vals), 1.96) * statistics.stdev(vals) / math.sqrt(len(vals))


def fmt(x, unit):
    if x is None:
        return "-"
    a = abs(x)
    if unit in ("", "B"):
        return f"{x:,.0f}" if float(x).is_integer() else f"{x:,.1f}"
    d = 0 if a >= 1000 else (1 if a >= 10 else 2)
    return f"{x:,.{d}f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kind", choices=["esp32", "laptop"])
    ap.add_argument("--classical", nargs="+", required=True)
    ap.add_argument("--pqc", nargs="+", required=True)
    args = ap.parse_args()
    kpis = ESP32_KPIS if args.kind == "esp32" else LAPTOP_KPIS
    cl, pq = [load(p) for p in args.classical], [load(p) for p in args.pqc]

    lines = [f"# {args.kind.upper()} benchmark: {len(cl)} classical runs, {len(pq)} post-quantum runs",
             "", "Each cell: mean over the runs +- 95% confidence interval (Student t). For KPIs that are a",
             "median or p95, each run contributes its own median / p95. 1 KB = 1,024 bytes.", "",
             "| KPI | Unit | Classical: per run | Classical: mean +- 95% CI | Post-quantum: per run | "
             "Post-quantum: mean +- 95% CI |", "|---|---|---|---|---|---|"]
    rows_csv = []
    for tid, metric, col, label, scale, unit in kpis:
        cv, pv = values(cl, tid, metric, col, scale), values(pq, tid, metric, col, scale)
        cm, cci = summary(cv)
        pm, pci = summary(pv)
        cell = lambda m, ci: "-" if m is None else (fmt(m, unit) if ci is None else f"{fmt(m, unit)} +- {fmt(ci, unit)}")
        lines.append(f"| {tid} {label} | {unit} | {', '.join(fmt(v, unit) for v in cv)} | {cell(cm, cci)} | "
                     f"{', '.join(fmt(v, unit) for v in pv)} | {cell(pm, pci)} |")
        rows_csv.append({"id": tid, "metric": metric, "column": col, "label": label, "unit": unit,
                         "classical_runs": ";".join(f"{v:.4f}" for v in cv),
                         "classical_mean": "" if cm is None else f"{cm:.4f}",
                         "classical_ci95": "" if cci is None else f"{cci:.4f}",
                         "pqc_runs": ";".join(f"{v:.4f}" for v in pv),
                         "pqc_mean": "" if pm is None else f"{pm:.4f}",
                         "pqc_ci95": "" if pci is None else f"{pci:.4f}"})
    lines += ["", "Runs used:", *[f"* classical: {p}" for p in args.classical], *[f"* post-quantum: {p}" for p in args.pqc]]
    md = "\n".join(lines) + "\n"
    OUT.mkdir(exist_ok=True)
    (OUT / f"{args.kind}_summary.md").write_text(md)
    with open(OUT / f"{args.kind}_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_csv[0].keys()))
        w.writeheader()
        w.writerows(rows_csv)
    print(md)
    print(f"Saved {OUT / (args.kind + '_summary.md')} and .csv")


if __name__ == "__main__":
    main()
