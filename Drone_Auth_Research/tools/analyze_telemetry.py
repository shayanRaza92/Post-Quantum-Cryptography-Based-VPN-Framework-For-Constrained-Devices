#!/usr/bin/env python3
"""Tables and figures for Step 5 (E5): signed MPU6050 telemetry on the ESP32.

    python3 tools/analyze_telemetry.py results/e5/raw/telemetry_bench_<date>_<time>.log [--out <folder>]

Writes to results/e5/<log name>/ (or --out):
  runs.csv       one row per run: samples due / taken / missed / dropped / signed, signing time,
                 age of the telemetry when its signature is ready, how late the samples were taken
  capacity.csv   how many samples per second each algorithm can sign (from the measured signing
                 times: typical = median, safe = p99), per mode
  radio.csv      bytes per sample and the radio speed needed to send all samples signed, with
                 MAVLink 2 framing (at most 255 payload bytes and 12 bytes of overhead per frame),
                 compared with a 57,600-baud telemetry radio (a serial line sends 10 bits per byte:
                 start bit, 8 data bits, stop bit, so 5,760 bytes/s). Calculated from the measured sizes.
                 Mode mavsign is MAVLink 2's own message signing (13 bytes per packet).
  results.md     all of the above as readable tables
  figures/fig11_signed_rate     signed samples per second vs sensor rate (sig1, sig10, MAVLink 2 signing)
  figures/fig12_age             age of the telemetry when its signature is ready (50 Hz)
  figures/fig13_sampling        does signing disturb the sensor sampling? (task vs simple loop)
  figures/fig14_radio           radio speed needed for signed telemetry at 50 Hz
"""
import argparse
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
ORDER = ["Ed25519", "ECDSA-P256", "RSA-3072", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
MAV_PAYLOAD, MAV_OVERHEAD, RADIO_KBPS = 255, 12, 57.6   # mavlink.io serialization: 255 B payload, 10 + 2 B
BITS_PER_BYTE = 10                                       # serial line 8N1
FIG_RATE = 50


def parse(path):
    meta, raw, runs, kat, errors = {}, defaultdict(list), {}, {}, []
    inside = False
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("### BEGIN"):
            inside = True
            continue
        if line.startswith("### END"):
            inside = False
            continue
        if not inside:
            continue
        p = line.split(",")
        if p[0] == "META" and len(p) >= 3:
            meta[p[1]] = ",".join(p[2:])
        elif p[0] == "SENSOR" and len(p) >= 3:
            meta["sensor_" + p[1]] = ",".join(p[2:])
        elif p[0] == "KAT":
            kat[p[1]] = p[2]
        elif p[0] == "RAW" and len(p) >= 5:
            raw[(p[1], p[2])] += [int(v) for v in p[4].split()]
        elif p[0] == "E5RUN":
            runs[p[1]] = {k: v for k, v in (x.split("=", 1) for x in p[2:])}
        elif p[0] in ("ERROR", "WARN"):
            errors.append(line)
    return meta, raw, runs, kat, errors


def q(values, pct):
    """Nearest-rank percentile, as on the device."""
    s = np.sort(values)
    return float(s[max(0, int(math.ceil(pct / 100 * len(s))) - 1)])


def summarise(meta, raw, runs):
    mhz = float(meta.get("cpu_mhz", 240))
    rows = []
    for name, r in runs.items():
        alg, arch, mode, rate = name.split("/")
        row = {"algorithm": alg, "arch": arch, "mode": mode, "rate_hz": int(rate), "batch": int(r["batch"]),
               "seconds": int(r["seconds"])}
        for k in ("due", "taken", "missed", "dropped", "signed", "messages", "backlog", "sign_fail",
                  "data_bytes", "tag_bytes", "i2c_errors"):
            row[k] = int(r[k])
        row["last_check"] = r["last_check"]
        row["signed_pct"] = 100.0 * row["signed"] / row["due"] if mode != "none" and row["due"] else float("nan")
        row["signed_per_s"] = row["signed"] / row["seconds"]
        row["missed_pct"] = 100.0 * row["missed"] / row["due"] if row["due"] else 0.0
        for op, unit, div in (("sign", "ms", mhz * 1000), ("age", "ms", mhz * 1000), ("late", "us", mhz)):
            v = np.asarray(raw.get((name, op), []), float) / div
            for stat in ("median", "p99", "max"):
                key = f"{op}_{stat}_{unit}"
                if len(v) == 0:
                    row[key] = float("nan")
                else:
                    row[key] = float(np.median(v)) if stat == "median" else q(v, 99) if stat == "p99" else float(v.max())
            if op == "sign":
                row["sign_mean_ms"] = float(v.mean()) if len(v) else float("nan")
        rows.append(row)
    return rows


def capacity(rows):
    """Samples per second each algorithm can sign, from the signing times of all its task runs."""
    out = []
    for alg in ORDER + ["MAVLink2-sign"]:
        for mode in ("sig1", "sig10", "mavsign"):
            rs = [r for r in rows if r["algorithm"] == alg and r["mode"] == mode and r["arch"] == "task"]
            if not rs:
                continue
            batch = rs[0]["batch"]
            med = float(np.median([r["sign_median_ms"] for r in rs]))
            p99 = max(r["sign_p99_ms"] for r in rs)
            mean = float(np.mean([r["sign_mean_ms"] for r in rs]))
            at100 = [r for r in rs if r["rate_hz"] == 100]
            out.append({"algorithm": alg, "mode": mode, "batch": batch, "sign_median_ms": med, "sign_mean_ms": mean,
                        "sign_p99_ms": p99, "max_rate_typical_hz": 1000 * batch / mean,
                        "max_rate_safe_hz": 1000 * batch / p99,
                        "measured_signed_per_s_at_100hz": at100[0]["signed_per_s"] if at100 else float("nan")})
    return out


def radio(rows):
    out, seen = [], set()
    for r in rows:
        if r["mode"] == "none" or r["arch"] != "task" or r["messages"] == 0:
            continue
        key = (r["algorithm"], r["mode"])
        if key in seen:
            continue
        seen.add(key)
        msg = r["data_bytes"] + r["tag_bytes"]
        frames = math.ceil(msg / MAV_PAYLOAD)
        on_air = msg + frames * MAV_OVERHEAD
        row = {"algorithm": r["algorithm"], "mode": r["mode"], "batch": r["batch"], "data_bytes": r["data_bytes"],
               "tag_bytes": r["tag_bytes"], "message_bytes": msg, "mavlink_frames": frames,
               "on_air_bytes_per_sample": on_air / r["batch"]}
        for hz in (10, 50, 100):
            row[f"kbit_s_at_{hz}hz"] = on_air * BITS_PER_BYTE * hz / r["batch"] / 1000
        row["max_hz_on_57k6_radio"] = RADIO_KBPS * 1000 / BITS_PER_BYTE / (on_air / r["batch"])
        out.append(row)
    order = {a: i for i, a in enumerate(ORDER + ["MAVLink2-sign"])}
    out.sort(key=lambda x: (order.get(x["algorithm"], 99), x["mode"]))
    return out


def write_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.3f}" if isinstance(v, float) else v) for k, v in r.items()})


def md_table(rows, cols, heads):
    def fmt(v):
        if isinstance(v, float):
            if math.isnan(v):
                return "-"
            return f"{v:,.0f}" if abs(v) >= 100 else f"{v:.1f}" if abs(v) >= 10 else f"{v:.2f}"
        return str(v)
    lines = ["| " + " | ".join(heads) + " |", "|" + "|".join("---" for _ in heads) + "|"]
    lines += ["| " + " | ".join(fmt(r[c]) for c in cols) + " |" for r in rows]
    return "\n".join(lines)


# ---- Figures ---------------------------------------------------------------------------------
def figures(rows, rad, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from plot_sig_bench import COLOR, DASH, name

    plt.rcParams.update({"font.size": 8, "legend.fontsize": 6.5, "xtick.labelsize": 7, "ytick.labelsize": 7,
                         "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                         "grid.color": "#e4e3df", "grid.linewidth": 0.6, "axes.axisbelow": True,
                         "legend.frameon": False, "savefig.dpi": 300, "savefig.bbox": "tight", "pdf.fonttype": 42})
    INK2, MAV_C = "#52514e", "#52514e"
    out.mkdir(parents=True, exist_ok=True)
    algs = [a for a in ORDER if any(r["algorithm"] == a for r in rows)]
    get = lambda alg, arch, mode, rate: next((r for r in rows if r["algorithm"] == alg and r["arch"] == arch
                                              and r["mode"] == mode and r["rate_hz"] == rate), None)
    rates = sorted({r["rate_hz"] for r in rows if r["arch"] == "task"})

    def save(fig, stem):
        fig.savefig(out / f"{stem}.pdf")
        fig.savefig(out / f"{stem}.png")
        plt.close(fig)

    # fig11: signed samples per second vs sensor rate
    fig, axes = plt.subplots(1, 2, figsize=(3.5, 2.5), sharey=True)
    for ax, mode, title in ((axes[0], "sig1", "Every sample signed"), (axes[1], "sig10", "10 samples per signature")):
        ax.plot(rates, rates, color="#b9b8b3", lw=0.8, ls=":", label="all samples")
        for a in algs:
            pts = [(hz, get(a, "task", mode, hz)) for hz in rates]
            pts = [(hz, r["signed_per_s"]) for hz, r in pts if r]
            if pts:
                ax.plot(*zip(*pts), color=COLOR[a], ls=DASH[a], lw=1.3, marker="o", ms=2.5, label=name(a))
        pts = [(hz, get("MAVLink2-sign", "task", "mavsign", hz)) for hz in rates]
        pts = [(hz, r["signed_per_s"]) for hz, r in pts if r]
        if pts:
            ax.plot(*zip(*pts), color="#b9b8b3", lw=2.6, marker="s", ms=3, zorder=1, label="MAVLink 2 signing")
        ax.set_title(title, fontsize=7.5)
        ax.set_xticks(rates)
        ax.set_xlabel("Sensor rate (samples/s)")
    axes[0].set_ylabel("Signed samples per second")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, fontsize=6)
    fig.tight_layout()
    save(fig, "fig11_signed_rate")

    # fig12: age of the telemetry when its signature is ready, at FIG_RATE
    fig, axes = plt.subplots(1, 2, figsize=(3.5, 2.4), sharey=True)
    labels = [name(a) for a in algs] + ["MAVLink sign"]
    for ax, mode, title in ((axes[0], "sig1", "Every sample signed"), (axes[1], "sig10", "10 samples per signature")):
        for i, a in enumerate(algs + ["MAVLink2-sign"]):
            r = get(a, "task", "mavsign" if a == "MAVLink2-sign" else mode, FIG_RATE)
            if not r or math.isnan(r["age_median_ms"]):
                continue
            c = MAV_C if a == "MAVLink2-sign" else COLOR[a]
            ax.plot([r["age_median_ms"], r["age_p99_ms"]], [i, i], color=c, lw=1.2)
            ax.plot(r["age_median_ms"], i, "o", color=c, ms=3.5)
            ax.plot(r["age_p99_ms"], i, "|", color=c, ms=7, mew=1.4)
        ax.set_xscale("log")
        ax.set_title(title, fontsize=7.5)
        ax.set_xlabel("Age when signed (ms)")
        ax.grid(axis="y", visible=False)
    axes[0].set_yticks(range(len(labels)))
    axes[0].set_yticklabels(labels)
    axes[0].invert_yaxis()
    fig.text(0.5, 1.0, f"{FIG_RATE} samples/s.  ● median   | p99", ha="center", va="bottom", fontsize=6.5, color=INK2)
    fig.tight_layout()
    save(fig, "fig12_age")

    # fig13: sampling lateness, task vs simple loop, and missed samples in the simple loop
    inline_rate = next((r["rate_hz"] for r in rows if r["arch"] == "inline"), FIG_RATE)
    fig, axes = plt.subplots(1, 2, figsize=(3.5, 2.4), sharey=True)
    base = get("none", "task", "none", inline_rate)
    y = np.arange(len(algs) + 1)
    names = algs + ["MAVLink2-sign"]
    for i, a in enumerate(names):
        mode = "mavsign" if a == "MAVLink2-sign" else "sig1"
        t, s = get(a, "task", mode, inline_rate), get(a, "inline", mode, inline_rate)
        c = MAV_C if a == "MAVLink2-sign" else COLOR[a]
        if t:
            axes[0].plot(t["late_p99_us"] / 1000, i - 0.15, "o", color=c, ms=3.5)
        if s:
            axes[0].plot(s["late_p99_us"] / 1000, i + 0.15, "x", color=c, ms=4, mew=1.2)
            axes[1].barh(i, s["missed_pct"], color=c, height=0.6)
            axes[1].text(s["missed_pct"] + 2, i, f"{s['missed_pct']:.0f}%", va="center", fontsize=6)
    if base:
        axes[0].axvline(base["late_p99_us"] / 1000, color="#b9b8b3", lw=0.8, ls=":")
    axes[0].set_xscale("log")
    axes[0].set_xlabel("Late, p99 (ms)")
    axes[0].set_title("● separate task   × simple loop", fontsize=6.5)
    axes[1].set_xlim(0, 110)
    axes[1].set_xlabel("Missed (%)")
    axes[1].set_title("Simple loop", fontsize=6.5)
    axes[0].set_yticks(y)
    axes[0].set_yticklabels([name(a) if a != "MAVLink2-sign" else "MAVLink sign" for a in names])
    axes[0].invert_yaxis()
    for ax in axes:
        ax.grid(axis="y", visible=False)
    fig.text(0.5, 1.0, f"Every sample signed, {inline_rate} samples/s", ha="center", va="bottom", fontsize=6.5,
             color=INK2)
    fig.tight_layout()
    save(fig, "fig13_sampling")

    # fig14: radio speed needed at FIG_RATE
    fig, ax = plt.subplots(figsize=(3.5, 2.2))
    labels, x = [], 0
    for a in algs + ["MAVLink2-sign"]:
        modes = ["mavsign"] if a == "MAVLink2-sign" else ["sig1", "sig10"]
        for j, mode in enumerate(modes):
            r = next((r for r in rad if r["algorithm"] == a and r["mode"] == mode), None)
            if not r:
                continue
            c = MAV_C if a == "MAVLink2-sign" else COLOR[a]
            v = r[f"kbit_s_at_{FIG_RATE}hz"]
            ax.bar(x + 0.42 * j, v, width=0.38, color=c, alpha=1.0 if mode != "sig10" else 0.45,
                   edgecolor=c, lw=0.6)
        labels.append((x + 0.21 * (len(modes) - 1), name(a) if a != "MAVLink2-sign" else "MAVLink sign"))
        x += 1
    ax.axhline(RADIO_KBPS, color="#0b0b0b", lw=0.8, ls="--")
    ax.text(-0.45, RADIO_KBPS * 1.12, "57,600-baud radio", ha="left", va="bottom", fontsize=6.3)
    ax.set_yscale("log")
    ax.set_xticks([p for p, _ in labels])
    ax.set_xticklabels([l for _, l in labels], rotation=30, ha="right", fontsize=6.5)
    ax.set_ylabel(f"Radio speed needed (kbit/s)\nat {FIG_RATE} samples/s")
    ax.set_title("Solid: every sample signed.  Light: 10 samples per signature.", fontsize=6.5)
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    save(fig, "fig14_radio")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--out", help="output folder (default: results/e5/<log name>)")
    args = ap.parse_args()
    log = Path(args.log)
    meta, raw, runs, kat, errors = parse(log)
    if not runs:
        sys.exit("No E5RUN lines found. Is this a Step 5 (TELEMETRY_BENCH) log?")
    out = Path(args.out) if args.out else ROOT / "results" / "e5" / log.stem
    out.mkdir(parents=True, exist_ok=True)

    rows = summarise(meta, raw, runs)
    order = {a: i for i, a in enumerate(["none"] + ORDER + ["MAVLink2-sign"])}
    rows.sort(key=lambda r: (order.get(r["algorithm"], 99), r["arch"] != "task", r["mode"], r["rate_hz"]))
    cap, rad = capacity(rows), radio(rows)
    write_csv(out / "runs.csv", rows)
    write_csv(out / "capacity.csv", cap)
    write_csv(out / "radio.csv", rad)

    md = [f"# Step 5 results: signed MPU6050 telemetry\n", f"Log: `{log.name}`  ",
          f"Sensor: {meta.get('sensor', '?')}  ", f"Seconds per run: {meta.get('seconds_per_run', '?')}  ",
          f"Known-answer tests: " + ", ".join(f"{k} {v}" for k, v in kat.items()) + "\n"]
    if errors:
        md += ["**Errors / warnings in the log:**\n"] + [f"    {e}" for e in errors] + [""]
    bad = [r for r in rows if r["last_check"] == "FAIL" or r["sign_fail"]]
    md.append(f"Signature checks: {'all passed' if not bad else 'FAILED in ' + ', '.join(r['algorithm'] for r in bad)}\n")
    md += ["## Runs (separate sensor task and signing task)\n",
           md_table([r for r in rows if r["arch"] == "task"],
                    ["algorithm", "mode", "rate_hz", "due", "signed", "signed_pct", "dropped", "sign_median_ms",
                     "sign_p99_ms", "age_median_ms", "age_p99_ms", "late_p99_us", "late_max_us"],
                    ["Algorithm", "Mode", "Rate", "Due", "Signed", "Signed %", "Dropped", "Sign med ms",
                     "Sign p99 ms", "Age med ms", "Age p99 ms", "Late p99 us", "Late max us"]), "",
           "## Runs (simple loop: read the sensor, then sign, in one loop)\n",
           md_table([r for r in rows if r["arch"] == "inline"],
                    ["algorithm", "mode", "rate_hz", "due", "taken", "missed", "missed_pct", "signed",
                     "late_p99_us", "late_max_us"],
                    ["Algorithm", "Mode", "Rate", "Due", "Taken", "Missed", "Missed %", "Signed", "Late p99 us",
                     "Late max us"]), "",
           "## How many samples per second can be signed\n",
           md_table(cap, ["algorithm", "mode", "sign_median_ms", "sign_p99_ms", "max_rate_typical_hz",
                          "max_rate_safe_hz", "measured_signed_per_s_at_100hz"],
                    ["Algorithm", "Mode", "Sign med ms", "Sign p99 ms", "Max rate (mean) /s", "Max rate (p99) /s",
                     "Measured at 100 Hz /s"]), "",
           f"## Radio: bytes and speed needed (MAVLink 2 frames, {MAV_PAYLOAD} B payload + {MAV_OVERHEAD} B "
           f"overhead per frame)\n",
           md_table(rad, ["algorithm", "mode", "message_bytes", "mavlink_frames", "on_air_bytes_per_sample",
                          "kbit_s_at_10hz", "kbit_s_at_50hz", "kbit_s_at_100hz", "max_hz_on_57k6_radio"],
                    ["Algorithm", "Mode", "Message B", "Frames", "On-air B/sample", "kbit/s @10", "kbit/s @50",
                     "kbit/s @100", "Max rate on 57,600 baud"]), ""]
    (out / "results.md").write_text("\n".join(md))
    figures(rows, rad, out / "figures")
    print((out / "results.md").read_text())
    print(f"\nWritten to {out}")


if __name__ == "__main__":
    main()
