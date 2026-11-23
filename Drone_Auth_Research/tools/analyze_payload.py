#!/usr/bin/env python3
"""Tables and a figure for Step 2 (E2): message size and the largest message.

    python3 tools/analyze_payload.py results/e2/raw/payload_bench_<date>_<time>.log [--step1 <Step 1 summary.csv>]

Reuses the log reader and statistics of analyze_sig_bench.py. Writes to
results/e2/<log name>/:
  sweep.csv     time per algorithm, operation and message size (median + 95% CI, p95, p99, max)
  fit.csv       straight-line fit time = fixed part + per-KB part (on the medians)
  budget.csv    largest message that can be signed within 20 / 50 / 100 ms (median and p95).
                Model: time(L) = time for a 64-byte message + per-KB cost x (L - 64 B) / 1024.
                The 64-byte part comes from Step 1 (1,000 runs; newest results/e1/*/summary.csv
                unless --step1 is given). The per-KB cost is the straight-line fit of signing,
                except for ML-DSA, whose signing times jump too much to fit: there the per-KB
                cost of verifying is used, which is the same work (ML-DSA hashes the message
                once when signing and once when verifying).
  largest.csv   largest message the ESP32 could sign (measured) and what limit was hit
  frames.csv    how much data fits next to the signature in one radio frame (calculated)
  results.md    all of the above as readable tables
  figures/fig4_size_scaling.pdf/.png   sign and verify time vs message size
  figures/fig5_packets.pdf/.png        packets needed for one signed authentication message
                                       (64 bytes of data + the signature), calculated
"""
import argparse
import csv
import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_sig_bench import ORDER, parse, stats  # noqa: E402  (same folder)

ROOT = Path(__file__).resolve().parents[1]
BUDGETS_MS = [20, 50, 100]
# Payload per frame (bytes). MAVLink 2: protocol maximum. ESP-NOW and TCP: from the ESP32 core
# used here (esp_now.h: 250 / 1470 bytes; sdkconfig CONFIG_LWIP_TCP_MSS = 1436).
FRAMES = [("MAVLink 2 message", 255), ("ESP-NOW v1", 250), ("ESP-NOW v2", 1470), ("TCP segment (ESP32)", 1436)]


def extra_lines(path):
    """MAXMSG and E2STACK lines (not read by analyze_sig_bench.parse)."""
    largest, stack = {}, {}
    for line in Path(path).read_text(errors="replace").splitlines():
        parts = line.split(",")
        if parts[0] == "MAXMSG":
            largest[parts[1]] = dict(p.split("=", 1) for p in parts[2:])
        elif parts[0] == "E2STACK":
            stack[parts[1]] = dict(p.split("=", 1) for p in parts[2:])
    return largest, stack


def fit(sizes, times):
    """Least squares time = a + b * size. Returns a (ms), b (ms per byte), R^2."""
    x, y = np.asarray(sizes, float), np.asarray(times, float)
    b, a = np.polyfit(x, y, 1)
    pred = a + b * x
    ss_res, ss_tot = ((y - pred) ** 2).sum(), ((y - y.mean()) ** 2).sum()
    return a, b, (1 - ss_res / ss_tot) if ss_tot > 0 else 1.0


def plot(rows, sizes_by, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from plot_sig_bench import COLOR, DASH, name  # same colours and line styles as Step 1

    plt.rcParams.update({"font.size": 8, "legend.fontsize": 6.5, "xtick.labelsize": 7, "ytick.labelsize": 7,
                         "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                         "grid.color": "#e4e3df", "grid.linewidth": 0.6, "axes.axisbelow": True,
                         "legend.frameon": False, "savefig.dpi": 300, "savefig.bbox": "tight", "pdf.fonttype": 42})
    fig, axes = plt.subplots(1, 2, figsize=(3.5, 2.4), sharey=True)
    for ax, op, title in ((axes[0], "sign", "Sign (median)"), (axes[1], "verify", "Verify (median)")):
        for a in ORDER:
            pts = sorted((r["size"], r["median_ms"]) for r in rows if r["algorithm"] == a and r["operation"] == op)
            if pts:
                ax.plot([p[0] for p in pts], [p[1] for p in pts], color=COLOR[a], ls=DASH[a], lw=1.3,
                        marker="o", ms=2.5, label=name(a))
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_title(title, fontsize=8, loc="left")
        ax.set_xticks([64, 1024, 65536], ["64 B", "1 KB", "64 KB"])
        ax.set_xlabel("Message size")
    axes[0].set_ylabel("Time on ESP32 (ms, log scale)")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", bbox_to_anchor=(0.5, 0.98), ncol=3)
    out.mkdir(exist_ok=True)
    fig.savefig(out / "fig4_size_scaling.pdf")
    fig.savefig(out / "fig4_size_scaling.png")
    plt.close(fig)


AUTH_DATA_BYTES = 64          # drone ID, random challenge, timestamp: a typical authentication message


def plot_packets(sig_size, algs, out):
    """Packets needed for one signed authentication message (64 B data + signature)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from plot_sig_bench import name
    links = [("MAVLink 2 (255 B)", 255, "#2a78d6"), ("ESP-NOW v2 (1,470 B)", 1470, "#eb6834")]
    fig, ax = plt.subplots(figsize=(3.5, 2.3))
    x = np.arange(len(algs))
    w = 0.36
    for off, (label, fp, col) in zip((-w / 2 - 0.01, w / 2 + 0.01), links):
        vals = [math.ceil((AUTH_DATA_BYTES + sig_size[a]) / fp) for a in algs]
        ax.bar(x + off, vals, w, color=col, edgecolor="white", linewidth=0.5, label=label)
        for xi, v in zip(x + off, vals):
            ax.text(xi, v + 0.3, str(v), ha="center", va="bottom", fontsize=6, color="#0b0b0b")
    two_line = {"ECDSA-P256": "ECDSA\nP-256", "RSA-3072": "RSA\n3072", "ML-DSA-44": "ML-DSA\n44",
                "ML-DSA-65": "ML-DSA\n65", "ML-DSA-87": "ML-DSA\n87"}
    ax.set_xticks(x, [two_line.get(a, name(a)) for a in algs])
    ax.set_yticks([0, 5, 10, 15, 20])
    ax.tick_params(axis="x", length=0, labelsize=6.5)
    ax.set_ylabel("Packets per signed message")
    ax.set_ylim(0, 22)
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper left", fontsize=6.5)
    out.mkdir(exist_ok=True)
    fig.savefig(out / "fig5_packets.pdf")
    fig.savefig(out / "fig5_packets.png")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--step1", help="Step 1 summary.csv (default: the newest one)")
    args = ap.parse_args()
    log = Path(args.log)
    step1_path = Path(args.step1) if args.step1 else max((ROOT / "results" / "e1").glob("sig_bench_*/summary.csv"),
                                                         key=lambda q: q.stat().st_mtime, default=None)
    step1 = {}
    if step1_path and step1_path.exists():
        for r in csv.DictReader(open(step1_path)):
            if r["operation"] == "sign":
                step1[r["algorithm"]] = {"median": float(r["median_ms"]), "p95": float(r["p95_ms"])}
    d = parse(log)
    largest, stack = extra_lines(log)
    mhz = int(d["meta"].get("cpu_mhz", "240").split()[0])
    out = ROOT / "results" / "e2" / log.stem
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(1)

    # ---- per size statistics
    rows = []
    for (a, opsize), cyc in d["samples"].items():
        op, _, size = opsize.partition("_")
        if not size.isdigit():
            continue
        s = stats(cyc, mhz, rng)
        s.update({"algorithm": a, "operation": op, "size": int(size),
                  "failures": int(d["sum"].get((a, opsize), {}).get("fail", -1))})
        rows.append(s)
    rows.sort(key=lambda r: (ORDER.index(r["algorithm"]), r["operation"], r["size"]))
    algs = [a for a in ORDER if any(r["algorithm"] == a for r in rows)]
    sizes = sorted({r["size"] for r in rows})
    R = {(r["algorithm"], r["operation"], r["size"]): r for r in rows}

    cols = ["algorithm", "operation", "size", "n", "failures", "median_ms", "median_ci_low_ms", "median_ci_high_ms",
            "mean_ms", "p95_ms", "p99_ms", "max_ms", "std_ms"]
    with open(out / "sweep.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(r[k], 4) if isinstance(r[k], float) else r[k]) for k in cols})

    # ---- straight-line fits on the medians (and on p95 for the time budget)
    fits = {}
    for a in algs:
        for op in ("sign", "verify"):
            pts = [(s, R[(a, op, s)]) for s in sizes if (a, op, s) in R]
            fits[(a, op, "median")] = fit([p[0] for p in pts], [p[1]["median_ms"] for p in pts])
            fits[(a, op, "p95")] = fit([p[0] for p in pts], [p[1]["p95_ms"] for p in pts])
    with open(out / "fit.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "operation", "fixed_ms", "per_KB_ms", "r_squared"])
        for a in algs:
            for op in ("sign", "verify"):
                fa, fb, r2 = fits[(a, op, "median")]
                w.writerow([a, op, round(fa, 4), round(fb * 1024, 5), round(r2, 5)])

    # ---- largest message within a time budget (signing), capped at what fits in RAM
    def per_byte(a):
        op = "verify" if a.startswith("ML-DSA") else "sign"
        return fits[(a, op, "median")][1]

    def within(a, stat, budget):
        if a in step1:
            base = step1[a][stat]                    # 1,000 runs at 64 bytes
        else:                                        # no Step 1 data: use this run's fit
            base = fits[(a, "sign", stat)][0] + 64 * fits[(a, "sign", stat)][1]
        fb = per_byte(a)
        cap = int(largest.get(a, {}).get("max_ok", 0)) or None
        if budget <= base:
            return 0
        if fb <= 0:
            return cap
        n = 64 + int((budget - base) / fb)
        return min(n, cap) if cap else n

    budget_rows = []
    for a in algs:
        budget_rows.append([a] + [within(a, st, b) for b in BUDGETS_MS for st in ("median", "p95")])
    with open(out / "budget.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm"] + [f"{b}ms_{st}_bytes" for b in BUDGETS_MS for st in ("median", "p95")])
        w.writerows(budget_rows)

    # ---- largest message (measured)
    with open(out / "largest.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "largest_ok_bytes", "first_fail_bytes", "limit", "stack_given_B",
                    "free_heap_B", "largest_free_block_B", "sign_ms_at_largest"])
        for a in algs:
            m = largest.get(a)
            if m:
                w.writerow([a, m["max_ok"], m["first_fail"], m["reason"], m["stack_given"], m["free_heap"],
                            m["largest_block"], m["sign_ms_at_max"]])

    # ---- radio frames (calculated from the measured signature and key sizes)
    sig_size = {a: int(float(d["size"][a]["sig_max"])) if a in d["size"] else None for a in algs}
    if not any(sig_size.values()):                 # E2 logs carry no SIZE lines: use Step 1 sizes
        sig_size = {"Ed25519": 64, "ECDSA-P256": 72, "RSA-3072": 384, "ML-DSA-44": 2420, "ML-DSA-65": 3309,
                    "ML-DSA-87": 4627}
    frame_rows = []
    for a in algs:
        sg = sig_size[a]
        frame_rows.append([a, sg] + [max(fp - sg, 0) for _, fp in FRAMES] + [math.ceil(sg / fp) for _, fp in FRAMES])
    with open(out / "frames.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "signature_B"] + [f"data_left_in_one_{n.replace(' ', '_')}_B" for n, _ in FRAMES]
                   + [f"frames_for_signature_{n.replace(' ', '_')}" for n, _ in FRAMES])
        w.writerows(frame_rows)

    plot(rows, sizes, out / "figures")
    plot_packets(sig_size, algs, out / "figures")

    # ---- readable tables
    L = [f"# Step 2 (E2): message size and the largest message\n",
         f"Log: `{log.name}`. Board: {d['meta'].get('chip', '?')}, {d['meta'].get('cpu_mhz', '?')} MHz. "
         f"Runs per size: {d['meta'].get('e2_runs', '?')}. Sizes: {d['meta'].get('e2_sizes', '?')} bytes. "
         f"Git commit: `{d['host'].get('git_commit', '?')[:12]}`.\n"]
    for op in ("sign", "verify"):
        L += [f"\n## {op.capitalize()} time by message size (median ms; p95 in brackets)\n",
              "| Algorithm | " + " | ".join(f"{s:,} B" for s in sizes) + " |",
              "|---|" + "---:|" * len(sizes)]
        for a in algs:
            cells = []
            for s in sizes:
                r = R.get((a, op, s))
                cells.append(f"{r['median_ms']:,.2f} ({r['p95_ms']:,.1f})" if r else "-")
            L.append(f"| {a} | " + " | ".join(cells) + " |")
    L += ["\n## Cost of a longer message (straight-line fit on the medians)\n",
          "| Algorithm | Sign: fixed part (ms) | Sign: per KB (ms) | Verify: fixed part (ms) | Verify: per KB (ms) | Fit R² (sign / verify) |",
          "|---|---:|---:|---:|---:|---:|"]
    for a in algs:
        sa, sb, sr = fits[(a, "sign", "median")]
        va, vb, vr = fits[(a, "verify", "median")]
        L.append(f"| {a} | {sa:,.2f} | {sb * 1024:.4f} | {va:,.2f} | {vb * 1024:.4f} | {sr:.3f} / {vr:.3f} |")
    L += ["\n## Largest message the ESP32 could sign (measured)\n",
          "| Algorithm | Largest message (B) | Next size failed because | Stack given (B) | Free heap at start (B) | Largest free block (B) | Sign time at largest (ms) |",
          "|---|---:|---|---:|---:|---:|---:|"]
    for a in algs:
        m = largest.get(a)
        if m:
            L.append(f"| {a} | {int(m['max_ok']):,} | {m['reason'].replace('_', ' ')} | {int(m['stack_given']):,} | "
                     f"{int(m['free_heap']):,} | {int(m['largest_block']):,} | {float(m['sign_ms_at_max']):,.1f} |")
    L += ["\n## Largest message that can be signed within a time budget (bytes; 0 = not even a tiny message)\n",
          "| Algorithm | " + " | ".join(f"{b} ms (median) | {b} ms (p95)" for b in BUDGETS_MS) + " |",
          "|---|" + "---:|" * (2 * len(BUDGETS_MS))]
    for r in budget_rows:
        L.append(f"| {r[0]} | " + " | ".join(f"{x:,}" if x is not None else "-" for x in r[1:]) + " |")
    L += [f"\nMedian: the typical signature fits. p95: 95% of signatures fit. Model: time for a 64-byte message "
          f"({'Step 1, 1,000 runs: ' + step1_path.parent.name if step1 else 'this run'}) + per-KB cost "
          f"(ML-DSA: from verifying, the same hashing work). Capped at the largest message that fits in RAM.",
          "\n## Data that fits next to the signature in ONE frame (calculated, bytes)\n",
          "| Algorithm | Signature | " + " | ".join(f"{n} ({fp} B)" for n, fp in FRAMES) + " | Frames for the signature alone (MAVLink 2) |",
          "|---|---:|" + "---:|" * len(FRAMES) + "---:|"]
    for r in frame_rows:
        L.append(f"| {r[0]} | {r[1]:,} | " + " | ".join(f"{x:,}" for x in r[2:2 + len(FRAMES)]) + f" | {r[2 + len(FRAMES)]} |")
    L.append("\n0 = the signature alone does not fit in one frame, so the message must be split. "
             "Frame counts are a minimum (no extra headers for splitting are counted).")
    if stack:
        L += ["\n## Stack given to each algorithm in Step 2\n", "| Algorithm | Measured need (B) | Given (need + margin) (B) |",
              "|---|---:|---:|"]
        for a in algs:
            if a in stack:
                L.append(f"| {a} | {int(stack[a]['measured']):,} | {int(stack[a]['given']):,} |")
    fails = sum(max(r["failures"], 0) for r in rows)
    L.append(f"\nKnown-answer tests: {', '.join(f'{a} {v}' for a, v in d['kat'].items())}. Failed operations: {fails}.")
    if d["errors"]:
        L.append("\nErrors/warnings in the log:\n" + "\n".join(f"- `{e}`" for e in d["errors"]))
    (out / "results.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))
    print(f"\nFiles written to {out}")


if __name__ == "__main__":
    main()
