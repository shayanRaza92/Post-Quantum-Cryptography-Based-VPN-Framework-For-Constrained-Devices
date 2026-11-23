#!/usr/bin/env python3
"""Figures and the deadline table for Step 1 (E1), from the files analyze_sig_bench.py wrote.

    python3 tools/plot_sig_bench.py results/e1/sig_bench_<date>_<time>

Writes into <that folder>/figures/ (PDF for the paper, PNG for viewing):
  fig1_auth_time      sign and verify time per algorithm (median, line up to p99), log scale
  fig2_sign_cdf       share of signatures finished within a given time (all 1,000 runs)
  fig3_mldsa_levels   cost of ML-DSA-65 and ML-DSA-87 relative to ML-DSA-44
and <that folder>/deadlines.csv: share of signatures slower than 20, 50, 100 and 200 ms.
Sized for one IEEE column (3.5 in wide), 8-pt text, readable in black and white.
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# Fixed colour per algorithm (categorical palette, slots 1-6, always in this order)
COLOR = {"Ed25519": "#2a78d6", "ECDSA-P256": "#eb6834", "RSA-3072": "#1baf7a",
         "ML-DSA-44": "#eda100", "ML-DSA-65": "#e87ba4", "ML-DSA-87": "#008300"}
DASH = {"Ed25519": "-", "ECDSA-P256": "-", "RSA-3072": "-",
        "ML-DSA-44": (0, (5, 1.5)), "ML-DSA-65": (0, (2, 1.2)), "ML-DSA-87": (0, (6, 1.5, 1.5, 1.5))}
LABEL = {"ECDSA-P256": "ECDSA P-256"}
CLASSIC_VS_PQ = ["Ed25519", "ECDSA-P256", "RSA-3072", "ML-DSA-44"]
ALL = ["Ed25519", "ECDSA-P256", "RSA-3072", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
SIGN_C, VERIFY_C = "#2a78d6", "#eb6834"
DEADLINES_MS = [20, 50, 100, 200]

plt.rcParams.update({
    "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8, "legend.fontsize": 7,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "legend.frameon": False, "savefig.dpi": 300, "savefig.bbox": "tight", "pdf.fonttype": 42,
})


def name(a):
    return LABEL.get(a, a)


def load(run):
    summary = {(r["algorithm"], r["operation"]): {k: float(v) for k, v in r.items() if k.endswith("_ms")}
               for r in csv.DictReader(open(run / "summary.csv"))}
    samples = defaultdict(list)
    for r in csv.DictReader(open(run / "samples.csv")):
        samples[(r["algorithm"], r["operation"])].append(float(r["ms"]))
    sizes = {r["algorithm"]: r for r in csv.DictReader(open(run / "sizes.csv"))}
    memory = {(r["algorithm"], r["operation"]): r for r in csv.DictReader(open(run / "memory.csv"))}
    return summary, {k: np.array(v) for k, v in samples.items()}, sizes, memory


def save(fig, out, stem):
    fig.savefig(out / f"{stem}.pdf")
    fig.savefig(out / f"{stem}.png")
    plt.close(fig)


def fig1(summary, out):
    """Sign and verify per algorithm: bar = median, thin line up to p99."""
    fig, ax = plt.subplots(figsize=(3.5, 2.35))
    x = np.arange(len(CLASSIC_VS_PQ))
    w = 0.36
    for off, op, col in ((-w / 2 - 0.01, "sign", SIGN_C), (w / 2 + 0.01, "verify", VERIFY_C)):
        for i, a in enumerate(CLASSIC_VS_PQ):
            s = summary[(a, op)]
            ax.bar(x[i] + off, s["median_ms"], w, color=col, edgecolor="white", linewidth=0.5,
                   label=f"{op.capitalize()} (median)" if i == 0 else None)
            if s["p99_ms"] > s["median_ms"] * 1.02:
                ax.plot([x[i] + off] * 2, [s["median_ms"], s["p99_ms"]], color=INK2, lw=0.8)
                ax.plot([x[i] + off - 0.06, x[i] + off + 0.06], [s["p99_ms"]] * 2, color=INK2, lw=0.8)
            top = max(s["median_ms"], s["p99_ms"])
            ax.text(x[i] + off, top * 1.12, f"{s['median_ms']:.1f}" if s["median_ms"] < 100 else f"{s['median_ms']:.0f}",
                    ha="center", va="bottom", fontsize=6, color=INK)
    ax.plot([], [], color=INK2, lw=0.8, label="line up to p99")
    ax.set_yscale("log")
    ax.set_ylim(1, 3000)
    ax.set_xticks(x, [name(a) for a in CLASSIC_VS_PQ])
    ax.tick_params(axis="x", length=0)
    ax.set_ylabel("Time on ESP32 (ms, log scale)")
    ax.legend(loc="upper left", ncol=3, handlelength=1.2, columnspacing=0.8, bbox_to_anchor=(0, 1.02))
    ax.grid(axis="x", visible=False)
    save(fig, out, "fig1_auth_time")


def fig2(samples, out):
    """Empirical CDF of signing time for all six algorithms, with drone deadlines."""
    fig, ax = plt.subplots(figsize=(3.5, 2.7))
    for a in ALL:
        v = np.sort(samples[(a, "sign")])
        y = np.arange(1, len(v) + 1) / len(v) * 100
        ax.plot(v, y, color=COLOR[a], ls=DASH[a], lw=1.4, label=name(a))
    for d in (20, 100):
        ax.axvline(d, color=INK2, lw=0.7, ls=":")
        ax.text(d, 102, f"{d} ms", color=INK2, fontsize=6, ha="center", va="bottom")
    ax.set_xscale("log")
    ax.set_xlim(5, 1500)
    ax.set_ylim(0, 101)
    ax.set_xlabel("Signing time (ms, log scale)")
    ax.set_ylabel("Signatures finished (%)")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.07), ncol=3, handlelength=2.2, columnspacing=1.0)
    save(fig, out, "fig2_sign_cdf")


def fig3(summary, sizes, memory, out):
    """ML-DSA-65 and ML-DSA-87 relative to ML-DSA-44 (= 1)."""
    base = "ML-DSA-44"
    metrics = [("Keygen", lambda a: summary[(a, "keygen")]["median_ms"]),
               ("Sign", lambda a: summary[(a, "sign")]["median_ms"]),
               ("Verify", lambda a: summary[(a, "verify")]["median_ms"]),
               ("Sig.\nbytes", lambda a: float(sizes[a]["signature_max_B"])),
               ("Pub. key\nbytes", lambda a: float(sizes[a]["public_key_B"])),
               ("Stack\n(sign)", lambda a: float(memory[(a, "sign")]["peak_stack_B"]))]
    fig, ax = plt.subplots(figsize=(3.5, 2.3))
    x = np.arange(len(metrics))
    w = 0.36
    for off, a in ((-w / 2 - 0.01, "ML-DSA-65"), (w / 2 + 0.01, "ML-DSA-87")):
        vals = [f(a) / f(base) for _, f in metrics]
        ax.bar(x + off, vals, w, color=COLOR[a], edgecolor="white", linewidth=0.5, label=a)
        for xi, v in zip(x + off, vals):
            ax.text(xi, v + 0.05, f"{v:.2f}", ha="center", va="bottom", fontsize=5.5, color=INK)
    ax.axhline(1, color=INK2, lw=0.8, ls="--", label="ML-DSA-44 (= 1)")
    ax.set_xticks(x, [m for m, _ in metrics])
    ax.tick_params(axis="x", length=0)
    ax.set_ylim(0, 3.3)
    ax.set_ylabel("Relative to ML-DSA-44")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, columnspacing=1.0)
    ax.grid(axis="x", visible=False)
    save(fig, out, "fig3_mldsa_levels")


def deadlines(samples, run):
    rows = []
    for a in ALL:
        v = samples[(a, "sign")]
        rows.append([a, len(v)] + [round(100 * float((v > d).mean()), 1) for d in DEADLINES_MS])
    with open(run / "deadlines.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "n"] + [f"slower_than_{d}ms_percent" for d in DEADLINES_MS])
        w.writerows(rows)
    return rows


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run = Path(sys.argv[1])
    out = run / "figures"
    out.mkdir(exist_ok=True)
    summary, samples, sizes, memory = load(run)
    fig1(summary, out)
    fig2(samples, out)
    fig3(summary, sizes, memory, out)
    for r in deadlines(samples, run):
        print("deadline misses (% of signatures slower than 20/50/100/200 ms):", r)
    print(f"Figures in {out}")


if __name__ == "__main__":
    main()
