#!/usr/bin/env python3
"""Graphs for the Ed25519 vs. ML-DSA-44 benchmark, made from the ESP32 output saved in results/.

    python3 make_graphs.py                      # uses results/sig_bench_run1.log
    python3 make_graphs.py results/<other>.log

Reads the summary table the ESP32 prints at the end and writes graphs/fig_*.png (the file names the
README uses). Times are shown as the median with the min-max range; sizes in bytes (1 KB = 1,024 B).
"""
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
OUT = HERE / "graphs"
C_ED, C_ML, INK, INK2, GRID = "#2a78d6", "#eb6834", "#0b0b0b", "#52514e", "#e4e3df"
NAMES = ("Ed25519\n(classical)", "ML-DSA-44\n(post-quantum, FIPS 204)")

plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                     "axes.grid.axis": "y", "grid.color": GRID, "axes.axisbelow": True, "font.size": 10,
                     "axes.titlesize": 11, "axes.titleweight": "bold", "axes.titlelocation": "left",
                     "savefig.dpi": 200, "savefig.bbox": "tight"})


def parse(log_text):
    """Returns {row label: (ed25519 cell, ml-dsa cell)} from the final summary table."""
    table = log_text[log_text.index("DIGITAL SIGNATURE BENCHMARK SUMMARY"):]
    rows = {}
    for line in table.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 4 and parts[1] and not parts[1].startswith("Metric"):
            rows[parts[1]] = (parts[2], parts[3])
    return rows


def num(cell):
    return float(re.search(r"[-\d.]+", cell.replace(",", "")).group())


def rng(cell):
    a, b = re.findall(r"[\d.]+", cell)[:2]
    return float(a), float(b)


def bars(name, title, ylabel, vals, labels, ylim=None):
    fig, ax = plt.subplots(figsize=(6.4, 4))
    for x, v, col, lab in zip((0, 1), vals, (C_ED, C_ML), labels):
        ax.bar(x, v, 0.55, color=col)
        ax.annotate(lab, (x, v), xytext=(0, 4), textcoords="offset points", ha="center", va="bottom",
                    fontsize=9, color=INK)
    ax.set_xticks([0, 1], NAMES)
    ax.tick_params(axis="x", length=0)
    ax.set_ylabel(ylabel, color=INK2)
    ax.set_title(title)
    ax.set_ylim(0, ylim or max(vals) * 1.3 + 1e-9)
    fig.savefig(OUT / name)
    plt.close(fig)
    print("saved", OUT / name)


def main():
    log = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "results" / "sig_bench_run1.log"
    r = parse(log.read_text(errors="replace"))
    OUT.mkdir(exist_ok=True)

    def timed(prefix, med_key, range_key, fname, title):
        med = [num(c) for c in r[med_key]]
        lo_hi = [rng(c) for c in r[range_key]]
        labels = [f"{m:.2f} ms\n(range {a:g}-{b:g} ms)" for m, (a, b) in zip(med, lo_hi)]
        bars(fname, f"{prefix}: {title} (median of 100 runs)", "Time on the ESP32 at 240 MHz (ms)", med, labels)

    timed("SIG-1", "KeyGen Latency (Median)", "KeyGen Range (Min - Max)", "fig_keygen_mean.png", "make a key pair")
    timed("SIG-3", "Message Signing Time (Median)", "Signing Range (Min - Max)", "fig_signing_latency.png", "sign")
    timed("SIG-5", "Verification Time (Median)", "Verify Range (Min - Max)", "fig_verify_latency.png", "verify")

    pk = [num(c) for c in r["Public Key Wire Size"]]
    bars("fig_public_key_wire_size.png", "SIG-2: public key size", "Bytes", pk, [f"{v:,.0f} B" for v in pk])
    sig = [num(c) for c in r["Signature Wire Size (Fixed)"]]
    bars("fig_signature_wire_size.png", "SIG-4: signature size", "Bytes", sig, [f"{v:,.0f} B" for v in sig])

    sign = [num(c) for c in r["Message Signing Time (Median)"]]
    ver = [num(c) for c in r["Verification Time (Median)"]]
    tot = [a + b for a, b in zip(sign, ver)]
    bars("fig_crypto_auth_cost.png", "SIG-6: sign + verify per handshake (medians)", "Time on the ESP32 (ms)",
         tot, [f"{t:.2f} ms" for t in tot])
    heap = [num(c) for c in r["Steady-State Heap (Sign+Verify)"]]
    bars("fig_heap_steady_state.png", "SIG-7: heap used while signing and verifying", "Bytes", heap,
         [f"{v:,.0f} B" for v in heap], ylim=1024)
    stack = [num(c) for c in r["Peak Crypto Stack Usage (True)"]]
    bars("fig_stack_usage.png", "SIG-8: stack used (task has 64 KB)", "Bytes", stack,
         [f"{v:,.0f} B ({v / 1024:.1f} KB)" for v in stack])


if __name__ == "__main__":
    main()
