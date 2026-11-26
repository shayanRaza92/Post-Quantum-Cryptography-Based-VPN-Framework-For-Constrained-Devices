#!/usr/bin/env python3
"""
Demo 4: how much memory a Qiskit simulation of Shor's algorithm needs.

    .venv/bin/python scripts/run_memory_table.py            # measures up to 26 qubits
    .venv/bin/python scripts/run_memory_table.py --max 28   # bigger (needs ~4.5 GB free RAM)

A statevector simulator stores 2^n complex numbers (16 bytes each) for n qubits, so the memory
doubles with every qubit. This script
  1. MEASURES the real peak memory of Qiskit Aer for growing numbers of qubits (each in its own
     process), and
  2. CALCULATES the memory for our demos and for real targets:
       RSA-2048  : 2n + 3 = 4,099 logical qubits      (Beauregard 2003, arXiv:quant-ph/0205095)
       256-bit elliptic curve (like X25519 / Ed25519):
                   9n + 2*ceil(log2 n) + 10 = 2,330     (Roetteler et al. 2017, arXiv:1706.06752)
Writes results/memory_table.txt and results/fig_memory.png.
"""
import argparse
import json
import math
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qshor import human_bytes, statevector_bytes  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "results"

PROBE = r"""
import json, resource, sys, time
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
n = int(sys.argv[1])
qc = QuantumCircuit(n)
qc.h(range(n))
for i in range(n - 1):
    qc.cx(i, i + 1)
qc.measure_all()
sim = AerSimulator(method="statevector")
t0 = time.perf_counter()
sim.run(transpile(qc, sim), shots=16).result()
secs = time.perf_counter() - t0
print(json.dumps({"n": n, "peak_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, "secs": secs}))
"""


def measure(n: int):
    r = subprocess.run([sys.executable, "-c", PROBE, str(n)], capture_output=True, text=True, timeout=1800)
    return json.loads(r.stdout.strip().splitlines()[-1]) if r.returncode == 0 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max", type=int, default=26, help="largest number of qubits to measure")
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)

    base = measure(2)
    lines = ["Memory needed to simulate a quantum computer (Qiskit Aer, statevector, complex128)", "=" * 78,
             "Measured on this laptop (peak memory of the whole Python process; the first ~"
             f"{base['peak_mb']:.0f} MB is Python + Qiskit itself):",
             f"  {'qubits':>6}  {'state (calculated)':>18}  {'peak process (measured)':>24}  {'time':>8}"]
    measured = []
    for n in list(range(10, args.max + 1, 2)):
        r = measure(n)
        if r is None:
            lines.append(f"  {n:>6}  failed (not enough memory?)")
            break
        measured.append(r)
        lines.append(f"  {n:>6}  {human_bytes(statevector_bytes(n)):>18}  {r['peak_mb']:>21,.0f} MB  {r['secs']:>6.2f} s")

    rows = [("Demo 1: factor N = 15", 12), ("Demo 1: factor N = 21", 15), ("Demo 1: factor N = 35", 18),
            ("Demo 2: toy elliptic-curve key (p = 13)", 19), ("Demo 3: group vs LWE (q = 13)", 16),
            ("Largest that fits in this laptop's 16 GB", 29),
            ("Real 256-bit elliptic curve (X25519/Ed25519)", 2330), ("Real RSA-2048", 4099)]
    lines += ["", "Calculated (16 bytes x 2^qubits):", f"  {'case':<46}{'qubits':>7}  memory"]
    for name, n in rows:
        lines.append(f"  {name:<46}{n:>7,}  {human_bytes(statevector_bytes(n))}")
    lines += ["", "For comparison: 1 TB = 10^12 bytes. Real X25519 or RSA cannot be simulated at all;",
              "they need a real, large, error-corrected quantum computer."]
    text = "\n".join(lines)
    print(text)
    (OUT / "memory_table.txt").write_text(text + "\n")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ns = list(range(8, 36))
    fig, ax = plt.subplots(figsize=(5.6, 3.2))
    ax.plot(ns, [statevector_bytes(n) / 2 ** 30 for n in ns], color="#2a78d6", lw=1.6, label="calculated: 16 B x 2^n")
    if measured:
        ax.plot([r["n"] for r in measured], [r["peak_mb"] / 1024 for r in measured], "o", color="#eb6834", ms=4,
                label="measured peak (this laptop)")
    ax.axhline(16, color="#d03b3b", ls="--", lw=1)
    ax.text(8.3, 20, "this laptop: 16 GB", fontsize=7, color="#d03b3b")
    for name, n in rows[:5]:
        ax.axvline(n, color="#b9b8b3", lw=0.6, ls=":")
    ax.set_yscale("log")
    ax.set_xlabel("number of simulated qubits", fontsize=8)
    ax.set_ylabel("memory (GB, log scale)", fontsize=8)
    ax.set_title("Memory doubles with every qubit (our demos: dotted lines, 12-19 qubits)\n"
                 "real X25519 needs ~2,330 qubits, RSA-2048 ~4,099: impossible to simulate", fontsize=8)
    ax.legend(fontsize=7, frameon=False)
    ax.tick_params(labelsize=7)
    fig.tight_layout()
    fig.savefig(OUT / "fig_memory.png", dpi=200)
    print("\nSaved results/memory_table.txt and results/fig_memory.png")


if __name__ == "__main__":
    main()
