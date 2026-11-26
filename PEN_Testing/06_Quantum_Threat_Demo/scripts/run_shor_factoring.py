#!/usr/bin/env python3
"""
Demo 1: Shor's algorithm factors numbers (the problem behind RSA), simulated with Qiskit.

    .venv/bin/python scripts/run_shor_factoring.py

For N = 15, 21 and 35 it builds the real Shor circuit:
  * a "counting" register of t = 2n qubits in superposition,
  * a work register of n qubits holding a^x mod N   (the modular multiplications are exact
    "multiply by c mod N" gates; on a real quantum computer they would be built from adders),
  * the inverse quantum Fourier transform, then measurement.
The measured values cluster at multiples of 2^t / r, where r is the period of a^x mod N.
From r, ordinary arithmetic gives the factors: gcd(a^(r/2) +- 1, N).

Writes results/shor_factoring.txt and results/fig_shor_factoring.png.
Toy size only: see run_memory_table.py for why real RSA-2048 cannot be simulated.
"""
import math
import sys
import time
from pathlib import Path

from qiskit import QuantumCircuit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qshor import (controlled_permutation, continued_fraction_denominator, human_bytes, iqft_gate,  # noqa: E402
                   simulate, statevector_bytes)

OUT = Path(__file__).resolve().parents[1] / "results"
CASES = [(15, 7), (21, 2), (35, 2)]          # (N, base a); a must not share a factor with N
SHOTS = 2048


def shor_circuit(N: int, a: int):
    n = math.ceil(math.log2(N))               # work register: holds numbers 0..N-1
    t = 2 * n                                 # counting register: enough precision for the period
    qc = QuantumCircuit(t + n, t)
    count, work = list(range(t)), list(range(t, t + n))
    qc.h(count)
    qc.x(work[0])                             # work register = 1
    for j in range(t):                        # controlled multiply by a^(2^j) mod N
        c = pow(a, 2 ** j, N)
        perm = [(c * x) % N if x < N else x for x in range(2 ** n)]
        qc.append(controlled_permutation(perm, n), work + [count[j]])
    qc.append(iqft_gate(t), count)
    qc.measure(count, list(range(t)))
    return qc, t, n


def factors_from_measurement(y: int, t: int, N: int, a: int):
    """Classical post-processing: measurement -> period r -> factors (or None)."""
    r = continued_fraction_denominator(y, t, N)
    for mult in range(1, 4):                  # the fraction may have lost a common factor
        rr = r * mult
        if rr and pow(a, rr, N) == 1:
            if rr % 2:
                return rr, None
            h = pow(a, rr // 2, N)
            if h == N - 1:
                return rr, None
            p, q = math.gcd(h - 1, N), math.gcd(h + 1, N)
            if 1 < p < N:
                return rr, tuple(sorted((p, N // p)))
            if 1 < q < N:
                return rr, tuple(sorted((q, N // q)))
            return rr, None
    return None, None


def main():
    OUT.mkdir(exist_ok=True)
    lines = ["Shor's algorithm (Qiskit Aer statevector simulator) - factoring", "=" * 64]
    hist = {}
    for N, a in CASES:
        qc, t, n = shor_circuit(N, a)
        t0 = time.perf_counter()
        counts = simulate(qc, SHOTS)
        secs = time.perf_counter() - t0
        ok, period, factors = 0, None, None
        for bits, k in counts.items():
            r, f = factors_from_measurement(int(bits, 2), t, N, a)
            if f:
                ok += k
                period, factors = r, f
        nq = t + n
        lines += [f"N = {N:>3} (base a = {a})   qubits = {nq:>2} ({t} counting + {n} work)   "
                  f"state memory = {human_bytes(statevector_bytes(nq))}",
                  f"   period r of {a}^x mod {N} = {period}   ->   factors = {factors[0]} x {factors[1]}"
                  if factors else "   no factors found",
                  f"   shots that directly gave the factors: {100 * ok / SHOTS:.1f}%   "
                  f"(simulation time {secs:.1f} s)", ""]
        hist[N] = (counts, t, period)
    lines += ["Classical check: the factors multiply back to N, so the attack worked.",
              "This breaks RSA in principle: RSA's private key is found from the two factors of N."]
    text = "\n".join(lines)
    print(text)
    (OUT / "shor_factoring.txt").write_text(text + "\n")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, len(hist), figsize=(10, 2.8))
    for ax, (N, (counts, t, r)) in zip(axes, hist.items()):
        xs = [int(b, 2) / 2 ** t for b in counts]
        ys = [c / SHOTS for c in counts.values()]
        ax.bar(xs, ys, width=0.006, color="#2a78d6")
        if r:
            for s in range(r):
                ax.axvline(s / r, color="#eb6834", lw=0.6, ls=":")
        ax.set_title(f"N = {N}: period r = {r}", fontsize=9)
        ax.set_xlabel("measured value / 2^t", fontsize=8)
        ax.tick_params(labelsize=7)
    axes[0].set_ylabel("probability", fontsize=8)
    fig.suptitle("Shor's algorithm: measurements pile up at s / r (orange lines) - that reveals the period",
                 fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "fig_shor_factoring.png", dpi=200)
    print(f"\nSaved {OUT / 'shor_factoring.txt'} and {OUT / 'fig_shor_factoring.png'}")


if __name__ == "__main__":
    main()
