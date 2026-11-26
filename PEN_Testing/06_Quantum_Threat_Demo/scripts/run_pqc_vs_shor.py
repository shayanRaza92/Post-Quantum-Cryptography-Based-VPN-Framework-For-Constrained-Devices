#!/usr/bin/env python3
"""
Demo 3: why Shor's algorithm does NOT break ML-KEM / ML-DSA (our PQC VPN).

    .venv/bin/python scripts/run_pqc_vs_shor.py

Part A - same quantum circuit, two problems (Qiskit Aer):
  * GROUP problem (like X25519 / Ed25519 / RSA): the public value hides the secret s EXACTLY,
    f(a, b) = a + s*b (mod q). This has a hidden repeating pattern (a period); Shor finds it and
    recovers s.
  * LWE problem (like ML-KEM / ML-DSA, "Learning With Errors"): the same equation, but every value
    has a small random error added: f(a, b) = a + s*b + e (mod q), e in {-1, 0, +1}. The errors
    blur the exact pattern Shor relies on, and the success rate falls sharply. (In this tiny
    one-number toy some signal survives; real ML-KEM hides 512 numbers.)
  The state after the oracle is loaded directly into the simulator (the oracle itself is not built
  from gates), then the real inverse quantum Fourier transforms are applied and measured.
  This is an ILLUSTRATION of why Shor does not apply, not a proof that lattices are hard.

Part B - classical view of the same point: without errors, the secret of a lattice-style system is
  found instantly by linear algebra; with small errors that fails, and brute force grows like q^n.

Part C - the real ML-KEM-512 used in our VPN: its size.
Writes results/pqc_vs_shor.txt and results/fig_pqc_vs_shor.png.
"""
import math
import sys
import time
from pathlib import Path

import numpy as np
from qiskit import QuantumCircuit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qshor import human_bytes, iqft_gate, simulate, statevector_bytes  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "results"
Q = 13            # modulus of the toy problems (prime)
S_SECRET = 5      # the secret both attacks try to find
T = 6             # qubits per exponent register
SHOTS = 2048
RNG = np.random.default_rng(2026)

try:
    from qiskit_aer.library import SetStatevector
except ImportError:
    SetStatevector = None


# ============================================================================ Part A (quantum)
def post_oracle_state(f):
    """(1/M) * sum_{a,b} |a>|b>|f(a,b)>  with a, b in 0..M-1. Qiskit is little-endian."""
    M, m = 2 ** T, math.ceil(math.log2(Q))
    vec = np.zeros(2 ** (2 * T + m), dtype=complex)
    for a in range(M):
        for b in range(M):
            vec[a | (b << T) | (int(f[a, b]) << (2 * T))] = 1.0 / M
    return vec, 2 * T + m


def shor_on(f):
    vec, nq = post_oracle_state(f)
    qc = QuantumCircuit(nq, 2 * T)
    if SetStatevector is not None:
        qc.append(SetStatevector(vec), qc.qubits)
    else:
        qc.initialize(vec, qc.qubits)
    A, B = list(range(T)), list(range(T, 2 * T))
    qc.append(iqft_gate(T), A)
    qc.append(iqft_gate(T), B)
    qc.measure(A + B, list(range(2 * T)))
    counts = simulate(qc, SHOTS)
    M, hits = 2 ** T, 0
    grid = np.zeros((M, M))
    for bits, n in counts.items():
        v = int(bits, 2)
        c, d = v & (M - 1), v >> T
        grid[d, c] += n / SHOTS
        j = round(c * Q / M) % Q
        if j:
            guess = (round(d * Q / M) * pow(j, -1, Q)) % Q
            if guess == S_SECRET:
                hits += n
    return hits / SHOTS, nq, grid


# ============================================================================ Part B (classical)
def solve_mod(Amat, bvec, q):
    """Gaussian elimination mod q (square, invertible system)."""
    n = len(bvec)
    M = np.concatenate([Amat % q, (bvec % q)[:, None]], axis=1).astype(np.int64)
    for col in range(n):
        piv = next((r for r in range(col, n) if M[r, col] % q), None)
        if piv is None:
            return None
        M[[col, piv]] = M[[piv, col]]
        M[col] = (M[col] * pow(int(M[col, col]), -1, q)) % q
        for r in range(n):
            if r != col and M[r, col]:
                M[r] = (M[r] - M[r, col] * M[col]) % q
    return M[:, -1]


def lwe_instance(n, q, noise):
    A = RNG.integers(0, q, size=(n, n))
    while round(np.linalg.det(A)) % q == 0:
        A = RNG.integers(0, q, size=(n, n))
    s = RNG.integers(0, q, size=n)
    e = RNG.integers(-1, 2, size=n) if noise else np.zeros(n, dtype=int)
    return A, s, (A @ s + e) % q


def brute_force_seconds(n, q):
    """Time to try every secret of a tiny LWE instance (2n equations, errors in {-1,0,1})."""
    A = RNG.integers(0, q, size=(2 * n, n))
    s = RNG.integers(0, q, size=n)
    b = (A @ s + RNG.integers(-1, 2, size=2 * n)) % q
    grids = np.stack(np.meshgrid(*[np.arange(q)] * n, indexing="ij"), -1).reshape(-1, n)
    t0 = time.perf_counter()
    r = (b[None, :] - grids @ A.T) % q
    r = np.minimum(r, q - r)
    found = grids[np.all(r <= 1, axis=1)]
    secs = time.perf_counter() - t0
    return secs, any((g == s).all() for g in found)


def main():
    OUT.mkdir(exist_ok=True)
    M = 2 ** T
    a_idx, b_idx = np.meshgrid(np.arange(M), np.arange(M), indexing="ij")
    f_exact = (a_idx + S_SECRET * b_idx) % Q
    f_noisy = (f_exact + RNG.integers(-1, 2, size=f_exact.shape)) % Q

    ok_exact, nq, grid_exact = shor_on(f_exact)
    ok_noisy, _, grid_noisy = shor_on(f_noisy)

    lines = ["Shor's algorithm vs. lattice (LWE) problems - toy illustration", "=" * 62,
             f"Part A: the same Shor circuit ({nq} qubits, state memory {human_bytes(statevector_bytes(nq))}), "
             f"secret s = {S_SECRET}, q = {Q}",
             f"  Group problem  f = a + s*b      (X25519 / Ed25519 / RSA style): "
             f"{100 * ok_exact:5.1f}% of shots give s",
             f"  LWE problem    f = a + s*b + e  (ML-KEM / ML-DSA style)       : "
             f"{100 * ok_noisy:5.1f}% of shots give s   (random guessing: {100 / Q:.1f}%)",
             "  -> With exact algebra the period is there and Shor finds the secret most of the time.",
             "     The small random errors blur that period, so the success rate falls sharply.",
             "     In this tiny toy (ONE secret number, q = 13) some signal still survives. Real ML-KEM-512",
             "     hides 512 numbers mod 3329, and no known quantum algorithm (Shor or any other) can undo",
             "     the errors efficiently: that is why NIST chose it (FIPS 203, Abstract).", ""]

    lines.append("Part B: the same idea without quantum computers (toy LWE, q = 13):")
    A, s, b = lwe_instance(4, Q, noise=False)
    lines.append(f"  no errors : linear algebra finds s = {solve_mod(A, b, Q).tolist()} "
                 f"(true {s.tolist()})  -> instant")
    A, s, b = lwe_instance(4, Q, noise=True)
    got = solve_mod(A, b, Q)
    lines.append(f"  with errors: linear algebra gives {got.tolist()} (true {s.tolist()})  -> "
                 f"{'wrong' if got is None or not (got == s).all() else 'right (lucky)'}")
    lines.append("  brute force (try every secret):")
    for n in range(1, 6):
        secs, ok = brute_force_seconds(n, Q)
        lines.append(f"    n = {n}: {Q ** n:>9,} secrets, {secs * 1000:9.2f} ms, secret found: {ok}")
    lines.append("    every +1 in n multiplies the work by q = 13.")
    lines.append("")

    n_real, q_real = 512, 3329
    tries = n_real * math.log10(q_real)
    lines += ["Part C: the real ML-KEM-512 in our PQC VPN (FIPS 203):",
              f"  secret: {n_real} numbers mod {q_real} (k = 2 polynomials of 256), public key 800 bytes",
              f"  brute force: about 10^{tries:,.0f} secrets; even Grover's quantum search only halves the",
              f"  exponent (about 10^{tries / 2:,.0f}). The best known attacks (lattice reduction) are far",
              "  faster than brute force but are still out of reach; there is no period for Shor to find.",
              "  NIST: ML-KEM and ML-DSA are believed secure even against adversaries with a quantum",
              "  computer (FIPS 203 and FIPS 204, Abstract)."]
    text = "\n".join(lines)
    print(text)
    (OUT / "pqc_vs_shor.txt").write_text(text + "\n")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(7.4, 3.4))
    for ax, grid, title in ((axes[0], grid_exact, f"Group problem (classical crypto)\nShor finds s: {100 * ok_exact:.0f}% of shots"),
                            (axes[1], grid_noisy, f"LWE problem (ML-KEM / ML-DSA)\nShor finds s: {100 * ok_noisy:.0f}% (guessing: {100 / Q:.0f}%)")):
        ax.imshow(grid, origin="lower", cmap="Blues", interpolation="nearest", vmax=grid_exact.max())
        ax.set_title(title, fontsize=8)
        ax.set_xlabel("register a (measured)", fontsize=8)
        ax.set_ylabel("register b (measured)", fontsize=8)
        ax.tick_params(labelsize=7)
    fig.suptitle("Same Shor circuit: sharp pattern with exact algebra, blurred pattern with LWE errors", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "fig_pqc_vs_shor.png", dpi=200)
    print("\nSaved results/pqc_vs_shor.txt and results/fig_pqc_vs_shor.png")


if __name__ == "__main__":
    main()
