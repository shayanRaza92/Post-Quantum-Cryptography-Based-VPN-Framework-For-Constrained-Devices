"""
Shared helpers for the Shor's-algorithm demos (Qiskit + Qiskit Aer statevector simulator).

Everything here is a SIMULATION on a normal computer, at toy size. A simulator must store the whole
quantum state: 2^n complex numbers for n qubits, 16 bytes each (complex128). That is why only small
numbers can be attacked: memory doubles with every qubit.
"""
from __future__ import annotations

import math
from fractions import Fraction

import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit.circuit.library import UnitaryGate
from qiskit_aer import AerSimulator

try:                                   # Qiskit >= 1.2
    from qiskit.circuit.library import QFTGate

    def iqft_gate(t: int):
        return QFTGate(t).inverse()
except ImportError:                    # older Qiskit
    from qiskit.circuit.library import QFT

    def iqft_gate(t: int):
        return QFT(t, inverse=True).to_gate()

BYTES_PER_AMPLITUDE = 16               # complex128, Aer's default precision


def statevector_bytes(n_qubits: int) -> int:
    """Memory needed just to hold the quantum state of n qubits in a simulator (exact integer, so it
    also works for thousands of qubits)."""
    return BYTES_PER_AMPLITUDE * 2 ** n_qubits


def human_bytes(b: float) -> str:
    if b < 1024 ** 4:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if b < 1024:
                return f"{b:,.0f} {unit}" if unit == "B" else f"{b:,.1f} {unit}"
            b /= 1024
    exp = math.log10(b)
    return f"10^{exp:,.0f} bytes"


def controlled_permutation(perm: list[int], m: int) -> UnitaryGate:
    """Gate on (m work qubits + 1 control qubit, control listed LAST): if control = 1, the work register
    value x becomes perm[x]; if control = 0 nothing happens. `perm` must be a permutation of 0..2^m-1.
    Qiskit is little-endian: matrix index = work_value + control * 2^m."""
    dim = 2 ** m
    assert sorted(perm) == list(range(dim)), "not a permutation"
    u = np.zeros((2 * dim, 2 * dim), dtype=complex)
    for x in range(dim):
        u[x, x] = 1.0                      # control = 0: identity
        u[dim + perm[x], dim + x] = 1.0    # control = 1: x -> perm[x]
    return UnitaryGate(u)


def simulate(qc: QuantumCircuit, shots: int, seed: int = 1234) -> dict[str, int]:
    """Runs a circuit on the Aer statevector simulator and returns the measurement counts."""
    sim = AerSimulator(method="statevector", seed_simulator=seed)
    tqc = transpile(qc, sim, optimization_level=0, seed_transpiler=seed)
    return sim.run(tqc, shots=shots).result().get_counts()


def continued_fraction_denominator(y: int, t: int, limit: int) -> int:
    """Best fraction s/r close to y / 2^t with r <= limit; returns r."""
    return Fraction(y, 2 ** t).limit_denominator(limit).denominator


# ---------------------------------------------------------------- tiny elliptic curve (toy X25519)
class ToyCurve:
    """y^2 = x^3 + a x + b over F_p, with a prime number of points r. The SAME kind of math as the
    curve behind X25519 and Ed25519 (Curve25519), only with p = 13 instead of p = 2^255 - 19."""

    INF = None

    def __init__(self, p: int, a: int, b: int):
        self.p, self.a, self.b = p, a, b
        self.points = [self.INF] + [(x, y) for x in range(p) for y in range(p)
                                    if (y * y - (x ** 3 + a * x + b)) % p == 0]
        self.order = len(self.points)

    def add(self, P, Q):
        p = self.p
        if P is None:
            return Q
        if Q is None:
            return P
        (x1, y1), (x2, y2) = P, Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    def mul(self, k: int, P):
        R = None
        k %= self.order
        while k:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R

    # A point fits in (x_bits + 1) qubits: x coordinate, plus the parity of y. x = p means "infinity".
    @property
    def x_bits(self) -> int:
        return math.ceil(math.log2(self.p + 1))

    @property
    def enc_bits(self) -> int:
        return self.x_bits + 1

    def encode(self, P) -> int:
        if P is None:
            return self.p
        x, y = P
        return x | ((y & 1) << self.x_bits)

    def decode(self, v: int):
        x, par = v & ((1 << self.x_bits) - 1), v >> self.x_bits
        if x == self.p and par == 0:
            return None
        for P in self.points[1:]:
            if P[0] == x and (P[1] & 1) == par:
                return P
        raise ValueError("not a point")

    def add_permutation(self, T) -> list[int]:
        """Permutation of all (x_bits + 1)-bit values: valid point encodings P -> P + T, others unchanged."""
        size = 2 ** self.enc_bits
        perm = list(range(size))
        for P in self.points:
            perm[self.encode(P)] = self.encode(self.add(P, T))
        return perm

    @staticmethod
    def find(p: int, min_order: int = 11):
        """A curve over F_p whose number of points is prime (largest such order found)."""
        best = None
        for a in range(p):
            for b in range(p):
                if (4 * a ** 3 + 27 * b * b) % p == 0:
                    continue
                c = ToyCurve(p, a, b)
                n = c.order
                if n >= min_order and all(n % d for d in range(2, int(n ** 0.5) + 1)):
                    if best is None or n > best.order:
                        best = c
        return best


def shor_ecdlp(curve: ToyCurve, G, Q, t: int, shots: int, seed: int = 7):
    """Shor's algorithm for the elliptic-curve discrete log: finds k with Q = k*G.
    Registers: a (t qubits), b (t qubits), point register (enc_bits qubits).
    Oracle: |a>|b>|O> -> |a>|b>|a*G + b*Q>, built from controlled 'add a fixed point' gates.
    Returns (k or None, number of qubits, counts, success fraction over all shots)."""
    m = curve.enc_bits
    n_qubits = 2 * t + m
    qc = QuantumCircuit(n_qubits, 2 * t)
    A = list(range(0, t))
    B = list(range(t, 2 * t))
    W = list(range(2 * t, 2 * t + m))
    qc.h(A + B)
    start = curve.encode(None)                 # point register starts at "infinity" (the zero point)
    for i in range(m):
        if (start >> i) & 1:
            qc.x(W[i])
    for j in range(t):
        qc.append(controlled_permutation(curve.add_permutation(curve.mul(2 ** j, G)), m), W + [A[j]])
        qc.append(controlled_permutation(curve.add_permutation(curve.mul(2 ** j, Q)), m), W + [B[j]])
    qc.append(iqft_gate(t), A)
    qc.append(iqft_gate(t), B)
    qc.measure(A + B, list(range(2 * t)))
    counts = simulate(qc, shots, seed)

    r, M = curve.order, 2 ** t
    found, good = None, 0
    for bits, n in counts.items():
        v = int(bits, 2)
        c, d = v & (M - 1), v >> t             # c from register a, d from register b
        j = round(c * r / M) % r
        if j == 0:
            continue
        dj = round(d * r / M) % r
        for k in ((dj * pow(j, -1, r)) % r, (-dj * pow(j, -1, r)) % r):
            if curve.mul(k, G) == Q:           # an attacker can check a guess with the public key
                good += n
                found = k
                break
    return found, n_qubits, counts, good / shots
