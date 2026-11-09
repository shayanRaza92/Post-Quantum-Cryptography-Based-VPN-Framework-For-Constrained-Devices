#!/usr/bin/env python3
"""
Fair classical vs. post-quantum comparison of the gateway's crypto cost per handshake (test L1).

Laptop CPU speed changes all the time (power profile, battery, temperature), so comparing a
classical run with a PQC run made a minute later can be off by 2x. This script ALTERNATES
the two (classical, PQC, classical, PQC, ...) for several rounds, so both see the same
conditions, then reports the median over the rounds and the PQC / classical ratio.

  python3 compare_gateway_crypto.py [--rounds 6] [--runs 500]

For the most stable numbers: plug the laptop in and set the power profile to Performance.
"""
import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

FYP = Path(__file__).resolve().parents[3]
SCRIPTS = {
    "classical": FYP / "Non_PQC_VPN" / "benchmarking" / "system_benchmark" / "gateway_benchmark.py",
    "pqc": FYP / "PQC_VPN" / "benchmarking" / "system_benchmark" / "gateway_benchmark.py",
}
# Same role in both VPNs -> metric name in each
ROLES = [
    ("Key exchange",                 "x25519_keygen_plus_shared_secret", "ml_kem_512_encapsulate"),
    ("Sign gateway transcript",      "ed25519_sign_server_transcript",   "ml_dsa_44_sign_server_transcript"),
    ("Verify device signature",      "ed25519_verify_client_signature",  "ml_dsa_44_verify_client_signature"),
    ("HKDF session keys",            "hkdf_sha256_session_keys",         "hkdf_sha256_session_keys"),
    ("Two HMAC confirmation tags",   "hmac_sha256_two_confirmation_tags", "hmac_sha256_two_confirmation_tags"),
    ("TOTAL gateway crypto",         "total_gateway_crypto_per_handshake", "total_gateway_crypto_per_handshake"),
]


def run_l1(which, runs):
    out = subprocess.run([sys.executable, str(SCRIPTS[which]), "--l1-json", "--crypto-runs", str(runs)],
                         capture_output=True, text=True, check=True)
    data = json.loads(out.stdout.strip().splitlines()[-1])
    return {r["metric"]: r for r in data["results"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--runs", type=int, default=500, help="timed runs per operation in each round")
    args = ap.parse_args()

    medians = {"classical": {}, "pqc": {}}     # metric -> [per-round median]
    p95s = {"classical": {}, "pqc": {}}
    for rnd in range(args.rounds):
        for which in ("classical", "pqc") if rnd % 2 == 0 else ("pqc", "classical"):   # Alternate the order too
            for metric, row in run_l1(which, args.runs).items():
                medians[which].setdefault(metric, []).append(float(row["median"]))
                p95s[which].setdefault(metric, []).append(float(row["p95"]))
        print(f"  round {rnd + 1}/{args.rounds}: classical total {medians['classical']['total_gateway_crypto_per_handshake'][-1]:.3f} ms, "
              f"PQC total {medians['pqc']['total_gateway_crypto_per_handshake'][-1]:.3f} ms")

    print(f"\nGateway crypto per handshake: median over {args.rounds} alternating rounds "
          f"(each round = median of {args.runs} timed runs)\n")
    print(f"| Operation | Classical (Ed25519 + X25519) | Post-quantum (ML-DSA-44 + ML-KEM-512) | PQC / classical |")
    print("|---|---|---|---|")
    for label, c_metric, p_metric in ROLES:
        c = statistics.median(medians["classical"][c_metric])
        p = statistics.median(medians["pqc"][p_metric])
        cp = statistics.median(p95s["classical"][c_metric])
        pp = statistics.median(p95s["pqc"][p_metric])
        print(f"| {label} | {c:.3f} ms (p95 {cp:.3f}) | {p:.3f} ms (p95 {pp:.3f}) | {p / c:.2f}x |")
    spread = lambda xs: (max(xs) - min(xs)) / statistics.median(xs) * 100       # noqa: E731
    print(f"\nRound-to-round spread of the total: classical {spread(medians['classical']['total_gateway_crypto_per_handshake']):.0f}%, "
          f"PQC {spread(medians['pqc']['total_gateway_crypto_per_handshake']):.0f}%")


if __name__ == "__main__":
    main()
