#!/usr/bin/env python3
"""
Differential test: ML-KEM-512 and ML-DSA-44 as used by this VPN (mlkem-native / mldsa-native,
laptop build) against INDEPENDENT reference implementations of FIPS 203 / FIPS 204:
kyber-py and dilithium-py (pure Python, written separately from the C libraries).

For every trial, fresh random inputs go into both implementations and the outputs must be
identical byte for byte. This complements the single-vector known-answer tests (B0 / L0):
a bug that only shows up for some inputs is very likely to be caught across hundreds of trials.

  pip install kyber-py dilithium-py          (once; any Python environment)
  python3 reference_cross_check.py [--trials 200]

Checked per trial:
  ML-KEM-512  keygen (ek, dk) from random d, z | encaps (ct, K) from random m | decaps |
              implicit rejection: decaps of a randomly corrupted ciphertext
  ML-DSA-44   keygen (pk, sk) from random xi | deterministic signature (rnd = 0) over a random
              message (0-256 B) and random context (0-32 B) | each side verifies the other's
              signatures (including the VPN's randomized signing) | corrupted signature rejected
"""
import argparse
import ctypes
import os
import random
import sys
import time
from pathlib import Path

try:
    from kyber_py.ml_kem import ML_KEM_512
    from dilithium_py.ml_dsa import ML_DSA_44
except ImportError:
    sys.exit("This test needs the reference implementations:  pip install kyber-py dilithium-py")

LIB_DIR = Path(__file__).resolve().parent.parent.parent / "laptop_server"
try:
    KEM = ctypes.CDLL(str(LIB_DIR / "libmlkem512.so"))
    DSA = ctypes.CDLL(str(LIB_DIR / "libmldsa44.so"))
except OSError:
    sys.exit(f"Build the native libraries first: {LIB_DIR}/build_native_libs.sh")

buf = ctypes.create_string_buffer
size_t = ctypes.c_size_t


def ours_kem_keygen(d, z):
    ek, dk = buf(800), buf(1632)
    assert KEM.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand(ek, dk, d + z) == 0
    return ek.raw, dk.raw


def ours_kem_encaps(ek, m):
    ct, k = buf(768), buf(32)
    assert KEM.PQCP_MLKEM_NATIVE_MLKEM512_enc_derand(ct, k, ek, m) == 0
    return k.raw, ct.raw


def ours_kem_decaps(dk, ct):
    k = buf(32)
    assert KEM.PQCP_MLKEM_NATIVE_MLKEM512_dec(k, ct, dk) == 0
    return k.raw


def ours_dsa_keygen(xi):
    pk, sk = buf(1312), buf(2560)
    assert DSA.PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(pk, sk, xi) == 0
    return pk.raw, sk.raw


def ours_dsa_sign_deterministic(sk, msg, ctx):
    sig, n = buf(2420), size_t()
    pre = bytes([0, len(ctx)]) + ctx                      # FIPS 204 pure ML-DSA domain separation
    rc = DSA.PQCP_MLDSA_NATIVE_MLDSA44_signature_internal(sig, ctypes.byref(n), msg, size_t(len(msg)), pre,
                                                          size_t(len(pre)), bytes(32), sk, ctypes.c_int(0))
    assert rc == 0
    return sig.raw[:n.value]


def ours_dsa_sign_hedged(sk, msg, ctx):                  # What the VPN actually uses
    sig, n = buf(2420), size_t()
    assert DSA.PQCP_MLDSA_NATIVE_MLDSA44_signature(sig, ctypes.byref(n), msg, size_t(len(msg)), ctx,
                                                   size_t(len(ctx)), sk) == 0
    return sig.raw[:n.value]


def ours_dsa_verify(pk, msg, sig, ctx):
    return DSA.PQCP_MLDSA_NATIVE_MLDSA44_verify(sig, size_t(len(sig)), msg, size_t(len(msg)), ctx,
                                                size_t(len(ctx)), pk) == 0


def corrupt(data, rng):
    b = bytearray(data)
    b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
    return bytes(b)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--seed", type=int, default=None, help="seed for the random inputs (to repeat a run)")
    args = ap.parse_args()
    seed = args.seed if args.seed is not None else int.from_bytes(os.urandom(4), "big")
    rng = random.Random(seed)
    rand = lambda n: bytes(rng.getrandbits(8) for _ in range(n))     # noqa: E731
    checks = {k: 0 for k in ("kem_keygen", "kem_encaps", "kem_decaps", "kem_implicit_rejection", "dsa_keygen",
                             "dsa_deterministic_sign", "dsa_ours_verifies_reference", "dsa_reference_verifies_ours",
                             "dsa_corrupted_sig_rejected")}
    failures = []
    t0 = time.time()
    for trial in range(args.trials):
        d, z, m, xi = rand(32), rand(32), rand(32), rand(32)
        msg, ctx = rand(rng.randrange(0, 257)), rand(rng.randrange(0, 33))
        # ---------------- ML-KEM-512 ----------------
        ek_r, dk_r = ML_KEM_512._keygen_internal(d, z)
        ek_o, dk_o = ours_kem_keygen(d, z)
        k_r, ct_r = ML_KEM_512._encaps_internal(ek_r, m)
        k_o, ct_o = ours_kem_encaps(ek_o, m)
        bad_ct = corrupt(ct_r, rng)
        results = {
            "kem_keygen": ek_r == ek_o and dk_r == dk_o,
            "kem_encaps": k_r == k_o and ct_r == ct_o,
            "kem_decaps": ours_kem_decaps(dk_o, ct_r) == k_r,
            "kem_implicit_rejection": ours_kem_decaps(dk_o, bad_ct) == ML_KEM_512.decaps(dk_r, bad_ct),
        }
        # ---------------- ML-DSA-44 ----------------
        pk_r, sk_r = ML_DSA_44._keygen_internal(xi)
        pk_o, sk_o = ours_dsa_keygen(xi)
        sig_r = ML_DSA_44.sign(sk_r, msg, ctx=ctx, deterministic=True)
        sig_o = ours_dsa_sign_deterministic(sk_o, msg, ctx)
        sig_h = ours_dsa_sign_hedged(sk_o, msg, ctx)
        bad_sig = corrupt(sig_r, rng)
        results.update({
            "dsa_keygen": pk_r == pk_o and sk_r == sk_o,
            "dsa_deterministic_sign": sig_r == sig_o,
            "dsa_ours_verifies_reference": ours_dsa_verify(pk_o, msg, sig_r, ctx),
            "dsa_reference_verifies_ours": ML_DSA_44.verify(pk_r, msg, sig_h, ctx=ctx),
            "dsa_corrupted_sig_rejected": not ours_dsa_verify(pk_o, msg, bad_sig, ctx)
                                          and not ML_DSA_44.verify(pk_r, msg, bad_sig, ctx=ctx),
        })
        for name, ok in results.items():
            checks[name] += ok
            if not ok:
                failures.append((trial, name))
        if (trial + 1) % 25 == 0:
            print(f"  ... {trial + 1}/{args.trials} trials, {len(failures)} mismatches so far")

    print(f"\nML-KEM-512 / ML-DSA-44 differential test: {args.trials} random trials (seed {seed}), {time.time() - t0:.0f} s")
    for name, passed in checks.items():
        print(f"  {name:<32} {passed:>4} / {args.trials}  {'PASS' if passed == args.trials else 'FAIL'}")
    total = sum(checks.values())
    print(f"  {'TOTAL':<32} {total:>4} / {args.trials * len(checks)}")
    if failures:
        print("First mismatches:", failures[:10])
        sys.exit(1)


if __name__ == "__main__":
    main()
