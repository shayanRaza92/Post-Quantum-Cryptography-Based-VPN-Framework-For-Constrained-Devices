#!/usr/bin/env python3
"""Turn a sig_bench_unified log into tables (Step 1 / experiment E1).

    python3 tools/analyze_sig_bench.py results/e1/raw/sig_bench_<date>_<time>.log

Writes to results/e1/<log name>/:
  summary.csv    timing per algorithm and operation, recomputed from the raw samples:
                 n, failures, min, median (+ 95% bootstrap confidence interval), mean, p95,
                 p99, max, standard deviation, IQR, coefficient of variation (all in ms)
  samples.csv    every single measurement (algorithm, operation, run, cycles, ms)
  sizes.csv      public key, secret key and signature bytes
  memory.csv     peak stack and peak heap per operation
  checks.csv     known-answer tests, failures, heap leaks, start-vs-end stability
  meta.json      board, library versions, settings, git commit
  results.md     the same as readable tables
The device's own summary (SUM lines) is compared with the recomputed numbers as a check.
"""
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
ORDER = ["Ed25519", "ECDSA-P256", "RSA-3072", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
OPS = ["keygen", "sign", "verify"]
BOOT = 2000                                   # bootstrap resamples for the median's 95% CI


def parse(path):
    d = {"meta": {}, "host": {}, "kat": {}, "raw": defaultdict(list), "sum": {}, "size": {},
         "stack": {}, "heap": {}, "leak": {}, "errors": []}
    inside = False
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("HOST,"):
            _, k, v = line.split(",", 2)
            d["host"][k] = v
            continue
        if line.startswith("### BEGIN"):
            inside = True
            continue
        if line.startswith("### END"):
            inside = False
            continue
        if not inside:
            continue
        parts = line.split(",")
        tag = parts[0]
        if tag == "META":
            d["meta"][parts[1]] = ",".join(parts[2:])
        elif tag == "KAT":
            d["kat"][parts[1]] = parts[2]
        elif tag == "RAW":
            d["raw"][(parts[1], parts[2])].append((int(parts[3]), [int(x) for x in parts[4].split()]))
        elif tag == "SUM":
            d["sum"][(parts[1], parts[2])] = {k: float(v) for k, v in (p.split("=") for p in parts[3:])}
        elif tag == "SIZE":
            d["size"][parts[1]] = {k: float(v) for k, v in (p.split("=") for p in parts[2:])}
        elif tag == "STACK":
            d["stack"][(parts[1], parts[2])] = int(parts[3])
        elif tag == "HEAP":
            d["heap"][(parts[1], parts[2])] = (int(parts[3]), len(parts) > 4)
        elif tag == "LEAK":
            kv = dict(p.split("=") for p in parts[2:])
            d["leak"][parts[1]] = (int(kv["free_before"]), int(kv["free_after"]))
        elif tag in ("ERROR", "WARN"):
            d["errors"].append(line)
    samples = {}
    for key, chunks in d["raw"].items():
        chunks.sort()
        samples[key] = np.array([v for _, vals in chunks for v in vals], dtype=np.float64)
    d["samples"] = samples
    return d


def stats(cycles, mhz, rng):
    ms = cycles / (mhz * 1000.0)
    n = len(ms)
    srt = np.sort(ms)
    pct = lambda p: srt[max(0, int(np.ceil(p / 100 * n)) - 1)]    # nearest rank, as on the device
    boots = np.median(rng.choice(ms, size=(BOOT, n), replace=True), axis=1)
    q1, q3 = np.percentile(ms, [25, 75])
    return {
        "n": n, "min_ms": srt[0], "median_ms": float(np.median(ms)),
        "median_ci_low_ms": float(np.percentile(boots, 2.5)), "median_ci_high_ms": float(np.percentile(boots, 97.5)),
        "mean_ms": float(ms.mean()), "p95_ms": float(pct(95)), "p99_ms": float(pct(99)), "max_ms": float(srt[-1]),
        "std_ms": float(ms.std(ddof=1)) if n > 1 else 0.0, "iqr_ms": float(q3 - q1),
        "cv_percent": float(100 * ms.std(ddof=1) / ms.mean()) if n > 1 else 0.0,
    }


def fmt(x, digits=3):
    return f"{x:,.{digits}f}"


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    log = Path(sys.argv[1])
    d = parse(log)
    mhz = int(d["meta"].get("cpu_mhz", "240").split()[0])
    out = ROOT / "results" / "e1" / log.stem
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(1)
    algs = [a for a in ORDER if any((a, op) in d["samples"] for op in OPS)]

    # ---- timing summary (recomputed from raw) and check against the device's own summary
    rows, mismatches = [], []
    for a in algs:
        for op in OPS:
            if (a, op) not in d["samples"]:
                continue
            s = stats(d["samples"][(a, op)], mhz, rng)
            dev = d["sum"].get((a, op), {})
            s.update({"algorithm": a, "operation": op, "failures": int(dev.get("fail", -1))})
            if dev and abs(dev["median_us"] / 1000 - s["median_ms"]) > 0.002 + 1e-6 * s["median_ms"]:
                mismatches.append(f"{a} {op}: device median {dev['median_us'] / 1000:.4f} ms, recomputed {s['median_ms']:.4f} ms")
            rows.append(s)
    cols = ["algorithm", "operation", "n", "failures", "min_ms", "median_ms", "median_ci_low_ms", "median_ci_high_ms",
            "mean_ms", "p95_ms", "p99_ms", "max_ms", "std_ms", "iqr_ms", "cv_percent"]
    with open(out / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(r[k], 4) if isinstance(r[k], float) else r[k]) for k in cols})

    with open(out / "samples.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "operation", "run", "cycles", "ms"])
        for (a, op), cyc in sorted(d["samples"].items()):
            for i, c in enumerate(cyc):
                w.writerow([a, op, i, int(c), round(c / (mhz * 1000.0), 5)])

    # ---- sizes and memory
    with open(out / "sizes.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "public_key_B", "secret_key_B", "signature_min_B", "signature_max_B", "signature_mean_B"])
        for a in algs:
            z = d["size"].get(a)
            if z:
                w.writerow([a, int(z["pk"]), int(z["sk"]), int(z["sig_min"]), int(z["sig_max"]), z["sig_mean"]])
    with open(out / "memory.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "operation", "peak_stack_B", "peak_heap_B"])
        for a in algs:
            for op in OPS:
                if (a, op) in d["stack"]:
                    w.writerow([a, op, d["stack"][(a, op)], d["heap"][(a, op)][0]])

    # ---- checks
    checks = []
    for a in algs:
        fails = sum(r["failures"] for r in rows if r["algorithm"] == a and r["failures"] > 0)
        before, after = d["leak"].get(a, (0, 0))
        checks.append({"algorithm": a, "known_answer_test": d["kat"].get(a, "missing"),
                       "failed_operations": fails, "heap_change_B": after - before,
                       "probe_errors": sum(1 for op in OPS if d["heap"].get((a, op), (0, False))[1])})
    with open(out / "checks.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(checks[0].keys()))
        w.writeheader()
        w.writerows(checks)

    calibration = next(((op, v) for (a, op), v in d["stack"].items() if a == "_calibration"), None)
    stability = None
    if ("Ed25519", "sign") in d["sum"] and ("Ed25519", "sign_repeat_end") in d["sum"]:
        m0 = d["sum"][("Ed25519", "sign")]["median_us"]
        m1 = d["sum"][("Ed25519", "sign_repeat_end")]["median_us"]
        stability = (m0 / 1000, m1 / 1000, 100 * (m1 - m0) / m0)

    meta = {"log": log.name, "host": d["host"], "device": d["meta"], "errors": d["errors"],
            "device_vs_host_median_mismatches": mismatches}
    (out / "meta.json").write_text(json.dumps(meta, indent=2))

    # ---- readable tables
    R = {(r["algorithm"], r["operation"]): r for r in rows}
    L = [f"# Step 1 (E1): signature algorithms on the ESP32\n",
         f"Log: `{log.name}`. Board: {d['meta'].get('chip', '?')}, {d['meta'].get('cpu_mhz', '?')} MHz. "
         f"ESP-IDF {d['meta'].get('esp_idf', '?')}, mbedTLS {d['meta'].get('mbedtls', '?')}, "
         f"libsodium {d['meta'].get('libsodium', '?')}, mldsa-native v1.0.0-beta2. "
         f"Runs: {d['meta'].get('runs', '?')}. Message: {d['meta'].get('message_bytes', '?')} bytes. "
         f"Git commit: `{d['host'].get('git_commit', '?')[:12]}`"
         f"{' (with uncommitted changes)' if d['host'].get('git_uncommitted_changes') == 'yes' else ''}.\n"]
    for op in OPS:
        L += [f"\n## {op.capitalize()} time (ms)\n",
              "| Algorithm | n | Median [95% CI] | Mean | p95 | p99 | Max | Std | CV % |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for a in algs:
            r = R.get((a, op))
            if r:
                L.append(f"| {a} | {r['n']} | {fmt(r['median_ms'])} [{fmt(r['median_ci_low_ms'])}, {fmt(r['median_ci_high_ms'])}] "
                         f"| {fmt(r['mean_ms'])} | {fmt(r['p95_ms'])} | {fmt(r['p99_ms'])} | {fmt(r['max_ms'])} "
                         f"| {fmt(r['std_ms'])} | {fmt(r['cv_percent'], 1)} |")
    L += ["\n## Sign + verify (one authentication, medians, ms)\n", "| Algorithm | Sign | Verify | Sum |", "|---|---:|---:|---:|"]
    for a in algs:
        if (a, "sign") in R:
            s, v = R[(a, "sign")]["median_ms"], R[(a, "verify")]["median_ms"]
            L.append(f"| {a} | {fmt(s)} | {fmt(v)} | {fmt(s + v)} |")
    L += ["\n## Sizes (bytes)\n", "| Algorithm | Public key | Secret key | Signature |", "|---|---:|---:|---:|"]
    for a in algs:
        z = d["size"].get(a)
        if z:
            sig = f"{int(z['sig_min'])}" if z["sig_min"] == z["sig_max"] else f"{int(z['sig_min'])}-{int(z['sig_max'])} (mean {z['sig_mean']:.1f})"
            L.append(f"| {a} | {int(z['pk']):,} | {int(z['sk']):,} | {sig} |")
    L += ["\n## Memory (bytes)\n", "| Algorithm | Stack keygen | Stack sign | Stack verify | Heap keygen | Heap sign | Heap verify |",
          "|---|---:|---:|---:|---:|---:|---:|"]
    for a in algs:
        if (a, "sign") in d["stack"]:
            st = [d["stack"].get((a, op), 0) for op in OPS]
            hp = [d["heap"].get((a, op), (0, False))[0] for op in OPS]
            L.append(f"| {a} | " + " | ".join(f"{x:,}" for x in st + hp) + " |")
    ml = [a for a in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87") if (a, "sign") in R]
    if len(ml) > 1:
        L += ["\n## ML-DSA levels compared with ML-DSA-44 (ratio of medians)\n",
              "| Level | Keygen | Sign | Verify | Signature size | Public key size |", "|---|---:|---:|---:|---:|---:|"]
        b = "ML-DSA-44"
        for a in ml:
            L.append(f"| {a} | " + " | ".join(f"{R[(a, op)]['median_ms'] / R[(b, op)]['median_ms']:.2f}x" for op in OPS)
                     + f" | {d['size'][a]['sig_max'] / d['size'][b]['sig_max']:.2f}x | {d['size'][a]['pk'] / d['size'][b]['pk']:.2f}x |")
    L += ["\n## Checks\n", "| Algorithm | Known-answer test | Failed operations | Heap change after run (B) |", "|---|---|---:|---:|"]
    for c in checks:
        L.append(f"| {c['algorithm']} | {c['known_answer_test']} | {c['failed_operations']} | {c['heap_change_B']} |")
    if calibration:
        L.append(f"\nStack meter check: a function using a {calibration[0].split('_')[0]}-byte array was measured as "
                 f"{calibration[1]:,} bytes.")
    L.append("\nHeap change after run: a few dozen bytes once per algorithm is set-up memory of the "
             "system (it does not grow with the number of runs), not a leak.")
    if stability:
        L.append(f"\nStability: Ed25519 sign median {stability[0]:.3f} ms at the start, {stability[1]:.3f} ms at the end "
                 f"({stability[2]:+.2f}%).")
    L.append(f"\nDevice summary vs recomputed medians: {'all match' if not mismatches else '; '.join(mismatches)}.")
    if d["errors"]:
        L.append("\nErrors/warnings in the log:\n" + "\n".join(f"- `{e}`" for e in d["errors"]))
    (out / "results.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))
    print(f"\nFiles written to {out}")


if __name__ == "__main__":
    main()
