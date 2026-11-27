# Gateway crypto per handshake: classical vs. post-quantum (alternating rounds)

Made with `compare_gateway_crypto.py --rounds 6 --runs 500` on 27 Nov 2026 (code with SA binding), on the
HP Victus 15, plugged in, Performance power mode. The earlier run (10 Nov 2026) is in
`archive_before_SA_binding/gateway_crypto_comparison.md` and gave the same results.

```
  round 1/6: classical total 0.178 ms, PQC total 0.311 ms
  round 2/6: classical total 0.178 ms, PQC total 0.315 ms
  round 3/6: classical total 0.177 ms, PQC total 0.308 ms
  round 4/6: classical total 0.177 ms, PQC total 0.311 ms
  round 5/6: classical total 0.176 ms, PQC total 0.310 ms
  round 6/6: classical total 0.175 ms, PQC total 0.323 ms
```

Gateway crypto per handshake: median over 6 alternating rounds (each round = median of 500 timed runs)

| Operation | Classical (Ed25519 + X25519) | Post-quantum (ML-DSA-44 + ML-KEM-512) | PQC / classical |
|---|---|---|---|
| Key exchange | 0.062 ms (p95 0.069) | 0.021 ms (p95 0.023) | 0.34x |
| Sign gateway transcript | 0.029 ms (p95 0.031) | 0.226 ms (p95 0.806) | 7.75x |
| Verify device signature | 0.078 ms (p95 0.083) | 0.059 ms (p95 0.062) | 0.75x |
| HKDF session keys | 0.004 ms (p95 0.004) | 0.004 ms (p95 0.004) | 1.01x |
| Two HMAC confirmation tags | 0.002 ms (p95 0.003) | 0.002 ms (p95 0.003) | 1.00x |
| TOTAL gateway crypto | 0.177 ms (p95 0.185) | 0.311 ms (p95 0.891) | 1.76x |

Round-to-round spread of the total: classical 1%, PQC 5%.
