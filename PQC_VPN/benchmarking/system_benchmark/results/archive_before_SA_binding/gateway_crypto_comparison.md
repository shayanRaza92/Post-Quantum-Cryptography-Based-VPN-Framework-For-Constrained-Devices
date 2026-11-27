# Gateway crypto per handshake: classical vs. post-quantum (alternating rounds)

Made with `compare_gateway_crypto.py --rounds 6 --runs 500` on the HP Victus 15, plugged in, Performance power mode.

```
  round 1/6: classical total 0.177 ms, PQC total 0.320 ms
  round 2/6: classical total 0.177 ms, PQC total 0.323 ms
  round 3/6: classical total 0.178 ms, PQC total 0.317 ms
  round 4/6: classical total 0.177 ms, PQC total 0.322 ms
  round 5/6: classical total 0.177 ms, PQC total 0.367 ms
  round 6/6: classical total 0.177 ms, PQC total 0.336 ms

Gateway crypto per handshake: median over 6 alternating rounds (each round = median of 500 timed runs)

| Operation | Classical (Ed25519 + X25519) | Post-quantum (ML-DSA-44 + ML-KEM-512) | PQC / classical |
|---|---|---|---|
| Key exchange | 0.062 ms (p95 0.069) | 0.021 ms (p95 0.023) | 0.34x |
| Sign gateway transcript | 0.029 ms (p95 0.032) | 0.233 ms (p95 0.845) | 7.96x |
| Verify device signature | 0.078 ms (p95 0.083) | 0.059 ms (p95 0.062) | 0.76x |
| HKDF session keys | 0.004 ms (p95 0.004) | 0.004 ms (p95 0.004) | 1.00x |
| Two HMAC confirmation tags | 0.002 ms (p95 0.003) | 0.002 ms (p95 0.003) | 0.99x |
| TOTAL gateway crypto | 0.177 ms (p95 0.186) | 0.323 ms (p95 0.932) | 1.82x |

Round-to-round spread of the total: classical 1%, PQC 15%
```
