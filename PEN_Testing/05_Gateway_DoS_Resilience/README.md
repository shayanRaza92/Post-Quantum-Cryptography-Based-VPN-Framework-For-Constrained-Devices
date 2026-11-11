# Test 5 — Gateway Denial-of-Service & Resource Exhaustion

## 1. Purpose
Evaluate whether an attacker can exhaust the gateway's CPU, memory, or connection capacity, and
confirm that the documented limits actually bound the impact. The goal is to **probe the limits**,
not to take the service down.

## 2. Vulnerability under investigation
A gateway that accepts unbounded concurrent handshakes, unlimited connections per IP, or holds
half-open handshakes forever can be starved by a single host — especially because each handshake
costs the gateway an ML-KEM encapsulation + ML-DSA signature (asymmetric cost favouring the
attacker). We verify the caps in `config.py` are enforced and that failed handshakes are cleaned
up.

## 3. How the test works — BOUNDED and SAFE
Every script here:
* loads `config.json` and refuses to act without `authorised: true` + `--run`;
* **clamps** its request/concurrency counts to the small ceiling in `config.json`
  (`limits.dos_max_requests`, `limits.dos_max_concurrent`);
* has conservative defaults and **no unbounded loop** — there is deliberately no "flood forever"
  mode;
* reports metrics (accepted vs. refused, timing) rather than trying to cause an outage.

Scripts:
* `probe_concurrent_handshakes.py` — opens up to the ceiling of connections and starts (but does
  not complete) handshakes, to observe the global cap (`MAX_CONCURRENT_HANDSHAKES=8`) and the
  per-IP cap (`MAX_HANDSHAKES_PER_IP=2`). Counts how many get a MSG 2 vs. are dropped.
* `probe_rate_limit.py` — makes a bounded burst of brief connections to observe the sliding
  window (`RATE_LIMIT_MAX_PER_IP=5` per `RATE_LIMIT_WINDOW_SEC=10`).
* `probe_slowloris.py` — opens a few connections and sends a partial MSG 1 slowly, to confirm the
  handshake deadline (`HANDSHAKE_TIMEOUT=15s`) drops stalled handshakes and frees the slot.

## 4. Part of the PQC VPN involved
* [`server.py`](../../PQC_VPN/laptop_server/server.py) — `_is_rate_limited`,
  `_try_acquire_handshake`, `_release_handshake`, `HandshakeSlot`, the accept loop
  (`listen(64)`).
* [`config.py`](../../PQC_VPN/laptop_server/config.py) — `MAX_CONCURRENT_HANDSHAKES=8`,
  `MAX_HANDSHAKES_PER_IP=2`, `RATE_LIMIT_WINDOW_SEC=10`, `RATE_LIMIT_MAX_PER_IP=5`,
  `HANDSHAKE_TIMEOUT=15`.
* [`tunnel_session.py`](../../PQC_VPN/laptop_server/tunnel_session.py) — `receive_exact`
  deadline enforcement; slot release on every failure path (cleanup after failed handshakes).

## 5. Files & modules in this test
* `modules/dos_common.py` — shared target loading, the ceiling clamp, and a single bounded
  connection helper used by all probes (no duplication, one choke point for safety).
* `scripts/probe_concurrent_handshakes.py`, `probe_rate_limit.py`, `probe_slowloris.py`.

## 6. Tools & dependencies
* Python 3 (standard library) for the probes.
* `nmap` (optional) for service discovery, documented but not required.
* An isolated lab network and your own gateway.

## 7. How it will be executed (future phase)
```bash
cd PEN_Testing/05_Gateway_DoS_Resilience
python scripts/probe_concurrent_handshakes.py --dry-run
python scripts/probe_concurrent_handshakes.py --run   # clamped to config.json ceiling
```
All probes dry-run by default and print the planned, clamped request count first.

## 8. Expected secure behaviour
* No more than 8 handshakes proceed globally at once; no more than 2 per IP.
* More than 5 connections per IP in 10 s are dropped with a rate-limit message.
* A stalled handshake is dropped at ~15 s and its slot is released (a later legitimate
  handshake still succeeds).
* The gateway and all other sessions keep running throughout.

## 9. What constitutes a vulnerability
* The caps not being enforced (e.g. >8 concurrent or >2 per IP accepted).
* A failed/stalled handshake permanently consuming a slot (slot leak) so that legitimate
  devices are locked out.
* The accept loop or a live tunnel dying because of one abusive client.

## 10. Evidence & metrics to collect
* Accepted-vs-refused counts at each attempted level, with timestamps.
* Time for a stalled handshake to be dropped (should be ≈ `HANDSHAKE_TIMEOUT`).
* Confirmation that a legitimate handshake succeeds immediately after the probe stops (no leak).
* Gateway CPU/RAM sampled during the probe (e.g. `top`/`psutil`), for the report.
