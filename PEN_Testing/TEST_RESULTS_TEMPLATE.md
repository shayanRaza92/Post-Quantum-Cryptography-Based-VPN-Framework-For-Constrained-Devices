# Test Results — <Test Name>

> Copy this file into the relevant `NN_*/reports/` folder (e.g.
> `reports/2026-11-10_handshake_mitm.md`) and fill it in for each run.

## Run metadata

| Field | Value |
|-------|-------|
| Test ID | e.g. 03-MITM-01 |
| Test category | e.g. 03_Handshake_Protocol_Security |
| Script / command | e.g. `python scripts/run_mitm_tamper.py --run` |
| Tester | |
| Date / time | |
| Target host:port | e.g. 192.168.50.10:9000 (LAB) |
| Target commit | git hash of `PQC_VPN/` under test |
| Authorised? | yes — lab network, own hardware |
| Mode | dry-run / live |

## Objective

<One or two sentences: which security property this run tests.>

## Expected secure behaviour

<Copy the "Expected secure behaviour" from the category README.>

## What was done

<Steps actually performed, exact inputs, any manipulation applied.>

## Observed result

<Raw output summary. Attach full logs / pcap in this folder and reference the filename.>

## Verdict

- [ ] PASS — target behaved as the secure-behaviour spec requires
- [ ] FAIL — vulnerability found (describe below)
- [ ] INCONCLUSIVE — explain why

## Vulnerability (if FAIL)

| Field | Value |
|-------|-------|
| Description | |
| Severity (CVSS / Low-Med-High-Crit) | |
| Affected PQC_VPN file(s) | |
| Root cause | |
| Recommended fix | |

## Evidence / metrics collected

- Files attached: <pcap, logs, screenshots>
- Metrics: <e.g. handshakes accepted vs. rejected, CPU %, connections held, timing>

## Notes
