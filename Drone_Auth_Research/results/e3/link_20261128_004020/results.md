# Step 3 (E3): drone authentication on a real Wi-Fi link

Run `link_20261128_004020`. Drone drone-01 at 10.60.60.39, captured on wlo1. 100 authentications per algorithm, style and size. Git commit `b19fb73ce2c7`. Ground station Wi-Fi power saving: off.

Styles: **udp** = one UDP datagram per message (split by the IP layer into 1,500-byte packets); **mav** = MAVLink-sized frames of at most 255 payload bytes, one UDP datagram each (emulated); **tunnel** / **v2ext** = real MAVLink 2 TUNNEL / V2_EXTENSION packets from the official C library, parsed and CRC-checked by pymavlink, one UDP datagram each.

pymavlink 2.4.50: 36537 MAVLink packets parsed, 0 rejected (bad CRC or malformed).


## Largest data that still fitted in ONE packet (measured)

| Algorithm | Wi-Fi UDP: one packet up to | first size that needed 2+ | MAVLink-sized: one frame up to | first size that needed 2+ |
|---|---:|---:|---:|---:|

'none' = even the smallest message (64 bytes of data) needed more than one packet.

## Real MAVLink 2 TUNNEL packets: every algorithm and data size (medians)

| Algorithm | Data (B) | Packets | Bytes on wire (auth msg) | Signature share | Challenge to verified (ms) | 95% CI of the median (ms) | p95 (ms) | Drone signing (ms) | Network + ground station (ms) | Transfer of the message (ms) | Lost |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Ed25519 | 64 | 2 | 240 | 26.7% | 18.4 | 17.9-18.7 | 23.4 | 9.8 | 8.5 | 0.00 | 0.0% |
| Ed25519 | 1,024 | 9 | 1,550 | 4.1% | 23.2 | 22.0-24.2 | 77.1 | 10.0 | 13.2 | 3.66 | 0.0% |
| ECDSA-P256 | 64 | 2 | 247 | 29.1% | 187.7 | 187.5-188.4 | 197.1 | 177.4 | 10.4 | 0.00 | 0.0% |
| ECDSA-P256 | 1,024 | 9 | 1,557 | 4.6% | 195.1 | 191.8-214.9 | 452.4 | 177.5 | 17.6 | 5.46 | 0.0% |
| RSA-3072 | 64 | 4 | 660 | 58.2% | 406.6 | 405.2-408.8 | 494.6 | 392.9 | 13.4 | 0.00 | 0.0% |
| RSA-3072 | 1,024 | 12 | 2,020 | 19.0% | 410.2 | 408.6-411.8 | 461.3 | 393.2 | 17.1 | 4.42 | 0.0% |
| ML-DSA-44 | 64 | 21 | 3,546 | 68.2% | 110.7 | 79.0-128.0 | 309.5 | 53.4 | 28.4 | 15.25 | 2.0% |
| ML-DSA-44 | 1,024 | 29 | 4,895 | 49.4% | 95.2 | 85.0-113.2 | 264.9 | 53.3 | 30.7 | 18.42 | 0.0% |
| ML-DSA-65 | 64 | 28 | 4,785 | 69.2% | 184.2 | 156.7-212.4 | 498.1 | 104.3 | 57.2 | 23.29 | 4.0% |
| ML-DSA-65 | 1,024 | 36 | 6,145 | 53.8% | 237.6 | 190.7-266.9 | 546.2 | 132.7 | 80.2 | 48.62 | 1.0% |
| ML-DSA-87 | 64 | 39 | 6,653 | 69.5% | 172.7 | 163.3-214.9 | 495.5 | 138.9 | 34.6 | 23.96 | 0.0% |
| ML-DSA-87 | 1,024 | 47 | 8,013 | 57.7% | 203.4 | 173.3-245.6 | 484.6 | 139.1 | 61.2 | 47.37 | 0.0% |

## Real MAVLink 2 V2_EXTENSION packets: every algorithm and data size (medians)

| Algorithm | Data (B) | Packets | Bytes on wire (auth msg) | Signature share | Challenge to verified (ms) | 95% CI of the median (ms) | p95 (ms) | Drone signing (ms) | Network + ground station (ms) | Transfer of the message (ms) | Lost |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Ed25519 | 64 | 1 | 190 | 33.7% | 18.1 | 17.8-18.4 | 22.0 | 9.8 | 8.2 | 0.00 | 0.0% |
| Ed25519 | 168 | 1 | 294 | 21.8% | 24.5 | 19.1-37.8 | 128.8 | 9.9 | 14.6 | 0.00 | 0.0% |
| Ed25519 | 169 | 2 | 345 | 18.6% | 19.6 | 18.8-21.6 | 456.5 | 9.9 | 9.8 | 0.00 | 0.0% |
| Ed25519 | 1,024 | 5 | 1,350 | 4.7% | 19.7 | 19.2-20.1 | 28.3 | 10.0 | 9.7 | 0.61 | 0.0% |
| ECDSA-P256 | 64 | 1 | 197 | 36.5% | 188.6 | 188.0-188.9 | 214.5 | 177.4 | 11.2 | 0.00 | 0.0% |
| ECDSA-P256 | 160 | 1 | 293 | 24.6% | 188.7 | 187.8-189.4 | 275.2 | 177.4 | 11.4 | 0.00 | 0.0% |
| ECDSA-P256 | 161 | 1 | 294 | 24.5% | 201.9 | 187.5-245.3 | 318.2 | 177.4 | 24.1 | 0.00 | 1.0% |
| ECDSA-P256 | 1,024 | 5 | 1,357 | 5.3% | 191.8 | 190.6-195.1 | 287.4 | 177.5 | 14.4 | 0.00 | 1.0% |
| RSA-3072 | 64 | 2 | 560 | 68.6% | 404.7 | 404.4-406.0 | 474.8 | 393.2 | 11.6 | 0.00 | 0.0% |
| RSA-3072 | 1,024 | 6 | 1,720 | 22.3% | 406.7 | 405.2-413.7 | 557.9 | 392.7 | 14.0 | 0.00 | 1.0% |
| ML-DSA-44 | 64 | 11 | 3,046 | 79.4% | 64.8 | 57.5-70.9 | 188.7 | 51.3 | 13.8 | 4.12 | 0.0% |
| ML-DSA-44 | 1,024 | 15 | 4,206 | 57.5% | 71.0 | 60.9-89.7 | 217.7 | 54.9 | 17.4 | 7.70 | 0.0% |
| ML-DSA-65 | 64 | 14 | 4,085 | 81.0% | 169.5 | 142.4-186.7 | 470.4 | 86.0 | 33.6 | 15.80 | 1.0% |
| ML-DSA-65 | 1,024 | 18 | 5,245 | 63.1% | 127.8 | 107.8-140.2 | 416.8 | 108.0 | 19.0 | 7.70 | 0.0% |
| ML-DSA-87 | 64 | 20 | 5,703 | 81.1% | 168.5 | 151.8-202.1 | 449.1 | 139.0 | 26.2 | 14.63 | 0.0% |
| ML-DSA-87 | 1,024 | 24 | 6,863 | 67.4% | 168.4 | 150.8-202.3 | 496.0 | 100.1 | 31.9 | 20.38 | 0.0% |

## Calculated: sending the signed message over a 57.6 kbit/s MAVLink telemetry radio

Uses the measured message length and frame count (MAVLink-sized style) and adds MAVLink 2's 12 bytes of header and checksum per frame. No IP/UDP headers on a serial radio. A 57,600-baud serial line sends 10 bits per byte (start bit, 8 data bits, stop bit), so time = bytes x 10 / 57,600. Last column: with MAVLink 2's own message signing switched on as well (13 more bytes per frame).

| Algorithm | Data (B) | Frames | Bytes on the radio | Time on the radio (ms) | With MAVLink signing (ms) |
|---|---:|---:|---:|---:|---:|

## Real MAVLink 2 packets on a 57,600-baud telemetry radio (calculated from the MEASURED packet bytes)

Bytes = the MAVLink 2 packets exactly as captured (header, payload after MAVLink 2's trailing-zero truncation, checksum; no IP/UDP). Time = bytes x 10 / 57,600. Last column: MAVLink 2 signing on (13 more bytes per packet).

| Style | Algorithm | Data (B) | Packets | MAVLink bytes | Time on the radio (ms) | With MAVLink signing (ms) |
|---|---|---:|---:|---:|---:|---:|
| tunnel | Ed25519 | 64 | 2 | 184 | 32 | 36 |
| tunnel | Ed25519 | 1,024 | 9 | 1,298 | 225 | 246 |
| v2ext | Ed25519 | 64 | 1 | 162 | 28 | 30 |
| v2ext | Ed25519 | 168 | 1 | 266 | 46 | 48 |
| v2ext | Ed25519 | 169 | 2 | 289 | 50 | 55 |
| v2ext | Ed25519 | 1,024 | 5 | 1,210 | 210 | 221 |
| tunnel | ECDSA-P256 | 64 | 2 | 191 | 33 | 38 |
| tunnel | ECDSA-P256 | 1,024 | 9 | 1,305 | 227 | 247 |
| v2ext | ECDSA-P256 | 64 | 1 | 169 | 29 | 32 |
| v2ext | ECDSA-P256 | 160 | 1 | 265 | 46 | 48 |
| v2ext | ECDSA-P256 | 161 | 1 | 266 | 46 | 48 |
| v2ext | ECDSA-P256 | 1,024 | 5 | 1,217 | 211 | 223 |
| tunnel | RSA-3072 | 64 | 4 | 548 | 95 | 104 |
| tunnel | RSA-3072 | 1,024 | 12 | 1,684 | 292 | 319 |
| v2ext | RSA-3072 | 64 | 2 | 504 | 88 | 92 |
| v2ext | RSA-3072 | 1,024 | 6 | 1,552 | 269 | 283 |
| tunnel | ML-DSA-44 | 64 | 21 | 2,958 | 514 | 561 |
| tunnel | ML-DSA-44 | 1,024 | 29 | 4,083 | 709 | 774 |
| v2ext | ML-DSA-44 | 64 | 11 | 2,738 | 475 | 500 |
| v2ext | ML-DSA-44 | 1,024 | 15 | 3,786 | 657 | 691 |
| tunnel | ML-DSA-65 | 64 | 28 | 4,001 | 695 | 758 |
| tunnel | ML-DSA-65 | 1,024 | 36 | 5,137 | 892 | 973 |
| v2ext | ML-DSA-65 | 64 | 14 | 3,693 | 641 | 673 |
| v2ext | ML-DSA-65 | 1,024 | 18 | 4,741 | 823 | 864 |
| tunnel | ML-DSA-87 | 64 | 39 | 5,561 | 965 | 1,053 |
| tunnel | ML-DSA-87 | 1,024 | 47 | 6,697 | 1,163 | 1,269 |
| v2ext | ML-DSA-87 | 64 | 20 | 5,143 | 893 | 938 |
| v2ext | ML-DSA-87 | 1,024 | 24 | 6,191 | 1,075 | 1,129 |

Network + ground station = challenge-to-verified time minus the drone's signing time (per message, then median). Transfer = time between the first and the last packet of the signed message in the capture.

All runs: 2800 authentications, 2789 verified by the ground station, 11 lost (no complete answer within 5 s).
