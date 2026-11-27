# Step 3 Wireshark screenshots

Opened with the plug-in `tools/wireshark/drone_auth.lua`.

**Run `link_20261124_210648` (styles udp and emulated MAVLink-sized frames, 20 runs):**

| File | Shows |
|---|---|
| 1_startup_hello_pubkey.png | drone HELLO and the public keys being sent |
| 2_ed25519_mavlink_1_frame.png | Ed25519 authentication in 1 emulated MAVLink-sized frame |
| 3_mldsa44_mavlink_10_frames.png | ML-DSA-44 authentication in 10 emulated MAVLink-sized frames |
| 4_mldsa87_mavlink_19_frames.png | ML-DSA-87 in 19 emulated MAVLink-sized frames |
| 5_mldsa87_wifi_split_4_packets.png | ML-DSA-87 as one UDP datagram split into 4 IP packets |
| 6_ed25519_details_64B_signature.png | details of an Ed25519 message (64-byte signature) |
| 7_mldsa44_details_2420B_signature.png | details of an ML-DSA-44 message (2,420-byte signature) |

**Run `link_20261128_004020` (real MAVLink 2 packets from the official C library, 100 runs):**

| File | Shows |
|---|---|
| 8_real_mavlink_mldsa44_v2ext_11_packets.png | ML-DSA-44 authentication seq 1829: challenge, 11 V2_EXTENSION packets, result (Fig. 4 of the paper) |
| 9_real_mavlink_ed25519_v2ext_1_packet.png | Ed25519 authentication seq 249: challenge, 1 V2_EXTENSION packet, result |
| 10_real_mavlink_mldsa44_details_checksum.png | one ML-DSA-44 V2_EXTENSION packet decoded: MAVLink 2 header, payload fields, checksum correct |
| 11_real_mavlink_ed25519_details_checksum.png | the Ed25519 V2_EXTENSION packet decoded, checksum correct, fragment 1 of 1 |

Filter used for one authentication: `droneauth.seq == 1829 && droneauth.type != 7` (time reference set on the challenge).
