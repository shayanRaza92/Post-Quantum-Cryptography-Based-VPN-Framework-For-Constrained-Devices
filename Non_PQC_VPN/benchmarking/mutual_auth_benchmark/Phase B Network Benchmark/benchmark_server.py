# Laptop Benchmark Server for Mutual Authentication (Phase B: Network Benchmark)
# Aligned with the production 4-Message Handshake Protocol and Running Transcript Hashing:
# - Option A 4-Message Handshake:
#     MSG 1 (Client Hello, 50B) -> [Ver (1B) | AlgID (1B) | DeviceID (16B) | ClientNonce (32B)]
#     MSG 2 (Server Proof, 96B for Ed25519) <- [ServerNonce (32B) | ServerSig over Server Transcript]
#     MSG 3 (Client Proof, 64B for Ed25519) -> [ClientSig over Client Transcript (binds MSG1 || MSG2)]
#     MSG 4 (Server Verdict & Timing ACK, 8B) <- [Status (4B) | Server Crypto Time in us (4B)]
# - TLS 1.3-style Running Transcript Hashing:
#     Server Transcript: SHA-256("VPN-v1|SERVER|" || MSG1 || ServerNonce)
#     Client Transcript: SHA-256("VPN-v1|CLIENT|" || MSG1 || MSG2)
# - Suites: NULL Baseline (transport floor), Ed25519, ECDSA P-256, RSA-3072
# - True Desynchronization Resilience: explicit verdicts prevent TCP stream stalls
# - Comprehensive Statistical Analysis (Mean, Median, StdDev σ, Min, Max)

import socket
import struct
import time
import os
import math
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization

HOST = "0.0.0.0"
PORT = 9000
ALLOWED_DEVICE_ID = "esp32-01"

SERVER_TRANSCRIPT_LABEL = b"VPN-v1|SERVER|"
CLIENT_TRANSCRIPT_LABEL = b"VPN-v1|CLIENT|"


# ----------------------------------------------------
# Helper: Get laptop local IP
# ----------------------------------------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


# ----------------------------------------------------
# Statistical Calculation Helper
# ----------------------------------------------------
def calculate_stats(data):
    if not data:
        return {"mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0, "stddev": 0.0}
    n = len(data)
    mean = sum(data) / n
    sorted_d = sorted(data)
    min_val = sorted_d[0]
    max_val = sorted_d[-1]
    if n % 2 == 0:
        median = (sorted_d[n // 2 - 1] + sorted_d[n // 2]) / 2.0
    else:
        median = sorted_d[n // 2]
    if n > 1:
        variance = sum((x - mean) ** 2 for x in data) / (n - 1)
        stddev = math.sqrt(variance)
    else:
        stddev = 0.0
    return {
        "mean": mean,
        "median": median,
        "min": min_val,
        "max": max_val,
        "stddev": stddev
    }


# ----------------------------------------------------
# Protocol Transcript Builders (Running Transcript Hash)
# Exact match with production laptop_server/crypto_engine.py
# ----------------------------------------------------
def build_server_transcript(msg1: bytes, server_nonce: bytes) -> bytes:
    """
    Server Transcript (signed in MSG 2):
    SHA-256("VPN-v1|SERVER|" (14B) || MSG1 (50B) || ServerNonce (32B)) -> 96B input
    """
    h = hashlib.sha256()
    h.update(SERVER_TRANSCRIPT_LABEL)
    h.update(msg1)
    h.update(server_nonce)
    return h.digest()


def build_client_transcript(msg1: bytes, msg2: bytes) -> bytes:
    """
    Client Transcript (signed in MSG 3):
    SHA-256("VPN-v1|CLIENT|" (14B) || MSG1 (50B) || MSG2 (len bytes)) -> binds entire transcript
    """
    h = hashlib.sha256()
    h.update(CLIENT_TRANSCRIPT_LABEL)
    h.update(msg1)
    h.update(msg2)
    return h.digest()


# ----------------------------------------------------
# Network Helpers (Length-prefixed Single-Segment Framing)
# ----------------------------------------------------
def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        except socket.timeout:
            return None
    return bytes(buf)


def recv_msg(conn):
    header = recv_exact(conn, 2)
    if not header:
        return None
    length = struct.unpack("!H", header)[0]
    payload = recv_exact(conn, length)
    if payload is None:
        return None
    return payload


def send_msg(conn, payload):
    header = struct.pack("!H", len(payload))
    conn.sendall(header + payload)


# ----------------------------------------------------
# Benchmark Suite 0: NULL-Crypto Baseline
# Measures the empirical physical network latency floor over Wi-Fi
# Identical 4-message exchange & wire sizes to Ed25519, zero crypto math
# ----------------------------------------------------
def benchmark_null(conn, runs):
    print("\n[0/3] Benchmarking NULL-Crypto Baseline (Wi-Fi Transport Floor)...")

    handshake_times = []
    wire_bytes_list = []
    successful_runs = 0

    for i in range(runs):
        t_start = time.perf_counter()
        run_wire = 0

        # MSG 1: Receive 50-byte Client Hello
        msg1 = recv_msg(conn)
        if not msg1 or len(msg1) != 50:
            print(f"  Run {i+1} failed: Invalid MSG 1 length ({len(msg1) if msg1 else 0})")
            if msg1 is None:
                break
            send_msg(conn, struct.pack("!II", 0, 0))
            continue
        run_wire += (2 + len(msg1))

        device_id = msg1[2:18].rstrip(b"\x00").decode("ascii", errors="ignore")
        if device_id != ALLOWED_DEVICE_ID:
            print(f"  Run {i+1} failed: Unauthorized Device ID '{device_id}'")
            send_msg(conn, os.urandom(96))
            recv_msg(conn)
            send_msg(conn, struct.pack("!II", 0, 0))
            continue

        # MSG 2: Send 96-byte dummy Server Proof (32B dummy nonce + 64B dummy payload)
        dummy_server_nonce = os.urandom(32)
        dummy_sig = os.urandom(64)
        msg2 = dummy_server_nonce + dummy_sig
        send_msg(conn, msg2)
        run_wire += (2 + len(msg2))

        # MSG 3: Receive 64-byte dummy Client Proof
        msg3 = recv_msg(conn)
        if not msg3 or len(msg3) != 64:
            print(f"  Run {i+1} failed: Invalid MSG 3 length ({len(msg3) if msg3 else 0})")
            if msg3 is None:
                break
            send_msg(conn, struct.pack("!II", 0, 0))
            continue
        run_wire += (2 + len(msg3))

        # MSG 4: Send 8-byte Verdict ACK (Status=1, Server Crypto Time=0 us)
        ack = struct.pack("!II", 1, 0)
        send_msg(conn, ack)
        run_wire += (2 + len(ack))

        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # ms
        handshake_times.append(t_elapsed)
        wire_bytes_list.append(run_wire)
        successful_runs += 1

        if (i + 1) % 10 == 0 or (i + 1) == runs:
            print(f"  - Completed {i+1:2d}/{runs} | Total Latency: {t_elapsed:6.2f} ms | OK")

    stats = calculate_stats(handshake_times)
    avg_wire = int(sum(wire_bytes_list) / len(wire_bytes_list)) if wire_bytes_list else 0
    success_rate = (successful_runs / runs * 100.0) if runs > 0 else 0.0

    print(f"\n  [NULL] Mean Latency: {stats['mean']:6.2f} ms | Median: {stats['median']:6.2f} ms | Wire: {avg_wire} B | Success: {success_rate:5.1f}%")

    return {
        "algo": "NULL Baseline",
        "runs": runs,
        "success": successful_runs,
        "stats": stats,
        "server_crypto": 0.0,
        "wire_bytes": avg_wire,
        "success_rate": success_rate
    }


# ----------------------------------------------------
# Benchmark Suite 1: Ed25519 Mutual Authentication
# Fully aligned with production 4-message handshake and running transcript
# ----------------------------------------------------
def benchmark_ed25519(conn, runs):
    print("\n[1/3] Benchmarking Ed25519 Real Mutual Authentication over Wi-Fi...")

    # Provisioning Key Exchange (Out-of-band / session init)
    server_priv = ed25519.Ed25519PrivateKey.generate()
    server_pub_bytes = server_priv.public_key().public_bytes_raw()

    client_pub_bytes = recv_msg(conn)
    if not client_pub_bytes or len(client_pub_bytes) != 32:
        print("  Error receiving client Ed25519 public key")
        return None
    client_pub = ed25519.Ed25519PublicKey.from_public_bytes(client_pub_bytes)
    send_msg(conn, server_pub_bytes)

    handshake_times = []
    server_crypto_times = []
    wire_bytes_list = []
    successful_runs = 0

    for i in range(runs):
        t_start = time.perf_counter()
        run_wire = 0

        # MSG 1: Receive 50-byte Client Hello
        msg1 = recv_msg(conn)
        if not msg1 or len(msg1) != 50:
            print(f"  Run {i+1} failed: Invalid MSG 1 length ({len(msg1) if msg1 else 0})")
            if msg1 is None:
                break
            send_msg(conn, struct.pack("!II", 0, 0))
            continue
        run_wire += (2 + len(msg1))

        device_id = msg1[2:18].rstrip(b"\x00").decode("ascii", errors="ignore")
        if device_id != ALLOWED_DEVICE_ID:
            print(f"  Run {i+1} failed: Unauthorized Device ID '{device_id}'")
            send_msg(conn, os.urandom(96))
            recv_msg(conn)
            send_msg(conn, struct.pack("!II", 0, 0))
            continue

        # Server Crypto 1: Generate Server Nonce & Sign Server Transcript
        t_sc_start1 = time.perf_counter()
        server_nonce = os.urandom(32)
        server_digest = build_server_transcript(msg1, server_nonce)
        server_sig = server_priv.sign(server_digest)
        t_sc_end1 = time.perf_counter()

        # MSG 2: Send 96-byte Server Proof (32B nonce + 64B sig)
        msg2 = server_nonce + server_sig
        send_msg(conn, msg2)
        run_wire += (2 + len(msg2))

        # MSG 3: Receive 64-byte Client Proof (Client Signature)
        msg3 = recv_msg(conn)
        if not msg3 or len(msg3) != 64:
            print(f"  Run {i+1} failed: Invalid MSG 3 length ({len(msg3) if msg3 else 0})")
            if msg3 is None:
                break
            send_msg(conn, struct.pack("!II", 0, 0))
            continue
        run_wire += (2 + len(msg3))
        client_sig = msg3

        # Server Crypto 2: Verify Client Signature over Client Transcript (binds MSG1 || MSG2)
        t_sc_start2 = time.perf_counter()
        client_digest = build_client_transcript(msg1, msg2)
        verified = True
        try:
            client_pub.verify(client_sig, client_digest)
        except Exception:
            verified = False
        t_sc_end2 = time.perf_counter()

        server_crypto_us = int(((t_sc_end1 - t_sc_start1) + (t_sc_end2 - t_sc_start2)) * 1_000_000)

        if not verified:
            print(f"  Run {i+1} failed: Client Ed25519 signature verification error")
            ack = struct.pack("!II", 0, server_crypto_us)
            send_msg(conn, ack)
            continue

        # MSG 4: Send 8-byte Verdict ACK (Status=1, Server Crypto Time)
        ack = struct.pack("!II", 1, server_crypto_us)
        send_msg(conn, ack)
        run_wire += (2 + len(ack))

        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # ms
        handshake_times.append(t_elapsed)
        server_crypto_times.append(server_crypto_us / 1000.0)
        wire_bytes_list.append(run_wire)
        successful_runs += 1

        if (i + 1) % 10 == 0 or (i + 1) == runs:
            print(f"  - Completed {i+1:2d}/{runs} | Handshake: {t_elapsed:6.2f} ms | Srv Crypto: {server_crypto_us/1000.0:4.2f} ms | OK")

    stats = calculate_stats(handshake_times)
    s_crypto_stats = calculate_stats(server_crypto_times)
    avg_wire = int(sum(wire_bytes_list) / len(wire_bytes_list)) if wire_bytes_list else 0
    success_rate = (successful_runs / runs * 100.0) if runs > 0 else 0.0

    print(f"\n  [Ed25519] Mean Latency: {stats['mean']:6.2f} ms | Median: {stats['median']:6.2f} ms | Wire: {avg_wire} B | Success: {success_rate:5.1f}%")

    return {
        "algo": "Ed25519",
        "runs": runs,
        "success": successful_runs,
        "stats": stats,
        "server_crypto": s_crypto_stats['mean'],
        "wire_bytes": avg_wire,
        "success_rate": success_rate
    }


# ----------------------------------------------------
# Benchmark Suite 2: ECDSA P-256 Mutual Authentication
# ----------------------------------------------------
def benchmark_ecdsa(conn, runs):
    print("\n[2/3] Benchmarking ECDSA P-256 Real Mutual Authentication over Wi-Fi...")

    # Provisioning Key Exchange
    server_priv = ec.generate_private_key(ec.SECP256R1())
    server_pub_bytes = server_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )

    client_pub_bytes = recv_msg(conn)
    if not client_pub_bytes or len(client_pub_bytes) != 65:
        print(f"  Error receiving client ECDSA public key (got {len(client_pub_bytes) if client_pub_bytes else 0} bytes)")
        return None
    client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
    send_msg(conn, server_pub_bytes)

    handshake_times = []
    server_crypto_times = []
    wire_bytes_list = []
    successful_runs = 0

    for i in range(runs):
        t_start = time.perf_counter()
        run_wire = 0

        # MSG 1: Receive 50-byte Client Hello
        msg1 = recv_msg(conn)
        if not msg1 or len(msg1) != 50:
            print(f"  Run {i+1} failed: Invalid MSG 1 length ({len(msg1) if msg1 else 0})")
            if msg1 is None:
                break
            send_msg(conn, struct.pack("!II", 0, 0))
            continue
        run_wire += (2 + len(msg1))

        device_id = msg1[2:18].rstrip(b"\x00").decode("ascii", errors="ignore")
        if device_id != ALLOWED_DEVICE_ID:
            print(f"  Run {i+1} failed: Unauthorized Device ID '{device_id}'")
            send_msg(conn, os.urandom(96))
            recv_msg(conn)
            send_msg(conn, struct.pack("!II", 0, 0))
            continue

        # Server Crypto 1: Generate Server Nonce & Sign Server Transcript with ECDSA P-256
        t_sc_start1 = time.perf_counter()
        server_nonce = os.urandom(32)
        server_digest = build_server_transcript(msg1, server_nonce)
        server_sig = server_priv.sign(server_digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        t_sc_end1 = time.perf_counter()

        # MSG 2: Send Server Proof (32B nonce + DER sig)
        msg2 = server_nonce + server_sig
        send_msg(conn, msg2)
        run_wire += (2 + len(msg2))

        # MSG 3: Receive Client Proof (DER sig)
        msg3 = recv_msg(conn)
        if not msg3 or len(msg3) < 30:
            print(f"  Run {i+1} failed: Invalid MSG 3 length ({len(msg3) if msg3 else 0})")
            if msg3 is None:
                break
            send_msg(conn, struct.pack("!II", 0, 0))
            continue
        run_wire += (2 + len(msg3))
        client_sig = msg3

        # Server Crypto 2: Verify Client ECDSA Signature over Client Transcript
        t_sc_start2 = time.perf_counter()
        client_digest = build_client_transcript(msg1, msg2)
        verified = True
        try:
            client_pub.verify(client_sig, client_digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        except Exception:
            verified = False
        t_sc_end2 = time.perf_counter()

        server_crypto_us = int(((t_sc_end1 - t_sc_start1) + (t_sc_end2 - t_sc_start2)) * 1_000_000)

        if not verified:
            print(f"  Run {i+1} failed: Client ECDSA signature verification error")
            ack = struct.pack("!II", 0, server_crypto_us)
            send_msg(conn, ack)
            continue

        # MSG 4: Send 8-byte Verdict ACK (Status=1, Server Crypto Time)
        ack = struct.pack("!II", 1, server_crypto_us)
        send_msg(conn, ack)
        run_wire += (2 + len(ack))

        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # ms
        handshake_times.append(t_elapsed)
        server_crypto_times.append(server_crypto_us / 1000.0)
        wire_bytes_list.append(run_wire)
        successful_runs += 1

        if (i + 1) % 10 == 0 or (i + 1) == runs:
            print(f"  - Completed {i+1:2d}/{runs} | Handshake: {t_elapsed:6.2f} ms | Srv Crypto: {server_crypto_us/1000.0:4.2f} ms | OK")

    stats = calculate_stats(handshake_times)
    s_crypto_stats = calculate_stats(server_crypto_times)
    avg_wire = int(sum(wire_bytes_list) / len(wire_bytes_list)) if wire_bytes_list else 0
    success_rate = (successful_runs / runs * 100.0) if runs > 0 else 0.0

    print(f"\n  [ECDSA] Mean Latency: {stats['mean']:6.2f} ms | Median: {stats['median']:6.2f} ms | Wire: {avg_wire} B | Success: {success_rate:5.1f}%")

    return {
        "algo": "ECDSA P-256",
        "runs": runs,
        "success": successful_runs,
        "stats": stats,
        "server_crypto": s_crypto_stats['mean'],
        "wire_bytes": avg_wire,
        "success_rate": success_rate
    }


# ----------------------------------------------------
# Benchmark Suite 3: RSA-3072 Mutual Authentication
# ----------------------------------------------------
def benchmark_rsa(conn, runs):
    print("\n[3/3] Benchmarking RSA-3072 Real Mutual Authentication over Wi-Fi...")

    # Provisioning Key Exchange
    server_priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_pub_bytes = server_priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client_pub_bytes = recv_msg(conn)
    if not client_pub_bytes:
        print("  Error receiving client RSA public key")
        return None
    client_pub = serialization.load_der_public_key(client_pub_bytes)
    send_msg(conn, server_pub_bytes)

    handshake_times = []
    server_crypto_times = []
    wire_bytes_list = []
    successful_runs = 0

    for i in range(runs):
        t_start = time.perf_counter()
        run_wire = 0

        # MSG 1: Receive 50-byte Client Hello
        msg1 = recv_msg(conn)
        if not msg1 or len(msg1) != 50:
            print(f"  Run {i+1} failed: Invalid MSG 1 length ({len(msg1) if msg1 else 0})")
            if msg1 is None:
                break
            send_msg(conn, struct.pack("!II", 0, 0))
            continue
        run_wire += (2 + len(msg1))

        device_id = msg1[2:18].rstrip(b"\x00").decode("ascii", errors="ignore")
        if device_id != ALLOWED_DEVICE_ID:
            print(f"  Run {i+1} failed: Unauthorized Device ID '{device_id}'")
            send_msg(conn, os.urandom(416))
            recv_msg(conn)
            send_msg(conn, struct.pack("!II", 0, 0))
            continue

        # Server Crypto 1: Generate Server Nonce & Sign Server Transcript with RSA-3072
        t_sc_start1 = time.perf_counter()
        server_nonce = os.urandom(32)
        server_digest = build_server_transcript(msg1, server_nonce)
        server_sig = server_priv.sign(server_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        t_sc_end1 = time.perf_counter()

        # MSG 2: Send Server Proof (32B nonce + 384B sig = 416 bytes)
        msg2 = server_nonce + server_sig
        send_msg(conn, msg2)
        run_wire += (2 + len(msg2))

        # MSG 3: Receive Client Proof (384B sig)
        msg3 = recv_msg(conn)
        if not msg3 or len(msg3) != 384:
            print(f"  Run {i+1} failed: Invalid MSG 3 length ({len(msg3) if msg3 else 0})")
            if msg3 is None:
                break
            send_msg(conn, struct.pack("!II", 0, 0))
            continue
        run_wire += (2 + len(msg3))
        client_sig = msg3

        # Server Crypto 2: Verify Client RSA Signature over Client Transcript
        t_sc_start2 = time.perf_counter()
        client_digest = build_client_transcript(msg1, msg2)
        verified = True
        try:
            client_pub.verify(client_sig, client_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        except Exception:
            verified = False
        t_sc_end2 = time.perf_counter()

        server_crypto_us = int(((t_sc_end1 - t_sc_start1) + (t_sc_end2 - t_sc_start2)) * 1_000_000)

        if not verified:
            print(f"  Run {i+1} failed: Client RSA signature verification error")
            ack = struct.pack("!II", 0, server_crypto_us)
            send_msg(conn, ack)
            continue

        # MSG 4: Send 8-byte Verdict ACK (Status=1, Server Crypto Time)
        ack = struct.pack("!II", 1, server_crypto_us)
        send_msg(conn, ack)
        run_wire += (2 + len(ack))

        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # ms
        handshake_times.append(t_elapsed)
        server_crypto_times.append(server_crypto_us / 1000.0)
        wire_bytes_list.append(run_wire)
        successful_runs += 1

        if (i + 1) % 5 == 0 or (i + 1) == runs:
            print(f"  - Completed {i+1:2d}/{runs} | Handshake: {t_elapsed:6.2f} ms | Srv Crypto: {server_crypto_us/1000.0:4.2f} ms | OK")

    stats = calculate_stats(handshake_times)
    s_crypto_stats = calculate_stats(server_crypto_times)
    avg_wire = int(sum(wire_bytes_list) / len(wire_bytes_list)) if wire_bytes_list else 0
    success_rate = (successful_runs / runs * 100.0) if runs > 0 else 0.0

    print(f"\n  [RSA-3072] Mean Latency: {stats['mean']:6.2f} ms | Median: {stats['median']:6.2f} ms | Wire: {avg_wire} B | Success: {success_rate:5.1f}%")

    return {
        "algo": "RSA-3072",
        "runs": runs,
        "success": successful_runs,
        "stats": stats,
        "server_crypto": s_crypto_stats['mean'],
        "wire_bytes": avg_wire,
        "success_rate": success_rate
    }


# ----------------------------------------------------
# Main Server Loop
# ----------------------------------------------------
def main():
    local_ip = get_local_ip()

    print("\n" + "=" * 94)
    print("      ESP32 Mutual Authentication Network Benchmark (Phase B: Over Wi-Fi Server)")
    print(f"Host: {local_ip}:{PORT} | Waiting for ESP32 connection...")
    print("=" * 94 + "\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    conn, addr = server.accept()
    print(f"[OK] ESP32 connected from {addr[0]}:{addr[1]}")
    conn.settimeout(15.0)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    results = []

    try:
        while True:
            # Read command from ESP32: [1 byte command] [1 byte run_count]
            cmd_data = recv_exact(conn, 2)
            if not cmd_data:
                break

            cmd, runs = struct.unpack("!BB", cmd_data)

            if cmd == 0x00:
                res = benchmark_null(conn, runs)
                if res: results.append(res)
            elif cmd == 0x01:
                res = benchmark_ed25519(conn, runs)
                if res: results.append(res)
            elif cmd == 0x02:
                res = benchmark_ecdsa(conn, runs)
                if res: results.append(res)
            elif cmd == 0x03:
                res = benchmark_rsa(conn, runs)
                if res: results.append(res)
            elif cmd == 0xFF:
                print("\n[OK] All benchmark suites completed successfully by ESP32!")
                break

        # Print Standardized Summary Comparison Table
        print("\n" + "=" * 98)
        print("                        BENCHMARK RESULTS SUMMARY (PHASE B: SERVER)                       ")
        print("=" * 98)
        print(f"{'KPI ID':<6} | {'Metric':<38} | {'NULL Ctrl':<10} | {'Ed25519':<10} | {'ECDSA P-256':<11} | {'RSA-3072':<10}")
        print("-------+----------------------------------------+------------+------------+-------------+-----------")

        res_map = {r['algo']: r for r in results}
        null_r = res_map.get("NULL Baseline", {})
        ed     = res_map.get("Ed25519", {})
        ec     = res_map.get("ECDSA P-256", {})
        rsa_r  = res_map.get("RSA-3072", {})

        def get_stat(d, k, fmt=".2f", suffix=" ms"):
            val = d.get('stats', {}).get(k, 0.0)
            return f"{val:{fmt}}{suffix}"

        print(f"{'NET-1':<6} | {'Total Handshake Latency (Mean)':<38} | {get_stat(null_r, 'mean'):>10} | {get_stat(ed, 'mean'):>10} | {get_stat(ec, 'mean'):>11} | {get_stat(rsa_r, 'mean'):>10}")
        print(f"{'     ':<6} | {'Total Handshake Latency (Median)':<38} | {get_stat(null_r, 'median'):>10} | {get_stat(ed, 'median'):>10} | {get_stat(ec, 'median'):>11} | {get_stat(rsa_r, 'median'):>10}")
        print(f"{'     ':<6} | {'Total Handshake Latency (StdDev σ)':<38} | {get_stat(null_r, 'stddev'):>10} | {get_stat(ed, 'stddev'):>10} | {get_stat(ec, 'stddev'):>11} | {get_stat(rsa_r, 'stddev'):>10}")
        print(f"{'NET-2':<6} | {'Handshake Wire Payload (Mean)':<38} | {null_r.get('wire_bytes', 0):8d} B | {ed.get('wire_bytes', 0):8d} B | {ec.get('wire_bytes', 0):9d} B | {rsa_r.get('wire_bytes', 0):8d} B")
        print(f"{'NET-4':<6} | {'Server Cryptographic Time (Mean)':<38} | {null_r.get('server_crypto', 0.0):7.2f} ms | {ed.get('server_crypto', 0.0):7.2f} ms | {ec.get('server_crypto', 0.0):8.2f} ms | {rsa_r.get('server_crypto', 0.0):7.2f} ms")
        print(f"{'NET-6':<6} | {'Handshake Success Rate':<38} | {null_r.get('success_rate', 0.0):7.1f} % | {ed.get('success_rate', 0.0):7.1f} % | {ec.get('success_rate', 0.0):8.1f} % | {rsa_r.get('success_rate', 0.0):7.1f} %")
        print("=" * 98 + "\n")

    except Exception as e:
        print(f"\n[ERROR] Connection interrupted: {e}")
    finally:
        conn.close()
        server.close()
        print("Benchmark session closed.")


if __name__ == "__main__":
    main()
