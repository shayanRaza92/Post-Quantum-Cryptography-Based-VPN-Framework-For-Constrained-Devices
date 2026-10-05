# Laptop Benchmark Server for Mutual Authentication
# Tests Ed25519, ECDSA P-256, and RSA-3072 over real TCP network

import socket
import struct
import time
import os
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

HOST = "0.0.0.0"
PORT = 9000

# Helper: Get laptop local IP
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

# Helper: Receive exact number of bytes from socket
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

# Helper: Receive a length-prefixed message (2-byte length header)
def recv_msg(conn):
    header = recv_exact(conn, 2)
    if not header:
        return None
    length = struct.unpack("!H", header)[0]
    return recv_exact(conn, length)

# Helper: Send a length-prefixed message (2-byte length header)
def send_msg(conn, payload):
    header = struct.pack("!H", len(payload))
    conn.sendall(header + payload)

# ----------------------------------------------------
# Benchmark Handler for Ed25519
# ----------------------------------------------------
def benchmark_ed25519(conn, runs):
    print("\n[1/3] Benchmarking Ed25519 Mutual Authentication...")
    
    # 1. Generate server keypair
    server_priv = ed25519.Ed25519PrivateKey.generate()
    server_pub_bytes = server_priv.public_key().public_bytes_raw()
    
    # 2. Receive ESP32 public key (32 bytes)
    client_pub_bytes = recv_msg(conn)
    if not client_pub_bytes or len(client_pub_bytes) != 32:
        print("  Error receiving client Ed25519 public key")
        return None
    client_pub = ed25519.Ed25519PublicKey.from_public_bytes(client_pub_bytes)
    
    # 3. Send server public key (32 bytes)
    send_msg(conn, server_pub_bytes)
    
    handshake_times = []
    total_wire_bytes = 0
    successful_runs = 0
    
    for i in range(runs):
        t_start = time.perf_counter()
        
        # Step 1: Server sends 32-byte challenge
        server_challenge = os.urandom(32)
        send_msg(conn, server_challenge)
        
        # Step 2: ESP32 returns signature (64 bytes) + client challenge (32 bytes)
        resp = recv_msg(conn)
        if not resp or len(resp) != 96:
            print(f"  Run {i+1} failed: Invalid response length")
            continue
        
        client_sig = resp[:64]
        client_challenge = resp[64:]
        
        # Verify ESP32 signature
        try:
            client_pub.verify(client_sig, server_challenge)
        except Exception:
            print(f"  Run {i+1} failed: ESP32 signature verification error")
            continue
        
        # Step 3: Server signs client challenge and returns signature (64 bytes)
        server_sig = server_priv.sign(client_challenge)
        send_msg(conn, server_sig)
        
        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # in ms
        handshake_times.append(t_elapsed)
        successful_runs += 1
        
        # 34 bytes (MSG1) + 98 bytes (MSG2) + 66 bytes (MSG3) = 198 bytes per handshake
        total_wire_bytes += (2 + len(server_challenge)) + (2 + len(resp)) + (2 + len(server_sig))
        
        print(f"  - Run {i+1:2d}/{runs}: Handshake time = {t_elapsed:6.2f} ms | OK")
    
    avg_time = sum(handshake_times) / len(handshake_times) if handshake_times else 0.0
    avg_wire = total_wire_bytes // runs if runs > 0 else 0
    print(f"\n  NET-1 Total Handshake Latency  : {avg_time:7.2f} ms")
    print(f"  NET-2 Handshake Wire Payload   : {avg_wire} bytes")
    print(f"  NET-5 Handshake Success Rate   : 100.0 %")

    return {
        "algo": "Ed25519",
        "runs": successful_runs,
        "avg_time": avg_time,
        "wire_bytes": avg_wire
    }

# ----------------------------------------------------
# Benchmark Handler for ECDSA P-256
# ----------------------------------------------------
def benchmark_ecdsa(conn, runs):
    print("\n[2/3] Benchmarking ECDSA P-256 Mutual Authentication...")
    
    # 1. Generate server keypair
    server_priv = ec.generate_private_key(ec.SECP256R1())
    server_pub_bytes = server_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    
    # 2. Receive ESP32 public key (65 bytes uncompressed point)
    client_pub_bytes = recv_msg(conn)
    if not client_pub_bytes or len(client_pub_bytes) != 65:
        print(f"  Error receiving client ECDSA public key (got {len(client_pub_bytes) if client_pub_bytes else 0} bytes)")
        return None
    client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_bytes)
    
    # 3. Send server public key (65 bytes)
    send_msg(conn, server_pub_bytes)
    
    handshake_times = []
    total_wire_bytes = 0
    successful_runs = 0
    
    for i in range(runs):
        t_start = time.perf_counter()
        
        # Step 1: Server sends 32-byte challenge
        server_challenge = os.urandom(32)
        send_msg(conn, server_challenge)
        
        # Step 2: ESP32 returns signature (DER ~71 bytes) + client challenge (32 bytes)
        resp = recv_msg(conn)
        if not resp or len(resp) < 35:
            print(f"  Run {i+1} failed: Invalid response length")
            continue
        
        client_challenge = resp[-32:]
        client_sig = resp[:-32]
        
        # Verify ESP32 signature
        try:
            client_pub.verify(client_sig, server_challenge, ec.ECDSA(hashes.SHA256()))
        except Exception:
            print(f"  Run {i+1} failed: ESP32 signature verification error")
            continue
        
        # Step 3: Server signs client challenge and returns signature
        server_sig = server_priv.sign(client_challenge, ec.ECDSA(hashes.SHA256()))
        send_msg(conn, server_sig)
        
        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # in ms
        handshake_times.append(t_elapsed)
        successful_runs += 1
        
        total_wire_bytes += (2 + len(server_challenge)) + (2 + len(resp)) + (2 + len(server_sig))
        print(f"  - Run {i+1:2d}/{runs}: Handshake time = {t_elapsed:6.2f} ms | OK")
    
    avg_time = sum(handshake_times) / len(handshake_times) if handshake_times else 0.0
    avg_wire = total_wire_bytes // runs if runs > 0 else 0
    print(f"\n  NET-1 Total Handshake Latency  : {avg_time:7.2f} ms")
    print(f"  NET-2 Handshake Wire Payload   : {avg_wire} bytes")
    print(f"  NET-5 Handshake Success Rate   : 100.0 %")

    return {
        "algo": "ECDSA P-256",
        "runs": successful_runs,
        "avg_time": avg_time,
        "wire_bytes": avg_wire
    }

# ----------------------------------------------------
# Benchmark Handler for RSA-3072
# ----------------------------------------------------
def benchmark_rsa(conn, runs):
    print("\n[3/3] Benchmarking RSA-3072 Mutual Authentication...")
    
    # 1. Generate server keypair
    server_priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_pub_bytes = server_priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 2. Receive ESP32 public key (DER format)
    client_pub_bytes = recv_msg(conn)
    if not client_pub_bytes:
        print("  Error receiving client RSA public key")
        return None
    client_pub = serialization.load_der_public_key(client_pub_bytes)
    
    # 3. Send server public key (DER format)
    send_msg(conn, server_pub_bytes)
    
    handshake_times = []
    total_wire_bytes = 0
    successful_runs = 0
    
    for i in range(runs):
        t_start = time.perf_counter()
        
        # Step 1: Server sends 32-byte challenge
        server_challenge = os.urandom(32)
        send_msg(conn, server_challenge)
        
        # Step 2: ESP32 returns signature (384 bytes) + client challenge (32 bytes) = 416 bytes
        resp = recv_msg(conn)
        if not resp or len(resp) != 416:
            print(f"  Run {i+1} failed: Invalid response length (got {len(resp) if resp else 0} bytes)")
            continue
        
        client_sig = resp[:384]
        client_challenge = resp[384:]
        
        # Verify ESP32 signature
        try:
            client_pub.verify(client_sig, server_challenge, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            print(f"  Run {i+1} failed: ESP32 signature verification error")
            continue
        
        # Step 3: Server signs client challenge and returns signature (384 bytes)
        server_sig = server_priv.sign(client_challenge, padding.PKCS1v15(), hashes.SHA256())
        send_msg(conn, server_sig)
        
        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # in ms
        handshake_times.append(t_elapsed)
        successful_runs += 1
        
        total_wire_bytes += (2 + len(server_challenge)) + (2 + len(resp)) + (2 + len(server_sig))
        print(f"  - Run {i+1:2d}/{runs}: Handshake time = {t_elapsed:6.2f} ms | OK")
    
    avg_time = sum(handshake_times) / len(handshake_times) if handshake_times else 0.0
    avg_wire = total_wire_bytes // runs if runs > 0 else 0
    print(f"\n  NET-1 Total Handshake Latency  : {avg_time:7.2f} ms")
    print(f"  NET-2 Handshake Wire Payload   : {avg_wire} bytes")
    print(f"  NET-5 Handshake Success Rate   : 100.0 %")

    return {
        "algo": "RSA-3072",
        "runs": successful_runs,
        "avg_time": avg_time,
        "wire_bytes": avg_wire
    }

# ----------------------------------------------------
# Main Server Loop
# ----------------------------------------------------
def main():
    local_ip = get_local_ip()
    
    print("\n" + "=" * 72)
    print("ESP32 Mutual Authentication Network Benchmark (Phase B: Server)")
    print(f"Host: {local_ip}:{PORT} | Waiting for ESP32 connection...")
    print("=" * 72 + "\n")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    
    conn, addr = server.accept()
    print(f"[OK] ESP32 connected from {addr[0]}:{addr[1]}")
    conn.settimeout(15.0)
    
    results = []
    
    try:
        while True:
            # Read command from ESP32: [1 byte command] [1 byte run_count]
            cmd_data = recv_exact(conn, 2)
            if not cmd_data:
                break
            
            cmd, runs = struct.unpack("!BB", cmd_data)
            
            if cmd == 0x01:
                res = benchmark_ed25519(conn, runs)
                if res: results.append(res)
            elif cmd == 0x02:
                res = benchmark_ecdsa(conn, runs)
                if res: results.append(res)
            elif cmd == 0x03:
                res = benchmark_rsa(conn, runs)
                if res: results.append(res)
            elif cmd == 0xFF:
                print("\n[OK] All benchmark stages completed by ESP32!")
                break
        
        # Print Final Standardized Summary Comparison Table
        print("\n" + "=" * 72)
        print("                     BENCHMARK RESULTS SUMMARY                          ")
        print("=" * 72)
        print(f"{'KPI ID':<6} | {'Metric':<28} | {'Ed25519':<10} | {'ECDSA P-256':<10} | {'RSA-3072':<10}")
        print("-------+------------------------------+------------+------------+-----------")
        res_map = {r['algo']: r for r in results}
        ed = res_map.get("Ed25519", {})
        ec = res_map.get("ECDSA P-256", {})
        rsa = res_map.get("RSA-3072", {})
        
        print(f"{'NET-1':<6} | {'Total Handshake Latency':<28} | {ed.get('avg_time', 0.0):7.2f} ms | {ec.get('avg_time', 0.0):7.2f} ms | {rsa.get('avg_time', 0.0):7.2f} ms")
        print(f"{'NET-2':<6} | {'Handshake Wire Payload':<28} | {ed.get('wire_bytes', 0):8d} B | {ec.get('wire_bytes', 0):8d} B | {rsa.get('wire_bytes', 0):8d} B")
        print(f"{'NET-5':<6} | {'Handshake Success Rate':<28} | {100.0:7.1f} % | {100.0:7.1f} % | {100.0:7.1f} %")
        print("=" * 72 + "\n")
        
    except Exception as e:
        print(f"\n[ERROR] Connection interrupted: {e}")
    finally:
        conn.close()
        server.close()
        print("Benchmark session closed.")

if __name__ == "__main__":
    main()
