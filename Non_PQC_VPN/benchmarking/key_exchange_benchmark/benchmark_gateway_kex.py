#!/usr/bin/env python3
"""
Combined ESP32 <-> Gateway (Laptop) Key Exchange Benchmark Server
Evaluates pure Diffie-Hellman key exchange across 3 classical algorithms at ~128-bit security:
  - Suite 1 (0x01): X25519 (RFC 7748 Curve25519)          -> 32-byte key share
  - Suite 2 (0x02): ECDH P-256 (NIST secp256r1)           -> 65-byte key share
  - Suite 3 (0x03): DH-3072 (RFC 7919 ffdhe3072 safe prime)-> 384-byte key share

Protocol Flow per Trial (Pure Key Exchange Only — No Signatures):
  1. ESP32 times Client KeyGen (sk_C, pk_C) using hardware cycle counter.
  2. ESP32 -> Laptop [MSG 1]: [AlgID (1B) | pk_C (32B / 65B / 384B)]
  3. Laptop times Server KeyGen (sk_S, pk_S) and Server Derive (SS = DH(sk_S, pk_C)).
  4. Outside the timer, Laptop derives K_confirm via HMAC-SHA256("VPN-v1-KEX-SALT", SS)
     and computes a 16-byte confirmation MAC over ("VPN-v1|KEX-CONFIRM|" || pk_C || pk_S)
     (proper key separation — never exposing a raw hash of SS on the wire).
  5. Laptop -> ESP32 [MSG 2]: [pk_S (32B/65B/384B) | SrvKeyGen_us (4B) | SrvDerive_us (4B) | ConfirmTag (16B)]
  6. ESP32 times Client Derive (SS = DH(sk_C, pk_S)) and verifies ConfirmTag outside the timer.
"""

import sys
import socket
import struct
import time
import math
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519, ec, dh
from cryptography.hazmat.primitives import serialization

HOST = "0.0.0.0"
PORT = 9000

ALG_X25519    = 0x01
ALG_ECDH_P256 = 0x02
ALG_DH3072    = 0x03

KEX_SALT          = b"VPN-v1-KEX-SALT"
KEX_CONFIRM_LABEL = b"VPN-v1|KEX-CONFIRM|"

# RFC 7919 ffdhe3072 standardized safe prime (384 bytes / 3072 bits, g = 2)
FFDHE3072_P_HEX = (
    "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695"
    "a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a"
    "d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935"
    "984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a"
    "bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4"
    "ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61"
    "9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005"
    "c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b"
    "bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c"
    "aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff"
    "5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e"
    "0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff"
)
FFDHE3072_P_INT = int(FFDHE3072_P_HEX, 16)
DH3072_PARAM_NUMBERS = dh.DHParameterNumbers(FFDHE3072_P_INT, 2)
DH3072_PARAMS = DH3072_PARAM_NUMBERS.parameters()


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


def calculate_stats(data):
    if not data:
        return {"mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0, "stddev": 0.0}
    n = len(data)
    mean = sum(data) / n
    sorted_d = sorted(data)
    median = (sorted_d[n // 2 - 1] + sorted_d[n // 2]) / 2.0 if n % 2 == 0 else sorted_d[n // 2]
    stddev = math.sqrt(sum((x - mean) ** 2 for x in data) / (n - 1)) if n > 1 else 0.0
    return {
        "mean": mean,
        "median": median,
        "min": sorted_d[0],
        "max": sorted_d[-1],
        "stddev": stddev,
    }


def compute_kex_confirm_tag(shared_secret: bytes, cli_pk: bytes, srv_pk: bytes) -> bytes:
    """
    Derives a dedicated confirmation key K_confirm via HMAC-SHA256 (HKDF-Extract)
    and computes a 16-byte key confirmation tag over the exchanged public shares.
    Never exposes the raw shared secret or its direct hash on the wire.
    """
    k_confirm = hmac.new(KEX_SALT, shared_secret, hashlib.sha256).digest()
    tag = hmac.new(k_confirm, KEX_CONFIRM_LABEL + cli_pk + srv_pk, hashlib.sha256).digest()
    return tag[:16]


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
    return recv_exact(conn, length)


def send_msg(conn, payload: bytes):
    header = struct.pack("!H", len(payload))
    conn.sendall(header + payload)


# -------------------------------------------------------------------------
# Gateway Cryptographic Operations (Timed per Trial)
# -------------------------------------------------------------------------
def gateway_kex_x25519(cli_pk_bytes: bytes):
    t0 = time.perf_counter()
    srv_priv = x25519.X25519PrivateKey.generate()
    srv_pk_bytes = srv_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    t1 = time.perf_counter()

    cli_pub = x25519.X25519PublicKey.from_public_bytes(cli_pk_bytes)
    shared_secret = srv_priv.exchange(cli_pub)
    t2 = time.perf_counter()

    kg_us = int((t1 - t0) * 1_000_000)
    der_us = int((t2 - t1) * 1_000_000)
    return srv_pk_bytes, shared_secret, kg_us, der_us


def gateway_kex_ecdh_p256(cli_pk_bytes: bytes):
    t0 = time.perf_counter()
    srv_priv = ec.generate_private_key(ec.SECP256R1())
    srv_pk_bytes = srv_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    t1 = time.perf_counter()

    cli_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), cli_pk_bytes)
    shared_secret = srv_priv.exchange(ec.ECDH(), cli_pub)
    t2 = time.perf_counter()

    kg_us = int((t1 - t0) * 1_000_000)
    der_us = int((t2 - t1) * 1_000_000)
    return srv_pk_bytes, shared_secret, kg_us, der_us


def gateway_kex_dh3072(cli_pk_bytes: bytes):
    t0 = time.perf_counter()
    srv_priv = DH3072_PARAMS.generate_private_key()
    srv_y = srv_priv.public_key().public_numbers().y
    srv_pk_bytes = srv_y.to_bytes(384, "big")
    t1 = time.perf_counter()

    cli_y = int.from_bytes(cli_pk_bytes, "big")
    cli_pub = dh.DHPublicNumbers(cli_y, DH3072_PARAM_NUMBERS).public_key()
    shared_secret = srv_priv.exchange(cli_pub)
    t2 = time.perf_counter()

    kg_us = int((t1 - t0) * 1_000_000)
    der_us = int((t2 - t1) * 1_000_000)
    return srv_pk_bytes, shared_secret, kg_us, der_us


# -------------------------------------------------------------------------
# Standalone Gateway Self-Test (Runs on Startup)
# -------------------------------------------------------------------------
def run_gateway_selftest():
    print("=" * 78)
    print("      GATEWAY (LAPTOP) KEY EXCHANGE SELF-TEST & BASELINE TIMING")
    print("=" * 78)

    # X25519
    peer_x = x25519.X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    kg_x, der_x = [], []
    for _ in range(200):
        _, _, k_u, d_u = gateway_kex_x25519(peer_x)
        kg_x.append(k_u / 1000.0)
        der_x.append(d_u / 1000.0)

    # ECDH P-256
    peer_ec = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    kg_ec, der_ec = [], []
    for _ in range(200):
        _, _, k_u, d_u = gateway_kex_ecdh_p256(peer_ec)
        kg_ec.append(k_u / 1000.0)
        der_ec.append(d_u / 1000.0)

    # DH-3072
    peer_dh = DH3072_PARAMS.generate_private_key().public_key().public_numbers().y.to_bytes(384, "big")
    kg_dh, der_dh = [], []
    for _ in range(10):
        _, _, k_u, d_u = gateway_kex_dh3072(peer_dh)
        kg_dh.append(k_u / 1000.0)
        der_dh.append(d_u / 1000.0)

    mx_kg, mx_der = sum(kg_x) / len(kg_x), sum(der_x) / len(der_x)
    me_kg, me_der = sum(kg_ec) / len(kg_ec), sum(der_ec) / len(der_ec)
    md_kg, md_der = sum(kg_dh) / len(kg_dh), sum(der_dh) / len(der_dh)

    print(f"{'Algorithm':<14} | {'Share Size':<12} | {'KeyGen (ms)':<14} | {'Derive (ms)':<14} | {'Gateway Total (ms)':<18}")
    print("-" * 78)
    print(f"{'X25519':<14} | {'32 B':<12} | {mx_kg:<14.3f} | {mx_der:<14.3f} | {mx_kg + mx_der:<18.3f}")
    print(f"{'ECDH P-256':<14} | {'65 B':<12} | {me_kg:<14.3f} | {me_der:<14.3f} | {me_kg + me_der:<18.3f}")
    print(f"{'DH-3072':<14} | {'384 B':<12} | {md_kg:<14.3f} | {md_der:<14.3f} | {md_kg + md_der:<18.3f}")
    print("=" * 78 + "\n")


# -------------------------------------------------------------------------
# Live Combined ESP32 <-> Laptop Suite Runner
# -------------------------------------------------------------------------
SUITE_INFO = {
    ALG_X25519:    ("X25519 (Curve25519)", 32,  gateway_kex_x25519),
    ALG_ECDH_P256: ("ECDH P-256 (secp256r1)", 65,  gateway_kex_ecdh_p256),
    ALG_DH3072:    ("DH-3072 (RFC 7919)", 384, gateway_kex_dh3072),
}


def run_suite(conn, alg_id: int, runs: int):
    if alg_id not in SUITE_INFO:
        print(f"[ERROR] Unknown AlgID: 0x{alg_id:02X}")
        return None

    name, expected_share_len, kex_fn = SUITE_INFO[alg_id]
    print(f"\n>>> Benchmarking {name} ({runs} runs, Share={expected_share_len} B) <<<")

    kg_ms_list = []
    der_ms_list = []
    tot_ms_list = []
    rtt_ms_list = []
    success = 0

    for i in range(runs):
        t_trial_start = time.perf_counter()

        # MSG 1: [AlgID (1B) | cli_pk (expected_share_len B)]
        msg1 = recv_msg(conn)
        if not msg1 or len(msg1) != 1 + expected_share_len or msg1[0] != alg_id:
            print(f"  [!] Run {i+1}: Invalid MSG 1 (got {len(msg1) if msg1 else 0} B)")
            break

        cli_pk = msg1[1:]

        # Timed Gateway KeyGen + Derive
        try:
            srv_pk, shared_secret, kg_us, der_us = kex_fn(cli_pk)
        except Exception as e:
            print(f"  [!] Run {i+1}: Crypto error: {e}")
            break

        # Untimed Key Confirmation Tag (HKDF-Extract + HMAC-SHA256)
        confirm_tag = compute_kex_confirm_tag(shared_secret, cli_pk, srv_pk)

        # MSG 2: [srv_pk (32/65/384B) | SrvKeyGen_us (4B) | SrvDerive_us (4B) | ConfirmTag (16B)]
        msg2 = srv_pk + struct.pack("!II", kg_us, der_us) + confirm_tag
        send_msg(conn, msg2)

        t_trial_ms = (time.perf_counter() - t_trial_start) * 1000.0
        kg_ms = kg_us / 1000.0
        der_ms = der_us / 1000.0

        kg_ms_list.append(kg_ms)
        der_ms_list.append(der_ms)
        tot_ms_list.append(kg_ms + der_ms)
        rtt_ms_list.append(t_trial_ms)
        success += 1

        if (i + 1) % 10 == 0 or (i + 1) == runs:
            print(
                f"  - Run {i+1:3d}/{runs} | Srv KeyGen: {kg_ms:6.3f} ms | "
                f"Srv Derive: {der_ms:6.3f} ms | Srv Total: {kg_ms + der_ms:6.3f} ms"
            )

    return {
        "name": name,
        "share_bytes": expected_share_len,
        "runs": runs,
        "success": success,
        "kg": calculate_stats(kg_ms_list),
        "der": calculate_stats(der_ms_list),
        "tot": calculate_stats(tot_ms_list),
    }


def print_server_summary(results):
    if not results:
        return
    print("\n" + "=" * 86)
    print("         GATEWAY-SIDE KEY EXCHANGE SUMMARY (MEASURED DURING LIVE ESP32 RUNS)")
    print("=" * 86)
    print(
        f"{'Algorithm':<24} | {'Share':<7} | {'Srv KeyGen':<13} | "
        f"{'Srv Derive':<13} | {'Srv Total':<13} | {'Status'}"
    )
    print("-" * 86)
    for r in results:
        status = f"{r['success']}/{r['runs']} OK"
        print(
            f"{r['name']:<24} | {r['share_bytes']:>4} B  | "
            f"{r['kg']['mean']:>9.3f} ms | {r['der']['mean']:>9.3f} ms | "
            f"{r['tot']['mean']:>9.3f} ms | {status}"
        )
    print("=" * 86 + "\n")


def main():
    run_gateway_selftest()
    if "--local-only" in sys.argv:
        return

    local_ip = get_local_ip()
    print("=" * 78)
    print("   COMBINED ESP32 <-> LAPTOP KEY EXCHANGE BENCHMARK SERVER (LIVE WI-FI)")
    print("=" * 78)
    print(f"  Listening on : {HOST}:{PORT}")
    print(f"  Laptop Wi-Fi : {local_ip}  <-- Set LAPTOP_IP to this in your ESP32 sketch")
    print("=" * 78)
    print("Waiting for ESP32 benchmark client to connect...\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)

        while True:
            conn, addr = srv.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(30.0)
            print(f"[+] Connected to ESP32 at {addr[0]}:{addr[1]}")

            results = []
            try:
                while True:
                    # Each suite starts with a 2-byte header: [AlgID (1B), Runs (1B)]
                    cmd = recv_exact(conn, 2)
                    if not cmd:
                        break
                    alg_id, runs = cmd[0], cmd[1]
                    if alg_id == 0xFF:
                        print("\n[+] ESP32 signalled benchmark completion.")
                        break
                    res = run_suite(conn, alg_id, runs)
                    if res:
                        results.append(res)
            except Exception as e:
                print(f"[!] Connection error: {e}")
            finally:
                conn.close()
                print_server_summary(results)
                print("Waiting for next ESP32 connection (or press Ctrl+C to exit)...\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServer stopped.")
