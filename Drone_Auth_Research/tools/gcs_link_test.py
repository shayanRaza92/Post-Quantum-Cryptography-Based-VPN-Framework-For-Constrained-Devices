#!/usr/bin/env python3
"""Ground station for Step 3 (E3): drone authentication over a real Wi-Fi link.

The ESP32 (the drone) runs the firmware in mode "W". This program, on the laptop:
  1. records every packet with dumpcap (the capture engine of Wireshark) into a .pcapng file;
  2. finds the drone (it broadcasts HELLO) and, for each algorithm, asks it for its public key;
  3. sends random challenges; the drone answers with [header | challenge, id, clock, data] +
     signature, for growing amounts of data and in two link styles:
       udp  one UDP datagram per message (the IP layer splits it if it does not fit one packet)
       mav  MAVLink-sized frames, at most 255 payload bytes each (like a drone radio link)
  4. verifies every signature (OpenSSL via 'cryptography' for the classical algorithms, our
     own ML-DSA build for ML-DSA), and writes one CSV line per authentication.

    python3 tools/gcs_link_test.py --iface wlo1
    python3 tools/gcs_link_test.py --iface wlo1 --runs 5          # quick test

Then:  python3 tools/analyze_link.py results/e3/raw/link_<date>_<time>
Message formats: firmware/sig_bench_unified/link_protocol.h.
"""
import argparse
import csv
import ctypes
import datetime as dt
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ROOT = Path(__file__).resolve().parents[1]
PORT = 47000
VERSION = 1
HDR, FHDR, MAV_PAYLOAD, MIN_DATA = 12, 10, 255, 56
UDP_MAX_ONE_PACKET = 1472           # 1500-byte Wi-Fi/Ethernet MTU - 20 (IPv4) - 8 (UDP)
HELLO, GETKEY, PUBKEY, CHALLENGE, AUTH, RESULT, STAT, DONE = range(1, 9)
ALGS = ["Ed25519", "ECDSA-P256", "RSA-3072", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
SIG_MAX = {"Ed25519": 64, "ECDSA-P256": 72, "RSA-3072": 384, "ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627}
PK_LEN = {"Ed25519": 32, "ECDSA-P256": 65, "RSA-3072": 384, "ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592}
BASE_SIZES = [64, 256, 1024, 4096, 8192]
STYLES = {"udp": 0, "mav": 1}


def header(mtype, alg, style, seq, dlen, slen):
    return bytes([ord("D"), ord("A"), VERSION, mtype, alg, style]) + seq.to_bytes(2, "big") + \
        dlen.to_bytes(2, "big") + slen.to_bytes(2, "big")


def parse_header(b):
    if len(b) < HDR or b[0:2] != b"DA" or b[2] != VERSION:
        return None
    return {"type": b[3], "alg": b[4], "style": b[5], "seq": int.from_bytes(b[6:8], "big"),
            "dlen": int.from_bytes(b[8:10], "big"), "slen": int.from_bytes(b[10:12], "big")}


def sizes_for(alg, style):
    """The base sizes plus, where possible, the largest data that fits one packet (B) and B + 1."""
    limit = UDP_MAX_ONE_PACKET if style == "udp" else MAV_PAYLOAD
    b = limit - HDR - SIG_MAX[alg]
    extra = [b, b + 1] if b >= MIN_DATA else []
    return sorted(set(BASE_SIZES + extra))


# ---- verifiers --------------------------------------------------------------------------
def build_mldsa_lib():
    """Our ML-DSA build (the same source as the firmware) as a shared library for ctypes."""
    out = ROOT / "tools" / "build" / "libdrone_mldsa.so"
    units = ROOT / "arduino_libraries" / "MLDSA_Levels" / "src"
    shim = ROOT / "tools" / "mldsa_vectors" / "shim"
    sources = [units / f"mldsa{lvl}_unit.c" for lvl in (44, 65, 87)] + [shim / "host_random.c"]
    if not out.exists() or any(s.stat().st_mtime > out.stat().st_mtime for s in sources):
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["gcc", "-O2", "-std=c99", "-D_DEFAULT_SOURCE", "-shared", "-fPIC", "-I", str(shim),
                        "-I", str(units), *map(str, sources), "-o", str(out)], check=True)
    return ctypes.CDLL(str(out))


class Verifier:
    def __init__(self, alg, pk, mldsa_lib):
        self.alg = alg
        if alg == "Ed25519":
            self.key = ed25519.Ed25519PublicKey.from_public_bytes(pk)
        elif alg == "ECDSA-P256":
            self.key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)
        elif alg == "RSA-3072":
            self.key = rsa.RSAPublicNumbers(65537, int.from_bytes(pk, "big")).public_key()
        else:
            self.pk = ctypes.create_string_buffer(pk, len(pk))
            self.fn = getattr(mldsa_lib, f"DRONE_MLDSA{alg[-2:]}_verify")

    def verify(self, msg, sig):
        try:
            if self.alg == "Ed25519":
                self.key.verify(sig, msg)
            elif self.alg == "ECDSA-P256":
                self.key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            elif self.alg == "RSA-3072":
                self.key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            else:
                return self.fn(sig, ctypes.c_size_t(len(sig)), msg, ctypes.c_size_t(len(msg)), None,
                               ctypes.c_size_t(0), self.pk) == 0
            return True
        except InvalidSignature:
            return False


# ---- receiving --------------------------------------------------------------------------
def receive_message(sock, want_type, seq, style, deadline):
    """Whole message (udp: one datagram; mav: all frames). Returns (bytes, frames) or (None, frames)."""
    frames, count = {}, None
    while time.monotonic() < deadline:
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        try:
            pkt, _ = sock.recvfrom(65535)
        except socket.timeout:
            break
        if style == 1 and pkt[0:2] == b"DF" and len(pkt) >= FHDR:
            if pkt[2] != want_type or int.from_bytes(pkt[4:6], "big") != seq:
                continue
            idx, count = pkt[6], pkt[7]
            n = int.from_bytes(pkt[8:10], "big")
            frames[idx] = pkt[FHDR:FHDR + n]
            if len(frames) == count:
                return b"".join(frames[i] for i in range(count)), count
        else:
            h = parse_header(pkt)
            if h and h["type"] == want_type and h["seq"] == seq:
                return pkt, 1
    return None, len(frames)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", default="wlo1", help="Wi-Fi interface to capture on (see: ip -br addr)")
    ap.add_argument("--runs", type=int, default=20, help="authentications per algorithm, style and size")
    ap.add_argument("--styles", default="udp,mav")
    ap.add_argument("--no-capture", action="store_true", help="do not start dumpcap")
    args = ap.parse_args()
    styles = [s for s in args.styles.split(",") if s in STYLES]

    power_save = "unknown"
    try:                                  # Wi-Fi power saving of the ground station delays replies
        info = subprocess.run(["iwconfig", args.iface], capture_output=True, text=True).stdout
        if "Power Management:" in info:
            power_save = info.split("Power Management:")[1].split()[0]
    except OSError:
        pass
    if power_save == "on":
        print(f"WARNING: Wi-Fi power saving is ON for {args.iface}. It delays answers that arrive after a pause.\n"
              f"         Switch it off first:  sudo iwconfig {args.iface} power off")
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = ROOT / "results" / "e3" / "raw" / f"link_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    mldsa = build_mldsa_lib()

    cap = None
    if not args.no_capture:
        if not shutil.which("dumpcap"):
            sys.exit("dumpcap not found. Install Wireshark, or run with --no-capture.")
        # Keep the later pieces of split (IP-fragmented) messages too: they carry no UDP header,
        # so "udp port" alone would drop them.
        cap = subprocess.Popen(["dumpcap", "-q", "-i", args.iface, "-f",
                                f"udp port {PORT} or (ip and (ip[6:2] & 0x1fff) != 0)",
                                "-w", str(out / "capture.pcapng")],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(2)
        if cap.poll() is not None:
            sys.exit("dumpcap stopped: " + cap.stderr.read().decode(errors="replace"))
        print(f"Capturing on {args.iface} -> {out / 'capture.pcapng'}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.bind(("0.0.0.0", PORT))

    print("Waiting for the drone's HELLO (ESP32 in mode W) ...")
    drone = None
    while drone is None:
        pkt, addr = sock.recvfrom(65535)
        h = parse_header(pkt)
        if h and h["type"] == HELLO:
            drone = addr                      # reply to the address and port the HELLO came from
            drone_id = pkt[HDR:HDR + 16].rstrip(b"\0").decode(errors="replace")
            n_algs = h["alg"]
    print(f"Drone '{drone_id}' at {drone[0]} ({n_algs} algorithms)")
    if n_algs != len(ALGS):
        sys.exit("The firmware must have all six algorithms built in.")

    meta = {"date": dt.datetime.now().isoformat(timespec="seconds"), "iface": args.iface, "drone_ip": drone[0],
            "drone_id": drone_id, "runs": args.runs, "styles": styles, "base_sizes": BASE_SIZES,
            "udp_max_one_packet": UDP_MAX_ONE_PACKET, "mav_payload": MAV_PAYLOAD, "gcs_wifi_power_save": power_save}
    rows, seq = [], 0
    started = time.time()
    for ai, alg in enumerate(ALGS):
        seq += 1
        sock.sendto(header(GETKEY, ai, 0, seq, 0, 0), drone)
        print(f"\n{alg}: asking for the public key (RSA key generation can take up to a minute) ...")
        pk_msg, _ = receive_message(sock, PUBKEY, seq, 0, time.monotonic() + 120)
        if pk_msg is None:
            print(f"  no public key received; {alg} skipped")
            continue
        h = parse_header(pk_msg)
        pk = pk_msg[HDR:HDR + h["slen"]]
        if len(pk) != PK_LEN[alg]:
            sys.exit(f"{alg}: public key has {len(pk)} bytes, expected {PK_LEN[alg]}")
        ver = Verifier(alg, pk, mldsa)
        for _ in range(3):           # warm-up exchanges after the key generation (not recorded)
            seq = (seq + 1) & 0xFFFF
            sock.sendto(header(CHALLENGE, ai, 0, seq, 64, 0) + os.urandom(32), drone)
            receive_message(sock, AUTH, seq, 0, time.monotonic() + 5)
            receive_message(sock, STAT, seq, 0, time.monotonic() + 1)
        for style in styles:
            st = STYLES[style]
            for dlen in sizes_for(alg, style):
                ok_count = lost = 0
                for rep in range(args.runs):
                    seq = (seq + 1) & 0xFFFF
                    nonce = os.urandom(32)
                    t_send = time.time()
                    t0 = time.perf_counter()
                    sock.sendto(header(CHALLENGE, ai, st, seq, dlen, 0) + nonce, drone)
                    msg, frames = receive_message(sock, AUTH, seq, st, time.monotonic() + 5)
                    t1 = time.perf_counter()
                    row = {"algorithm": alg, "style": style, "data_len": dlen, "rep": rep, "seq": seq,
                           "t_send_epoch": f"{t_send:.6f}", "lost": 1, "frames": frames}
                    if msg is not None:
                        mh = parse_header(msg)
                        data = msg[HDR:HDR + mh["dlen"]]
                        sig = msg[HDR + mh["dlen"]:HDR + mh["dlen"] + mh["slen"]]
                        signed = msg[:10] + b"\0\0" + data
                        tv0 = time.perf_counter()
                        ok = ver.verify(signed, sig)
                        tv1 = time.perf_counter()
                        fresh = data[:32] == nonce
                        sock.sendto(header(RESULT, ai, st, seq, 1, 0) + bytes([1 if ok and fresh else 0]), drone)
                        row.update({"lost": 0, "sig_len": mh["slen"], "message_len": len(msg),
                                    "auth_ok": int(ok), "challenge_ok": int(fresh),
                                    "rtt_ms": round((t1 - t0) * 1000, 3), "verify_ms": round((tv1 - tv0) * 1000, 3)})
                        stat, _ = receive_message(sock, STAT, seq, 0, time.monotonic() + 1)
                        if stat:
                            v = [int.from_bytes(stat[HDR + 4 * i:HDR + 4 * i + 4], "big") for i in range(4)]
                            row.update({"drone_sign_ms": v[0] / 1000, "drone_total_ms": v[1] / 1000,
                                        "drone_send_waits": v[2], "drone_free_heap": v[3]})
                        ok_count += int(ok and fresh)
                    else:
                        lost += 1
                    rows.append(row)
                    time.sleep(0.05)
                print(f"  {style:3s} data {dlen:5d} B: {ok_count}/{args.runs} verified, {lost} lost")
    for _ in range(3):
        seq = (seq + 1) & 0xFFFF
        sock.sendto(header(DONE, 0, 0, seq, 0, 0), drone)
        time.sleep(0.2)
    meta["seconds"] = round(time.time() - started, 1)

    cols = ["algorithm", "style", "data_len", "rep", "seq", "t_send_epoch", "lost", "frames", "sig_len",
            "message_len", "auth_ok", "challenge_ok", "rtt_ms", "verify_ms", "drone_sign_ms", "drone_total_ms",
            "drone_send_waits", "drone_free_heap"]
    with open(out / "gcs_log.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    try:
        meta["git_commit"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                            text=True).stdout.strip()
    except OSError:
        pass
    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    if cap:
        time.sleep(1)
        cap.terminate()
        cap.wait(timeout=10)
    print(f"\nDone in {meta['seconds']} s. Results in {out}")
    print(f"Next: python3 tools/analyze_link.py {out}")


if __name__ == "__main__":
    main()
