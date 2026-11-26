#!/usr/bin/env python3
"""
Demo 2: "Harvest now, decrypt later" against our CLASSICAL VPN, at toy size, with Shor's algorithm.

    .venv/bin/python scripts/run_harvest_now_decrypt_later.py

Story:
  1. TODAY. An ESP32 and the gateway run our classical VPN handshake (MSG 1-4) and send encrypted
     messages. An attacker only RECORDS the Wi-Fi traffic. The messages are unreadable.
  2. LATER, with a quantum computer. The attacker runs Shor's algorithm on the ESP32's one-time
     public key from MSG 1, gets its private key, recomputes the shared secret, and decrypts every
     recorded message.

What is real and what is toy:
  * REAL: the message formats (82 / 128 / 96 / 40 bytes), Ed25519 signatures, the key derivation
    (HKDF), the key-confirmation tags, the SA binding (handshake hash TH) and the AES-256-GCM tunnel.
    They are imported unchanged (read-only) from Non_PQC_VPN/laptop_server/.
  * TOY: the key exchange. Real X25519 uses Curve25519 (a 255-bit prime); here the same kind of
    elliptic-curve Diffie-Hellman runs on a curve over p = 13, so Shor fits in ~19 simulated qubits.
    The 32-byte key-share fields carry the toy point.
Writes results/recorded_toy_session.json, results/harvest_now_decrypt_later.txt, results/fig_shor_ecdlp.png.
"""
import json
import os
import secrets
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "Non_PQC_VPN" / "laptop_server"))   # the classical VPN (read-only use)

from cryptography.hazmat.primitives.asymmetric import ed25519      # noqa: E402

import config as vpn_config                                       # noqa: E402
from crypto_engine import GatewayCrypto as G                      # noqa: E402
from secure_tunnel import SecureTunnel, handshake_hash            # noqa: E402
from qshor import ToyCurve, human_bytes, shor_ecdlp, statevector_bytes  # noqa: E402

OUT = HERE.parent / "results"
SHOTS = 1024


def raw_pk(private_key) -> bytes:
    return private_key.public_key().public_bytes_raw()


def point_field(curve, P) -> bytes:
    """The 32-byte key-share field of MSG 1 / MSG 2, carrying the toy point (real X25519: 32-byte u)."""
    return curve.encode(P).to_bytes(32, "big")


def field_point(curve, field: bytes):
    return curve.decode(int.from_bytes(field, "big"))


# ============================================================================ 1. TODAY: a real session
def victim_session(curve, G_pt):
    r = curve.order
    device_key, gateway_key = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()

    # MSG 1: [ver][alg][device id 16][N_cli 32][client key share 32] = 82 bytes
    a_cli = secrets.randbelow(r - 1) + 1                      # ESP32's one-time private key (secret)
    A = curve.mul(a_cli, G_pt)
    n_cli = os.urandom(32)
    msg1 = (bytes([vpn_config.PROTOCOL_VERSION, vpn_config.ALGORITHM_ID]) + b"esp32-01".ljust(16, b"\0")
            + n_cli + point_field(curve, A))

    # MSG 2: [N_srv 32][gateway key share 32][Ed25519 signature 64] = 128 bytes
    b_srv = secrets.randbelow(r - 1) + 1                      # gateway's one-time private key (secret)
    B = curve.mul(b_srv, G_pt)
    n_srv = os.urandom(32)
    b_field = point_field(curve, B)
    msg2 = n_srv + b_field + gateway_key.sign(G.build_server_transcript(msg1, n_srv, b_field))

    # Both sides: shared secret -> K_confirm, K_session (the real HKDF of our VPN)
    shared = point_field(curve, curve.mul(a_cli, B))
    assert shared == point_field(curve, curve.mul(b_srv, A))
    k_confirm, k_session = G.derive_session_keys(shared, n_cli, n_srv)

    # MSG 3 and MSG 4 with signatures and key-confirmation tags (real code)
    h_cli = G.build_client_transcript(msg1, msg2)
    msg3 = device_key.sign(h_cli) + G.compute_confirmation_tag(k_confirm, vpn_config.CLIENT_CONFIRM_LABEL, h_cli)
    msg4 = vpn_config.AUTH_OK_TOKEN + G.compute_confirmation_tag(k_confirm, vpn_config.SERVER_CONFIRM_LABEL, h_cli)

    # SA bound to this handshake, then encrypted messages (real tunnel code)
    th = handshake_hash(msg1, msg2, msg3, msg4, raw_pk(device_key), raw_pk(gateway_key))
    esp32, gateway = SecureTunnel(k_session, th, role="client"), SecureTunnel(k_session, th, role="server")
    secret_messages = [b"[esp32-01] GPS 33.6844N 73.0479E, altitude 120 m",
                       b"[esp32-01] mission: inspect pipeline sector 7, return at 16:40",
                       b"[esp32-01] battery 81%, camera recording ON"]
    frames = [esp32.seal(m) for m in secret_messages]
    for f, m in zip(frames, secret_messages):                # the real gateway accepts them
        assert [p for *_, p in gateway.feed(f)] == [m]

    recording = {   # everything an eavesdropper on the Wi-Fi gets (+ the two PUBLIC identity keys)
        "note": "Toy-size recording of a classical-VPN session (curve over p=13 instead of Curve25519).",
        "msg1": msg1.hex(), "msg2": msg2.hex(), "msg3": msg3.hex(), "msg4": msg4.hex(),
        "encrypted_frames": [f.hex() for f in frames],
        "device_public_key": raw_pk(device_key).hex(), "gateway_public_key": raw_pk(gateway_key).hex(),
        "curve": {"p": curve.p, "a": curve.a, "b": curve.b, "order": curve.order, "G": list(G_pt)},
    }
    return recording, a_cli, secret_messages


# ============================================================================ 2. LATER: the attack
def attacker(recording, curve, G_pt, t):
    msg1, msg2, msg3, msg4 = (bytes.fromhex(recording[k]) for k in ("msg1", "msg2", "msg3", "msg4"))
    frames = [bytes.fromhex(f) for f in recording["encrypted_frames"]]
    A = field_point(curve, msg1[50:82])                     # ESP32's public key share, from MSG 1
    B_field = msg2[32:64]

    t0 = time.perf_counter()
    k, nq, counts, success = shor_ecdlp(curve, G_pt, A, t, SHOTS)   # Shor: A = k*G  ->  k
    secs = time.perf_counter() - t0
    if k is None:
        return None, nq, counts, success, secs, []

    shared = point_field(curve, curve.mul(k, field_point(curve, B_field)))
    _, k_session = G.derive_session_keys(shared, msg1[18:50], msg2[0:32])
    th = handshake_hash(msg1, msg2, msg3, msg4, bytes.fromhex(recording["device_public_key"]),
                        bytes.fromhex(recording["gateway_public_key"]))
    tunnel = SecureTunnel(k_session, th, role="server")      # the attacker rebuilds the same SA
    plain = [p for f in frames for *_, p in tunnel.feed(f)]
    return k, nq, counts, success, secs, plain


def main():
    OUT.mkdir(exist_ok=True)
    curve = ToyCurve.find(13)
    G_pt = curve.points[1]                                  # prime order: any point except O generates
    t = (curve.order - 1).bit_length() + 2                  # bits per exponent register (+2 for precision)

    recording, true_k, secret_messages = victim_session(curve, G_pt)
    (OUT / "recorded_toy_session.json").write_text(json.dumps(recording, indent=2))

    out = ["Harvest now, decrypt later - toy-size attack on our CLASSICAL VPN", "=" * 66,
           f"Toy curve: y^2 = x^3 + {curve.a}x + {curve.b} over F_{curve.p}, {curve.order} points "
           f"(Curve25519 has about 2^252)",
           "", "1) TODAY - the attacker only records the Wi-Fi traffic:",
           f"   MSG 1-4 recorded ({len(bytes.fromhex(recording['msg1']))} / {len(bytes.fromhex(recording['msg2']))} / "
           f"{len(bytes.fromhex(recording['msg3']))} / {len(bytes.fromhex(recording['msg4']))} bytes, real format)",
           f"   {len(recording['encrypted_frames'])} encrypted frames, e.g. "
           f"{recording['encrypted_frames'][0][:48]}...  (unreadable)", "",
           "2) LATER - the attacker has a quantum computer and runs Shor's algorithm on the",
           "   ESP32's one-time public key from MSG 1:"]

    k, nq, counts, success, secs, plain = attacker(recording, curve, G_pt, t)
    out += [f"   qubits = {nq} ({t} + {t} exponent qubits + {curve.enc_bits} point qubits), "
            f"state memory = {human_bytes(statevector_bytes(nq))}, simulation {secs:.1f} s",
            f"   private key found: k = {k}   (true value {true_k})   "
            f"[{100 * success:.0f}% of shots gave the right key]", ""]
    if plain == secret_messages:
        out += ["3) The attacker recomputes the shared secret, K_session and the SA (TH is built only",
                "   from recorded messages and PUBLIC keys), and decrypts every recorded message:"]
        out += [f"   -> {m.decode()}" for m in plain]
        out += ["", "RESULT: the classical VPN's recorded traffic is fully decrypted once its key exchange",
                "(elliptic-curve Diffie-Hellman, like X25519) is broken by Shor's algorithm.",
                "Signatures, HKDF, SA binding and AES-256-GCM do not help: they all depend on the",
                "shared secret that Shor recovers.", "",
                "Our PQC VPN uses ML-KEM-512 for this step instead: see run_pqc_vs_shor.py."]
    else:
        out += ["Attack did not succeed in this run (try again; Shor is probabilistic)."]
    text = "\n".join(out)
    print(text)
    (OUT / "harvest_now_decrypt_later.txt").write_text(text + "\n")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    M = 2 ** t
    grid = np.zeros((M, M))
    for bits, n in counts.items():
        v = int(bits, 2)
        grid[v >> t, v & (M - 1)] += n / SHOTS
    fig, ax = plt.subplots(figsize=(4.2, 3.6))
    im = ax.imshow(grid, origin="lower", cmap="Blues", interpolation="nearest")
    ax.set_xlabel("register a (measured)", fontsize=8)
    ax.set_ylabel("register b (measured)", fontsize=8)
    ax.set_title(f"Shor for the elliptic-curve discrete log ({nq} qubits)\n"
                 "the regular pattern of peaks reveals the private key", fontsize=8)
    ax.tick_params(labelsize=7)
    fig.colorbar(im, ax=ax, fraction=0.046).ax.tick_params(labelsize=7)
    fig.tight_layout()
    fig.savefig(OUT / "fig_shor_ecdlp.png", dpi=200)
    print(f"\nSaved results/recorded_toy_session.json, results/harvest_now_decrypt_later.txt, "
          f"results/fig_shor_ecdlp.png")


if __name__ == "__main__":
    main()
