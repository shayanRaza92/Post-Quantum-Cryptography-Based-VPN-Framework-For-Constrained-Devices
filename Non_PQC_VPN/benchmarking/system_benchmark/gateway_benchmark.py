#!/usr/bin/env python3
"""
System benchmark of the VPN gateway (laptop side). The same file is used in Non_PQC_VPN and
PQC_VPN; it detects which VPN it belongs to from laptop_server/config.py (ALGORITHM_ID).

  python3 gateway_benchmark.py            Laptop-side measurements (L0-L6), saved to results/
  python3 gateway_benchmark.py --serve    Real gateway (quiet) + plain TCP echo on port 9001,
                                          for the ESP32 benchmark (BENCHMARK_MODE 1 in config.h)

Laptop-side measurements use simulated ESP32 clients that speak exactly the same protocol as
esp32_client/ (handshake, AES-256-GCM tunnel, rekey) against the real gateway code. Each simulated
device connects from its own loopback address (127.0.0.x, Linux), like real ESP32s on Wi-Fi.
"""
import argparse
import csv
import ctypes
import json
import os
import socket
import statistics
import struct
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ["VPN_QUIET"] = "1"   # Session threads print nothing: terminal output would distort the timings
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "laptop_server"))

import config                                   # noqa: E402
import console                                  # noqa: E402
import crypto_engine                            # noqa: E402
import secure_tunnel                            # noqa: E402
import server                                   # noqa: E402
import tunnel_session                           # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # noqa: E402

IS_PQC = config.ALGORITHM_ID == 0x03
VPN_NAME = ("PQC VPN (ML-DSA-44 + ML-KEM-512 + AES-256-GCM)" if IS_PQC
            else "Classical VPN (Ed25519 + X25519 + AES-256-GCM)")
G = crypto_engine.GatewayCrypto
HANDSHAKE_BYTES = (config.MSG1_CLIENT_HELLO_SIZE + config.MSG2_SERVER_PROOF_SIZE +
                   config.MSG3_CLIENT_PROOF_SIZE + config.MSG4_AUTH_VERDICT_SIZE)
RESULTS = []


# =============================================================================== reporting
def record(test_id, metric, values, unit):
    values = list(values)
    p95 = statistics.quantiles(values, n=20, method="inclusive")[18] if len(values) > 1 else (values[0] if values else 0.0)
    row = dict(id=test_id, metric=metric, n=len(values), unit=unit,
               mean=statistics.fmean(values) if values else 0.0,
               median=statistics.median(values) if values else 0.0, p95=p95,
               std=statistics.stdev(values) if len(values) > 1 else 0.0,
               min=min(values) if values else 0.0, max=max(values) if values else 0.0)
    RESULTS.append(row)
    if row["n"] > 1:
        print(f"  {test_id:<4} {metric:<44} n={row['n']:<5} mean={row['mean']:9.4f} median={row['median']:9.4f}"
              f" p95={row['p95']:9.4f} std={row['std']:8.4f} min={row['min']:9.4f} max={row['max']:9.4f} {unit}")
    else:
        print(f"  {test_id:<4} {metric:<46} {row['mean']:14.4f} {unit}")


def section(title):
    print("\n" + "-" * 100 + f"\n{title}\n" + "-" * 100)


WARMUP_RUNS = 50   # Untimed runs first: CPU frequency ramp-up and first-call costs would distort the timings


def timed_ms(fn, runs):
    for _ in range(WARMUP_RUNS):
        fn()
    out = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000)
    return out


# =============================================================================== device keys + clients
if IS_PQC:
    _DSA, _KEM = crypto_engine._MLDSA_LIB, crypto_engine._MLKEM_LIB
    _KEM.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand.argtypes = [ctypes.c_char_p] * 3
    _KEM.PQCP_MLKEM_NATIVE_MLKEM512_dec.argtypes = [ctypes.c_char_p] * 3

    class DeviceKey:
        def __init__(self, secret=None):
            self.secret = secret or os.urandom(32)       # 32-byte ML-DSA-44 seed
            self._id = G(self.secret.hex())             # Same deterministic keygen as the ESP32
            self.public = self._id.public_bytes

        def sign(self, digest):
            sig, n = ctypes.create_string_buffer(config.SIGNATURE_LENGTH), ctypes.c_size_t()
            if _DSA.PQCP_MLDSA_NATIVE_MLDSA44_signature(sig, ctypes.byref(n), digest, len(digest),
                                                        None, 0, self._id._secret_bytes) != 0:
                raise RuntimeError("ML-DSA-44 signing failed")
            return sig.raw

    def kex_start():
        """Client side of the ephemeral key exchange: returns (key share to send, finish(peer data) -> SS)."""
        ek, dk = ctypes.create_string_buffer(800), ctypes.create_string_buffer(1632)
        _KEM.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand(ek, dk, os.urandom(64))

        def finish(ct):
            ss = ctypes.create_string_buffer(32)
            _KEM.PQCP_MLKEM_NATIVE_MLKEM512_dec(ss, ct, dk)
            return ss.raw
        return ek.raw, finish

    def verify_server(sig, digest, gateway_pk):
        return _DSA.PQCP_MLDSA_NATIVE_MLDSA44_verify(sig, len(sig), digest, len(digest), None, 0, gateway_pk) == 0

    def parse_msg2(m2):   # [N_srv 32][ct 768][sig 2420]
        return m2[:32], m2[32:800], m2[800:]
else:
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

    class DeviceKey:
        def __init__(self, secret=None):
            self._sk = (ed25519.Ed25519PrivateKey.from_private_bytes(secret) if secret
                        else ed25519.Ed25519PrivateKey.generate())
            self.secret = self._sk.private_bytes_raw()
            self.public = self._sk.public_key().public_bytes_raw()

        def sign(self, digest):
            return self._sk.sign(digest)

    def kex_start():
        sk = x25519.X25519PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), lambda peer: sk.exchange(x25519.X25519PublicKey.from_public_bytes(peer))

    def verify_server(sig, digest, gateway_pk):
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(gateway_pk).verify(sig, digest)
            return True
        except Exception:
            return False

    def parse_msg2(m2):   # [N_srv 32][PK_srv_eph 32][sig 64]
        return m2[:32], m2[32:64], m2[64:]


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


class SimClient:
    """A simulated ESP32: same handshake, tunnel framing and rekey as esp32_client/."""

    def __init__(self, port, device_id, key, src_ip, gateway_pk):
        self.device_id, self.key = device_id, key
        t0 = time.perf_counter()
        self.sock = socket.socket()
        self.sock.bind((src_ip, 0))
        self.sock.settimeout(10)
        self.sock.connect(("127.0.0.1", port))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        share, finish = kex_start()
        n_cli = os.urandom(32)
        m1 = bytes([config.PROTOCOL_VERSION, config.ALGORITHM_ID]) + device_id.encode().ljust(16, b"\0") + n_cli + share
        self.sock.sendall(m1)
        m2 = recv_exact(self.sock, config.MSG2_SERVER_PROOF_SIZE)
        n_srv, server_share, sig = parse_msg2(m2)
        if not verify_server(sig, G.build_server_transcript(m1, n_srv, server_share), gateway_pk):
            raise RuntimeError("gateway signature invalid")
        k_confirm, k_session = G.derive_session_keys(finish(server_share), n_cli, n_srv)
        h_cli = G.build_client_transcript(m1, m2)
        tag = G.compute_confirmation_tag(k_confirm, config.CLIENT_CONFIRM_LABEL, h_cli)
        self.sock.sendall(key.sign(h_cli) + tag)
        verdict = recv_exact(self.sock, 8)
        if verdict != config.AUTH_OK_TOKEN:
            raise RuntimeError(f"rejected: {verdict!r}")
        if recv_exact(self.sock, 32) != G.compute_confirmation_tag(k_confirm, config.SERVER_CONFIRM_LABEL, h_cli):
            raise RuntimeError("bad server confirmation tag")
        self.handshake_ms = (time.perf_counter() - t0) * 1000
        self.tunnel = secure_tunnel.SecureTunnel(k_session, role="client")

    def _wait_for(self, want):
        while True:
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("closed")
            for _, _, _, typ, payload in self.tunnel.feed(data):
                if typ == want:
                    return payload

    def round_trip(self, payload):
        t0 = time.perf_counter()
        self.sock.sendall(self.tunnel.seal(payload))
        self._wait_for(secure_tunnel.MSG_DATA)
        return (time.perf_counter() - t0) * 1000

    def rekey(self):
        t0 = time.perf_counter()
        epoch = self.tunnel.epoch + 1
        share, finish = kex_start()
        self.sock.sendall(self.tunnel.seal(struct.pack(">I", epoch) + share, secure_tunnel.MSG_REKEY_REQ))
        resp = self._wait_for(secure_tunnel.MSG_REKEY_RESP)
        self.tunnel.rekey(finish(resp[4:]), struct.unpack(">I", resp[:4])[0])
        return (time.perf_counter() - t0) * 1000

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# =============================================================================== in-process gateway
class Bench:
    def __init__(self, n_devices):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = {f"bench-{i:03d}": DeviceKey() for i in range(n_devices)}
        allow = Path(self.tmp.name) / "authorized_devices.json"
        allow.write_text(json.dumps({d: k.public.hex() for d, k in self.keys.items()}))
        self.port = 19100 + os.getpid() % 500
        self.gateway = server.VpnGateway(host="127.0.0.1", port=self.port)
        self.gateway.allowlist = crypto_engine.DeviceAllowlist(allow)
        self.gateway_pk = self.gateway.crypto.public_bytes
        self._ip = 10
        self._ip_lock = threading.Lock()
        # All gateway output (banner, [CONNECT] lines) is silenced; this script prints with builtins.print
        console.builtins = type("Silent", (), {"print": staticmethod(lambda *a, **k: None)})
        threading.Thread(target=self.gateway.start, daemon=True, name="gateway").start()
        time.sleep(0.5)

    def next_ip(self):
        with self._ip_lock:   # A fresh source address per connection keeps clear of the per-IP limits
            self._ip = self._ip + 1 if self._ip < 250 else 11
            return f"127.0.0.{self._ip}"

    def client(self, idx):
        device_id = f"bench-{idx:03d}"
        return SimClient(self.port, device_id, self.keys[device_id], self.next_ip(), self.gateway_pk)


# =============================================================================== tests
# Reference values for ML-KEM-512 / ML-DSA-44, from the independent pure-Python FIPS 203 / FIPS 204
# implementations kyber-py 1.2.0 and dilithium-py 1.5.1 with fixed inputs:
#   ML-KEM-512: d = 0x00..0x1F, z = 0x20..0x3F, m = 0x40..0x5F
#   ML-DSA-44 : xi = 0x00..0x1F, message = 0x60..0x7F, empty context, deterministic signing (rnd = 0)
REF = {
    "kem_ek_sha256": "3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee",
    "kem_dk_sha256": "17fb29b8c4baf74fb81eea15ffd583b3e37f5a5b8dcf6db96c72c3b3751d6f17",
    "kem_ct": "90d378b38f7fa38da486daeb005af67e384ffd83661756744487b4da04cf8ac945e990a0b7b9eaece37d10376a71a7050ad4d081d5f169d1707b7d58eb8ec35f081ffc4cb0ef2fe5fde8fb1c6a63ac64fcc235f93049b57827921e1c3148ecf7e847618f0b3b98ff4eff8cc69cfd9f19b15ddd47b7e977c373bba6c0f40b097096ee135aa6878f75a16dcea34588b51013ec3751b3f27ba60358fe18bb2680f96277da9b17eaae5feb51cacb8d05017686930dceda16ad78dfe9758dc2a7f645ab3586fbafcd1789cf662dce23d48250c9dc97baaab541d23b259fc68132b4ffdd5e92270f3cd057549416017f9ea88d97d71f8ed9870a4ede980614bc831a57a6d03e0588c5b2a3bad56d72c75537176297f26af50b780cee129a17fc95178462569a3620095e10c1bccb2ef84f6baeb2515cc2cd80d3229ecdc8d96abbc3078fa998d191d2b6b65402531f4a357c56a3233be4fa841c0c5b597cd3db0f3d7005b10db0bd4463128606a89a115cb0c1f36b3caabc1f4e0fadf6883bcb92515d84fe0d9d89b5c0e9d95b57625c51392018a3132fcbc3293a4cc457829a05053bbcd3d9a4bf4083d90eb4cc6404a261280d3c6d382107d79b51949211f71f5aa81b5a49575995b9de0303fb78a2054d9122bdc93ad6905170e0fce6001ce4df1ed585ddaf3d55a2675f74d07d640814b6e767a197b9b35f327cdf4953914732f9cd15a27b64436ecc7bceeb6a611fd7f8b918b7f32e3aabc3996b08a5990c89731027b9900e2a250e8de7aacb841f4aa44d059faf09e7214e02e454b4c0140dd935211448724e9217b92bd87e803ec6b612be1051f556e6a5ccab99adc770173744cd8f6a38826cf923ab35fc520bd12ffc1ae7d7c942191f0cbd9f80aaa25143859dc1eddff822308aeb2b030b9343790baad00d352202c5c43b47b6d75efe3f4f9b551db208f19bfc01b8f86244072832baa09223766df0a2c5f437bced624279f9fbc3d09f2cc7c04e8066983d31bc20f8b113155a32f950b2d1b2322dbf54ec3a39c2325e4a99f72f1a36213528d1d67d3cf48560498ca8c8edf4ad672a7a",
    "kem_ss": "14cace3e48771b316676afad2cfcfe8488daaa4fad954e57236caa3f24a42cf7",
    "kem_ss_reject": "32ee1fb3f7bd2915218e9c1b2d0d2da88f0edce6804278bab3a6123c5bb64fc4",
    "dsa_pk_sha256": "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46",
    "dsa_sk_sha256": "04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b",
    "dsa_sig": "5a6d1085edb2d61bb8ac925f80c26502ade9025b441671db17216a7c23377c7f61c8b8e0e83e0921ffa278cadee846e7ff5233ffb03292328ff4ccc4b2c01da844229bb12a4292d2ce8cf1f3c783d2acb4c838bbf440e75270f75af1bc88a27e8352275d2a7dde6afdc27ae87a0c40416bba4b727fbdfb877d7006a12c50cec105f89b15b633993a51b941747c89e2d5f6daad6cac90655d0f85e34fce325096cd307f8944f4e12edf8ad54e5223afaa263d3b228eda9fb488c0f5f14397147d3ba0d1bfd7f2fc00730c6dc5fe6b60d8872028ea147adc7c978ea46ba346514871140ceac7cdcff0cbee9bf9a658f842fd175004192b45e57d16b2ea45a059b9e67665aa3a2a726c2727999f9ae04b86cfeb37c7af43eb94f883ce1594504634c727ce62fda37376614b68710126c7a4b2c4d790d8ee2343b65d25a92db552be85a9684ea0ce4dd1c82f47d80768e30f1e1b83b49f57762d1c2a00e78b151e091f3d9ad36ba1530aa4399b9d6f4b3595986da6787cf3b9016ce3b1a06cdf8f4f44b9dfd1df6c969c2e990e4848ada0d8853b4149e42348322a2b83287c3c98c04b114a46cc748ae411ddd4904bc2e9f8d62a546e6e4e2d9ebc5b5043e4738810939079011b19e3f28d27f19fac8b747313ba7b61535f5fde9a882cd9abcbe8bbefd0937088b629a6df42a7c806d0464ac3e7df3921b57f4ba2faaa384a1616a0123ac4c33bc48388f0e93bb1d7975d0d34756ed8ca136ea1a1ecc9df9946cd9dea66d451df62373d0a7292effaec8ba628ec5ebb3d24997740fd9224f6f3b884f21d01bd116d6cb3975c0fa2c82a6cc322b71bef13b2cafe46bd3330839a56a8d3e0d4dfe63d081a733e2cdf13d97d045500316b6c5ee0ec6129b9fbd460b2c21ed6bde973d4af22441cbd06eee180ee81dbdd67cc37f8fb5b8469a1cb96b7fe9842b6c8c4af3670a6f1d620b4452e281dec9a29b7f9784aae47754a9d871af40188a8c814d740fe7e0469553d321ccc81e669773dd15103f479950fe26a08edc5d5a58f1ed723d0e38d37dcb301deec5146cec10a0acb4379f43a93856c514eb0fe7f9aec8865c92b5bd223e16c9edba57dc54b6d76f5963ede4fb423f12100d3eb0514d9806c8a9d37a4f40f10b09e101effa988c465cfa3538d1a92382e83d9cf0e674d6a605e5128c37f1ef22b33713587ac14646e609e6152c744930ddd627600d1f97ed5289e002e85fa4c31415732d77ece5349b12da719e946229a54f56742c80735c34310079309e0c842398548014e83d83d94adf790616df6d947cf12719de8c1d718a071767985146b12a2f61227ee52c956f55fe6267a41d42fd26bc618500ef5d6e5c179aeb33cee9e242db1b220acacaaff468a622508fc959814836db20dd0ff4bc77087c86ffa89c7c5d55b74a408d03a674bfde1b54003eaa4905c9235cb6a70deba31ce953d1262b11c36e093f42f1647ba401087fffa9dbf5224891ef2515b7d04b27fa0e2e4542f3449231f3e57ab654bf5c62114e678d31310fbdc949aa880707170cbf0643e31e41fffdd396680c2e09b6eb17217e157fb90aa2ccbcc38ee7b7e56f21ccdbdd6291b9275cf6f8527f0fef08c5683da8d0281ad5aaf2c128bd69dbdbd2a5690a727f6e7dafba3054513425ff481d41bf2883f18c1e7440793ac1249422287cc413804a2bb3a2b6393bc067f732964a3a8c75f95e3820e5d901f5dc4ff2b79856ba4584269892b2604c6c9d7358c2cf612dfcbf2d43c29e18de6d6fc98681386c8f4618185faad224ca92732dba734a4728dea5a8ae7ef7c3be02b5ae63b1cc283110cfa5ba7a4129e6a642554c48339e0e0fb85af0849b20edb754b100805c9e05af49e74123c8003bb94c4db6bdcc6fdacfb019c823eb5a1254f2a21b544a45607d885db6ce7ecc71538a7de0fe975b22544a9d5b4b335101622e8ff1556e01df35e9b3826e8b9f458ce85755572b6d38f837a894ea91c6d4bad466fddcc3c6b1dcf942a4f7572d87d4ba1034593b14f8d481aa63954a5b17d1660cd8de547c98d92d8cb09c8fd0709fe69e820012c147281bbe3cdf8e2281b44db2a32dad5221b0fe220fb88d3679cc751f32835745f8d95e6ba0b25952bca5e4cab7ebe34ef07ddbe5146e591248a80ca2f1522008f72f5431d5d6216750ecb3c84aba90821ec14e29e8183bd61ff4bbc54f451b0794ac8b78372490c3c03e85a9c476d998bc9716e6cec8c316326d642d5e9c793894a51e5c93dc480bb34d12d54ee56708968f08b9ebf6b3e932f7cc31ad6de366c53bbcfadad5068a6bb1869ad9aaaec8a9b65f7a01368ffcabcb4bb5f88eaaceedf338d0eaaf839294300c48cf520b8260a0e0cbb9f1829131c12d954705857b72eda2b2f86236cbe1606ab83a911a902eb6ff3019c4f32574f35329f55f77fc92d3c266e369c00861b60cf6ebea1d1d3dd19b93d98848951e53112405dd6a34012164a9eedb885bf0bdeb58537b0573dc2e54649da47c92cc79567e1d77f87957a921808403dbfe07046e7f81657ab26c1fa9a190e584508d8daa469b45af173c5833810c9b1b484214d1c20e90222560772780670dc295747cdbbd411f4685d57bcec572afe60c4c7b508ba90ae733091778663efcb2c2991d93192999bcec7ca358643dc6025cbb80844077ee1601918603666fdee1f1bbcee6dce02bf5f21de883eda0c2ae63b32a0b813efc4775eac9f20fe7c70e69e14994ab7951409bb867a5ab3abb99ba106f195242aefa3daa085cc6bf63e181e701b767fa4df6f8cdeabeac34f56e96650186885eb54f7f78d053bef4b5a346090278cf03d5401613484165fca8adce8dc0368fa7f561088e543839e146bd07a2bc592e0f8934a96b3d5db02a0a5c3e0d55c604eabad1d280c783aa7be428dccd0c69bdb2403f7219eca20266c2ce5936039eebf69c6b44d7907d0b62d2079f74db2ad9fb476063c05ea79815cafd7247335184d5df1356c80e3ef2516d77a890a2d358750dcb1cce28f06fb7901d11f8f774cf626014eccfae51f2f0b1053cdebb697f87d30f4e9eaa56fac79a519c5e27e16c1ffa665ea6618aa5548f745bb09c8499466c5447ad5289256db2ee5d273af81cf6dd27a757371daad212f608432337758811740a475c37e10d678e38e9fbbb5757ced13b5d8936f46efed19c5d1b7a07d52eb04e10c3535ffc3a807e2514628821ced5a557ce66058f5aab3fa6289a35851739829c1cdaaf8ad5f4a023fadf3aca0cd5cb3c696b854e6df0353d0b198732ed319252734363b4855595d6675797b9fa9adafb9c4d4d9f9fe091a1e7d959ebac9cacfe7f1f8112b2d363e4e52666776879ba2a7abadbdc0dcfa12191c1e36454d848c989da7b2b3d6daeef4f6000000001825394c",
}


def l0_known_answer():
    section("[L0] KNOWN-ANSWER TESTS: every algorithm the VPN uses, against official / reference vectors")
    import hashlib
    import hmac as hmac_mod
    results = []

    def check(name, source, ok):
        results.append(ok)
        print(f"  {name:<40} {source:<38} {'PASS' if ok else 'FAIL'}")

    check("sha256", 'FIPS 180-4 example "abc"', hashlib.sha256(b"abc").hexdigest() ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    check("hmac_sha256", "RFC 4231 test case 2", hmac_mod.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256)
          .hexdigest() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    iv = bytes.fromhex("cafebabefacedbaddecaf888")
    pt = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    exp = bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" "76fc6ece0f4e1768cddf8853bb2d551b")
    check("aes256_gcm", "NIST GCM test case 16", AESGCM(key).encrypt(iv, pt, aad) == exp)
    a = secure_tunnel.SecureTunnel(os.urandom(32), "client")
    b = secure_tunnel.SecureTunnel(a._k_session, "server")
    ok = [p for *_, p in b.feed(a.seal(b"hello"))] == [b"hello"]
    frame = bytearray(a.seal(b"again"))
    frame[-1] ^= 1
    try:
        list(b.feed(bytes(frame)))
        ok = False
    except secure_tunnel.TunnelError:
        pass
    check("vpn_tunnel_roundtrip_and_tamper", "own frames, 1 flipped tag bit", ok)

    if IS_PQC:
        h = lambda x: hashlib.sha256(x).hexdigest()                                     # noqa: E731
        buf = ctypes.create_string_buffer
        d_z, m, xi, msg = bytes(range(64)), bytes(range(64, 96)), bytes(range(32)), bytes(range(96, 128))
        ek, dk = buf(800), buf(1632)
        _KEM.PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand(ek, dk, d_z)
        check("ml_kem_512_keygen", "kyber-py (FIPS 203) d,z fixed",
              h(ek.raw) == REF["kem_ek_sha256"] and h(dk.raw) == REF["kem_dk_sha256"])
        ct, ss = buf(768), buf(32)
        _KEM.PQCP_MLKEM_NATIVE_MLKEM512_enc_derand(ct, ss, ek, m)
        check("ml_kem_512_encaps", "kyber-py, m fixed", ct.raw.hex() == REF["kem_ct"] and ss.raw.hex() == REF["kem_ss"])
        ss2 = buf(32)
        _KEM.PQCP_MLKEM_NATIVE_MLKEM512_dec(ss2, bytes.fromhex(REF["kem_ct"]), dk)
        check("ml_kem_512_decaps", "kyber-py ciphertext", ss2.raw.hex() == REF["kem_ss"])
        bad = bytearray.fromhex(REF["kem_ct"])
        bad[0] ^= 1
        _KEM.PQCP_MLKEM_NATIVE_MLKEM512_dec(ss2, bytes(bad), dk)
        check("ml_kem_512_implicit_rejection", "kyber-py, 1 flipped ct bit", ss2.raw.hex() == REF["kem_ss_reject"])
        pk, sk = buf(config.PUBLIC_KEY_LENGTH), buf(config.SECRET_KEY_LENGTH)
        _DSA.PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(pk, sk, xi)
        check("ml_dsa_44_keygen", "dilithium-py (FIPS 204) xi fixed",
              h(pk.raw) == REF["dsa_pk_sha256"] and h(sk.raw) == REF["dsa_sk_sha256"])
        sig, n = buf(config.SIGNATURE_LENGTH), ctypes.c_size_t()
        rc = _DSA.PQCP_MLDSA_NATIVE_MLDSA44_signature_internal(       # pure ML-DSA, empty context, rnd = 0
            sig, ctypes.byref(n), msg, ctypes.c_size_t(len(msg)), b"\x00\x00", ctypes.c_size_t(2),
            bytes(32), sk, ctypes.c_int(0))
        check("ml_dsa_44_deterministic_sign", "dilithium-py deterministic sig", rc == 0 and sig.raw[:n.value].hex() == REF["dsa_sig"])
        ref_sig = bytes.fromhex(REF["dsa_sig"])
        check("ml_dsa_44_verify_reference_sig", "dilithium-py deterministic sig", verify_server(ref_sig, msg, pk.raw))
        bad_sig = bytearray(ref_sig)
        bad_sig[100] ^= 1
        check("ml_dsa_44_tamper_rejected", "1 flipped signature bit", not verify_server(bytes(bad_sig), msg, pk.raw))
    else:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as ed, x25519 as xx
        sk = ed.Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
        check("ed25519_keygen", "RFC 8032 7.1 test 1", sk.public_key().public_bytes_raw().hex() ==
              "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = sk.sign(b"")
        check("ed25519_sign", "RFC 8032 7.1 test 1", sig.hex() ==
              "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        bad_sig = bytes([sig[0] ^ 1]) + sig[1:]
        check("ed25519_verify_and_tamper", "RFC 8032 7.1 test 1",
              verify_server(sig, b"", sk.public_key().public_bytes_raw()) and
              not verify_server(bad_sig, b"", sk.public_key().public_bytes_raw()))
        x = xx.X25519PrivateKey.from_private_bytes(
            bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"))
        out = x.exchange(xx.X25519PublicKey.from_public_bytes(
            bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")))
        check("x25519", "RFC 7748 5.2 vector 1",
              out.hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    print(f"  => {sum(results)} / {len(results)} known-answer tests passed")
    record("L0", "known_answer_tests_passed", [sum(results)], f"of {len(results)}")


def l1_gateway_crypto(runs):
    section(f"[L1] GATEWAY CRYPTO COST PER HANDSHAKE ({runs} timed runs each after {WARMUP_RUNS} warm-up runs, no network)")
    crypto = G()
    dev = DeviceKey()
    share, finish = kex_start()
    n_cli, n_srv = os.urandom(32), os.urandom(32)
    m1 = bytes([1, config.ALGORITHM_ID]) + b"bench".ljust(16, b"\0") + n_cli + share
    if IS_PQC:
        kex = lambda: crypto.encapsulate(share)                                         # noqa: E731
        server_share, ss = crypto.encapsulate(share)
        kex_name = "ml_kem_512_encapsulate"
    else:
        kex = lambda: crypto.compute_shared_secret(crypto.generate_ephemeral_keypair()[0], share)  # noqa: E731
        sk, server_share = crypto.generate_ephemeral_keypair()
        ss = crypto.compute_shared_secret(sk, share)
        kex_name = "x25519_keygen_plus_shared_secret"
    sig_name = "ml_dsa_44" if IS_PQC else "ed25519"
    m2 = n_srv + server_share + crypto.sign_server_transcript(m1, n_srv, server_share)
    client_sig = dev.sign(G.build_client_transcript(m1, m2))
    k_confirm, _ = G.derive_session_keys(ss, n_cli, n_srv)
    parts = {
        kex_name: timed_ms(kex, runs),
        f"{sig_name}_sign_server_transcript": timed_ms(lambda: crypto.sign_server_transcript(m1, n_srv, server_share), runs),
        f"{sig_name}_verify_client_signature": timed_ms(lambda: crypto.verify_client_transcript(dev.public, client_sig, m1, m2), runs),
        "hkdf_sha256_session_keys": timed_ms(lambda: G.derive_session_keys(ss, n_cli, n_srv), runs),
        "hmac_sha256_two_confirmation_tags": timed_ms(lambda: [G.compute_confirmation_tag(k_confirm, l, b"x" * 32)
                                                               for l in (b"a", b"b")], runs),
    }
    for name, vals in parts.items():
        record("L1", name, vals, "ms")
    record("L1", "total_gateway_crypto_per_handshake", [sum(v) for v in zip(*parts.values())], "ms")


def l2_message_crypto(runs):
    section(f"[L2] GATEWAY PER-MESSAGE AES-256-GCM COST ({runs} timed runs per size after {WARMUP_RUNS} warm-up runs)")
    for size in (64, 256, 1023):
        a = secure_tunnel.SecureTunnel(os.urandom(32), "client")
        b = secure_tunnel.SecureTunnel(a._k_session, "server")
        payload = os.urandom(size)
        for _ in range(WARMUP_RUNS):
            list(b.feed(a.seal(payload)))
        enc, dec = [], []
        for _ in range(runs):
            t0 = time.perf_counter()
            frame = a.seal(payload)
            t1 = time.perf_counter()
            list(b.feed(frame))
            t2 = time.perf_counter()
            enc.append((t1 - t0) * 1000)
            dec.append((t2 - t1) * 1000)
        record("L2", f"seal_{size}B", enc, "ms")
        record("L2", f"open_{size}B", dec, "ms")


def l3_handshake(bench, runs):
    section(f"[L3] HANDSHAKE TIME OVER LOOPBACK, real gateway + simulated ESP32 ({runs} runs, one at a time)")
    times = []
    for i in range(runs):
        c = bench.client(i % len(bench.keys))
        times.append(c.handshake_ms)
        c.close()
    record("L3", "handshake_total_loopback", times, "ms")
    record("L3", "handshake_bytes_on_wire", [HANDSHAKE_BYTES], "bytes")


def l4_rekey(bench, runs):
    section(f"[L4] REKEY TIME OVER LOOPBACK ({runs} rekeys in one tunnel; 5 s anti-flooding limit lifted for this test)")
    saved = tunnel_session.REKEY_MIN_INTERVAL
    tunnel_session.REKEY_MIN_INTERVAL = 0.0
    try:
        c = bench.client(0)
        times = []
        for _ in range(runs):
            times.append(c.rekey())
            c.round_trip(b"after rekey")
        c.close()
        record("L4", "rekey_round_trip_loopback", times, "ms")
    finally:
        tunnel_session.REKEY_MIN_INTERVAL = saved


def l5_burst(bench, sizes):
    section("[L5] SIMULTANEOUS HANDSHAKES (N devices connect at the same instant)")
    print(f"  Gateway limit: {config.MAX_CONCURRENT_HANDSHAKES} handshakes in progress at once; extra ones are refused (DoS protection).")
    for n in sizes:
        barrier = threading.Barrier(n)
        ok_times, refused = [], 0

        def one(i):
            barrier.wait()
            try:
                c = bench.client(i)
                c.close()
                return c.handshake_ms
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=n) as pool:
            for r in pool.map(one, range(n)):
                if r is None:
                    refused += 1
                else:
                    ok_times.append(r)
        record("L5", f"burst_{n}_devices_accepted", [len(ok_times)], "devices")
        record("L5", f"burst_{n}_devices_refused_by_dos_cap", [refused], "devices")
        if ok_times:
            record("L5", f"burst_{n}_devices_handshake_time", ok_times, "ms")
        time.sleep(1.0)


def _l6_worker(port, gateway_pk, devices, seconds, barrier, results):
    """Runs in its own process: connects its share of the devices, then sends 64-byte messages
    as fast as the ACKs return. Separate processes keep the devices' Python work off the gateway."""
    clients, errors = [], 0
    for dev_id, secret, ip_index in devices:
        for attempt in range(30):          # Refused by the handshake cap? Retry like a real ESP32
            ip = f"127.0.0.{11 + (ip_index + attempt * 37) % 230}"
            try:
                clients.append(SimClient(port, dev_id, DeviceKey(secret), ip, gateway_pk))
                break
            except Exception:
                time.sleep(0.05 * (attempt + 1))
    not_connected = len(devices) - len(clients)
    barrier.wait()                         # All processes start sending at the same moment
    stop = time.perf_counter() + seconds
    counts, rtts, lock = [0], [], threading.Lock()

    def run(c):
        nonlocal errors
        local, n = [], 0
        try:
            while time.perf_counter() < stop:
                local.append(c.round_trip(b"m" * 64))
                n += 1
        except Exception:
            with lock:
                errors += 1
        with lock:
            counts[0] += n
            rtts.extend(local)
    threads = [threading.Thread(target=run, args=(c,)) for c in clients]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for c in clients:
        c.close()
    results.put((counts[0], rtts[::max(1, len(rtts) // 2000)], errors, not_connected))


def l6_many_tunnels(bench, sizes, seconds):
    section(f"[L6] MANY ACTIVE TUNNELS (N devices in separate processes, 64-byte messages as fast as ACKs return, {seconds} s)")
    print("  The per-key message limit is lifted here: this test measures raw gateway capacity, and the policy")
    print(f"  (max {config.REKEY_MAX_MESSAGES} messages per key, one rekey per {config.REKEY_MIN_INTERVAL:.0f} s) caps one device at "
          f"~{config.REKEY_MAX_MESSAGES / config.REKEY_MIN_INTERVAL:.0f} msg/s by design.")
    saved = tunnel_session.REKEY_MAX_MESSAGES
    tunnel_session.REKEY_MAX_MESSAGES = 10 ** 12
    try:
        import multiprocessing as mp
        ctx = mp.get_context("spawn")
        for round_no, n in enumerate(sizes):
            n_proc = min(n, max(1, (os.cpu_count() or 2) - 2), 8)
            device_ids = [f"bench-{i:03d}" for i in range(n)]
            shares = [[] for _ in range(n_proc)]
            for i, dev_id in enumerate(device_ids):   # A fresh range of source addresses for every round
                shares[i % n_proc].append((dev_id, bench.keys[dev_id].secret, round_no * 41 + i))
            barrier, results = ctx.Barrier(n_proc), ctx.Queue()
            procs = [ctx.Process(target=_l6_worker, args=(bench.port, bench.gateway_pk, share, seconds, barrier, results))
                     for share in shares]
            for p in procs:
                p.start()
            total, rtts, errors, not_connected = 0, [], 0, 0
            for _ in procs:
                c, r, e, nc = results.get(timeout=120)
                total, errors, not_connected = total + c, errors + e, not_connected + nc
                rtts.extend(r)
            for p in procs:
                p.join()
            record("L6", f"tunnels_{n}_aggregate_messages_per_s", [total / seconds], "msg/s")
            record("L6", f"tunnels_{n}_round_trip", rtts, "ms")
            record("L6", f"tunnels_{n}_sessions_dropped", [errors + not_connected], "devices")
            time.sleep(1.0)
    finally:
        tunnel_session.REKEY_MAX_MESSAGES = saved


# =============================================================================== --serve mode
def serve(port, echo_port):
    def echo_server():
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", echo_port))
        srv.listen(8)

        def handle(conn):
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        return
                    conn.sendall(data)
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=echo_server, daemon=True).start()
    print(f"[BENCH] Plain TCP echo (no-VPN baseline) on port {echo_port}")
    print(f"[BENCH] {VPN_NAME} gateway on port {port}, session output silenced (VPN_QUIET=1)")
    print("[BENCH] Flash the ESP32 with BENCHMARK_MODE 1 and read its results on the Serial Monitor.\n")
    server.VpnGateway(port=port).start()


# =============================================================================== main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--serve", action="store_true", help="run the real gateway + echo server for the ESP32 benchmark")
    ap.add_argument("--echo-port", type=int, default=9001)
    ap.add_argument("--runs", type=int, default=100, help="handshake runs (L3)")
    ap.add_argument("--crypto-runs", type=int, default=500, help="runs per crypto operation (L1), after warm-up")
    ap.add_argument("--devices", default="1,5,10,20,40", help="device counts for L5/L6")
    ap.add_argument("--seconds", type=float, default=5.0, help="duration of each L6 load test")
    ap.add_argument("--l1-json", action="store_true", help="run only L1 and print it as JSON (used by compare_gateway_crypto.py)")
    args = ap.parse_args()
    if args.serve:
        return serve(config.PORT, args.echo_port)
    if args.l1_json:
        import builtins
        quiet_print = builtins.print
        globals()["print"] = lambda *a, **k: None
        l1_gateway_crypto(args.crypto_runs)
        quiet_print(json.dumps({"vpn": VPN_NAME, "results": RESULTS}))
        return

    sizes = [int(x) for x in args.devices.split(",")]
    print("=" * 100)
    print(f"GATEWAY SYSTEM BENCHMARK: {VPN_NAME}")
    print(f"Python {sys.version.split()[0]} | {os.cpu_count()} CPU threads | host {socket.gethostname()}")
    print("=" * 100)
    l0_known_answer()
    l1_gateway_crypto(args.crypto_runs)
    l2_message_crypto(2000)
    bench = Bench(max(sizes))
    l3_handshake(bench, args.runs)
    l4_rekey(bench, 20)
    l5_burst(bench, sizes)
    l6_many_tunnels(bench, sizes, args.seconds)

    out_dir = HERE / "results"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / "laptop_gateway_results.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "metric", "n", "mean", "median", "p95", "std", "min", "max", "unit"])
        w.writeheader()
        for r in RESULTS:
            w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"\nSaved {len(RESULTS)} results to {out}")


if __name__ == "__main__":
    main()
