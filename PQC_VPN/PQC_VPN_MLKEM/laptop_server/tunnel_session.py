import socket
import textwrap
import time
import re
import hmac
import hashlib
from secure_tunnel import SecureTunnel, TunnelError
from config import (
    PROTOCOL_VERSION,
    ALGORITHM_ID,
    SIGNATURE_LENGTH,
    KEM_PUBLIC_KEY_LENGTH,
    KEM_CIPHERTEXT_LENGTH,
    MSG1_CLIENT_HELLO_SIZE,
    MSG2_SERVER_PROOF_SIZE,
    MSG3_CLIENT_PROOF_SIZE,
    MSG4_AUTH_VERDICT_SIZE,
    AUTH_OK_TOKEN,
    AUTH_FAIL_TOKEN,
    SERVER_TRANSCRIPT_LABEL,
    CLIENT_TRANSCRIPT_LABEL,
    CLIENT_CONFIRM_LABEL,
    SERVER_CONFIRM_LABEL,
    HANDSHAKE_TIMEOUT,
    TUNNEL_IDLE_TIMEOUT
)


def print_hex_64_box(data_bytes):
    """Prints up to 64 bytes in 32-byte (64 hex characters) lines formatted to 75 chars."""
    hex_str = data_bytes.hex().upper()
    if len(hex_str) <= 64:
        print(f"| {hex_str:<75} |")
    else:
        print(f"| {hex_str[:64]:<75} |")
        print(f"| {hex_str[64:]:<75} |")


def print_mldsa_pubkey_box(pk_bytes):
    """Prints 1,312-byte ML-DSA-44 Public Key structure (rho seed + t1 polynomial tail) in a 79-char box."""
    print("| [Byte 0000..0031 : Matrix Expansion Seed rho (32 Bytes)]                    |")
    print_hex_64_box(pk_bytes[:32])
    print("| ... [Bytes 0032..1279 : NTT Polynomial Vector t1 (1248 Bytes omitted)] ...  |")
    print("| [Byte 1280..1311 : Polynomial Vector t1 Tail (32 Bytes)]                    |")
    print_hex_64_box(pk_bytes[1280:1312])


def print_mldsa_sig_box(sig_bytes):
    """Prints 2,420-byte ML-DSA-44 Signature structure (c_tilde + z response + h hints) in a 79-char box."""
    print("| [Byte 0000..0031 : Commitment Hash c_tilde (32 Bytes)]                      |")
    print_hex_64_box(sig_bytes[:32])
    print("| ... [Bytes 0032..2387 : Masked Response Vector z (2356 Bytes omitted)] ...  |")
    print("| [Byte 2388..2419 : PolyNorm Hint Vector h Tail (32 Bytes)]                  |")
    print_hex_64_box(sig_bytes[2388:2420])


def print_phase(number, title, description):
    """Beginner-friendly banner marking each stage of the handshake."""
    print("\n" + "=" * 79)
    print(f" PHASE {number} of 5 : {title}")
    print(f" {description}")
    print("=" * 79)


def print_note(text):
    """Plain-English explanation printed after a technical step."""
    print("  >> In plain words:")
    for line in textwrap.wrap(text, 71):
        print(f"     {line}")
    print()


SUMMARY_LINES = ['SECURE CONNECTION ESTABLISHED - WHAT JUST HAPPENED', '', '[1] Who are you?  ML-DSA-44 : both sides proved their identity', '[2] Shared secret ML-KEM-512: agreed on a 32-byte key K without sending it', '[3] Session keys  HKDF-256  : turned K into the keys used for encryption', '[4] Double check  HMAC-256  : both sides confirmed they hold the same keys', '[5] From now on   AES-256-GCM: every message is encrypted + tamper-proof', '', 'ML-DSA-44 and ML-KEM-512 are POST-QUANTUM: designed to resist attacks', 'from future quantum computers.']


def print_summary():
    print("#" * 79)
    for line in SUMMARY_LINES:
        print(f"# {line:<75} #")
    print("#" * 79 + "\n")


def print_mlkem_ek_box(ek_bytes):
    """Prints 800-byte ML-KEM-512 encapsulation key (ByteEncode12(t_hat) || rho) in a 79-char box."""
    print("| [Byte 000..031 : ByteEncode12(t_hat) Head (32 Bytes)]                       |")
    print_hex_64_box(ek_bytes[:32])
    print("| ... [Bytes 032..767 : NTT Polynomial Vector t_hat (736 Bytes omitted)] ...  |")
    print("| [Byte 768..799 : Matrix Expansion Seed rho (32 Bytes)]                      |")
    print_hex_64_box(ek_bytes[768:800])


def print_mlkem_ct_box(ct_bytes):
    """Prints 768-byte ML-KEM-512 ciphertext (c1 = Compress_10(u) || c2 = Compress_4(v)) in a 79-char box."""
    print("| [Byte 000..031 : c1 = Compress_10(u) Head (32 Bytes)]                       |")
    print_hex_64_box(ct_bytes[:32])
    print("| ... [Bytes 032..735 : Compressed u || Polynomial v (704 Bytes omitted)] ... |")
    print("| [Byte 736..767 : c2 = Compress_4(v) Tail (32 Bytes)]                        |")
    print_hex_64_box(ct_bytes[736:768])


def server_transcript_rows(label, msg1, device_id, server_nonce, kem_ct):
    """Field rows shared by the Server Transcript (1,664 B) and Client Transcript (4,084 B) tables."""
    return [
        ("Domain Prefix", "Byte 0..13", "14 Bytes", label),
        ("Protocol Version", "Byte 14", "1 Byte", f"0x{msg1[0]:02X}"),
        ("Algorithm ID", "Byte 15", "1 Byte", f"0x{msg1[1]:02X} (MLDSA+MLKEM)"),
        ("Device ID (Zero-Padded)", "Byte 16..31", "16 Bytes", f"\"{device_id}\""),
        ("Client Nonce [N_cli]", "Byte 32..63", "32 Bytes", preview(msg1[18:50])),
        ("Client KEM Key [ek_cli]", "Byte 64..863", "800 Bytes", preview(msg1[50:850])),
        ("Server Nonce [N_srv]", "Byte 864..895", "32 Bytes", preview(server_nonce)),
        ("KEM Ciphertext [ct]", "Byte 896-1663", "768 Bytes", preview(kem_ct)),
    ]


def print_transcript_table(title, rows, total_len):
    """Prints a structured transcript payload table showing exact byte offsets and sizes."""
    c1, c2, c3, c4 = 26, 13, 9, 18
    sep_inner = f"+{'-'*(c1+2)}+{'-'*(c2+2)}+{'-'*(c3+2)}+{'-'*(c4+2)}+"
    sep_outer = "+" + "-" * 77 + "+"

    header = f"| {title} ({total_len} Bytes / {total_len*8}-bits)"
    print(sep_outer)
    print(f"{header:<78}|")
    print(sep_inner)
    print(f"| {'Field Name':<{c1}} | {'Byte Offset':<{c2}} | {'Size':<{c3}} | {'Value / Encoding':<{c4}} |")
    print(sep_inner)
    for name, offset, size, val in rows:
        print(f"| {name:<{c1}} | {offset:<{c2}} | {size:<{c3}} | {val:<{c4}} |")
    print(sep_outer)


def preview(data):
    """Short hex preview: first 6 bytes .. last 2 bytes (18 chars)."""
    return f"{data[:6].hex().upper()}..{data[-2:].hex().upper()}"


def short_preview(data):
    """Compact hex preview: first 4 bytes .. last 2 bytes (14 chars)."""
    return f"{data[:4].hex().upper()}..{data[-2:].hex().upper()}"


class VpnSession:
    """
    Manages the lifecycle of an ESP32 connection:
    4-Message Handshake with ML-DSA-44 Mutual Authentication, Ephemeral ML-KEM-512 Key Encapsulation
    & HMAC-SHA256 Key Confirmation -> Data Tunnel.
    """

    def __init__(self, connection, client_address, crypto_engine, allowlist, handshake_slot=None):
        self.connection = connection
        self.client_address = client_address
        self.crypto = crypto_engine
        self.allowlist = allowlist
        self.handshake_deadline = 0.0
        self.handshake_slot = handshake_slot
        self.k_confirm = None
        self.k_session = None

    def receive_exact(self, expected_byte_count):
        """Reads exactly expected_byte_count bytes with deadline enforcement."""
        buffer = bytearray()
        while len(buffer) < expected_byte_count:
            if self.handshake_deadline > 0:
                time_remaining = self.handshake_deadline - time.monotonic()
                if time_remaining <= 0:
                    return None
                self.connection.settimeout(min(time_remaining, 5.0))

            try:
                chunk = self.connection.recv(expected_byte_count - len(buffer))
                if not chunk:
                    return None
                buffer.extend(chunk)
            except socket.timeout:
                return None
        return bytes(buffer)

    # -------------------------------------------------------------------------
    # MESSAGE 1: CLIENT HELLO RECEIVER (850 BYTES)
    # -------------------------------------------------------------------------
    def _receive_client_hello(self, client_ip):
        """Reads 850-byte Client Hello packet: [Ver] [Alg] [ID (16B)] [Nonce (32B)] [ML-KEM-512 ek (800B)]."""
        raw = self.receive_exact(MSG1_CLIENT_HELLO_SIZE)
        if not raw:
            print(f"[{client_ip}] [ERROR] Disconnected during Client Hello.")
            return None, None, None, None, None

        version = raw[0]
        alg_id = raw[1]
        id_field = raw[2:18]
        client_nonce = raw[18:50]
        client_kem_ek = raw[50:50 + KEM_PUBLIC_KEY_LENGTH]

        if version != PROTOCOL_VERSION or alg_id != ALGORITHM_ID:
            print(f"[{client_ip}] [AUTH-FAIL] Invalid Ver (0x{version:02X}) or AlgID (0x{alg_id:02X})")
            return None, None, None, None, None

        raw_id = id_field.rstrip(b"\x00")
        if b"\x00" in raw_id or not re.fullmatch(rb"[a-zA-Z0-9_-]{1,16}", raw_id):
            print(f"[{client_ip}] [AUTH-FAIL] Malformed Device ID field: {id_field!r}")
            return None, None, None, None, None
        device_id = raw_id.decode("ascii")

        # Step 1-3: Client generation & transmission of MSG 1
        print_phase(1, 'HELLO', 'The ESP32 says hello and sends a one-time ML-KEM-512 public key.')
        print(f"\n[Client] Generating 32-byte fresh Client Nonce [N_cli] via Hardware TRNG...")
        print(f"[Client] Generating fresh Ephemeral ML-KEM-512 Keypair [dk_cli_eph, ek_cli_eph] (Forward Secrecy)...")
        print(f"[Client -> Server] Sending MSG 1 (Client Hello with ML-KEM-512 Encapsulation Key)...")
        print("+-----------------------------------------------------------------------------+")
        print("| MSG 1: CLIENT HELLO WIRE PACKET (850 Bytes / 6800-bits)                     |")
        print("+-------------------+--------------------+------------------------------------+")
        print("| Version (8-bits)  | Alg ID (8-bits)    | Device ID (128-bits / 16 Bytes)    |")
        print(f"| 0x{version:02X}              | 0x{alg_id:02X} (MLDSA+MLKEM) | {device_id:<34} |")
        print("+-------------------+--------------------+------------------------------------+")
        print("| Client Nonce [N_cli] (32 Bytes / 256-bits)                                  |")
        print_hex_64_box(client_nonce)
        print("+-----------------------------------------------------------------------------+")
        print("| Client Ephemeral ML-KEM-512 Encaps Key [ek_cli_eph] (800 Bytes / 6400-bits) |")
        print_mlkem_ek_box(client_kem_ek)
        print("+-----------------------------------------------------------------------------+")

        # Step 4: Server allowlist authorization check
        print_note("The ESP32 sent its name, a fresh random number, and a ONE-TIME ML-KEM-512 public key (800 bytes). Anyone may see this public key - it can only be used to LOCK a secret that only this ESP32 can unlock.")
        print(f"\n[Server] [AUTHORIZATION] Checking Device ID '{device_id}' against local allowlist database...")
        registered_pubkey_bytes = self.allowlist.get_device_public_key(device_id)
        if not registered_pubkey_bytes:
            print(f"[Server] [AUTHORIZATION] Status: DENIED (Device ID not registered)")
            return None, None, None, None, None
        print(f"[Server] [AUTHORIZATION] Status: ALLOWED (Authorized client public key loaded from database)")
        print("+-----------------------------------------------------------------------------+")
        print("| Registered Client ML-DSA-44 Public Key [PK_cli] (1312 Bytes / 10496-bits)   |")
        print_mldsa_pubkey_box(registered_pubkey_bytes)
        print("+-----------------------------------------------------------------------------+\n")

        return device_id, registered_pubkey_bytes, client_nonce, client_kem_ek, raw

    # -------------------------------------------------------------------------
    # MESSAGE 2: SERVER PROOF TRANSMITTER (3,220 BYTES)
    # -------------------------------------------------------------------------
    def _send_server_proof(self, device_id, client_nonce, client_kem_ek, msg1):
        """
        Generates 32B server nonce and encapsulates against the client's ephemeral ML-KEM-512 ek.
        Constructs Server Transcript (1,664B), hashes it to H_srv (32B), signs H_srv with ML-DSA-44 (2,420B),
        and sends 3,220B MSG 2 packet: [Server Nonce (32B)] [ML-KEM-512 ct (768B)] [ML-DSA-44 Sig (2,420B)].
        """
        # Step 5: Server generates 32-byte Server Nonce
        print_note("The laptop looked up 'esp32-01' in its list of allowed devices and found it, so the connection may continue.")
        print_phase(2, 'LAPTOP REPLIES', 'The laptop makes a secret, locks it (ML-KEM-512), signs reply (ML-DSA-44).')
        print(f"[Server] Generating 32-byte fresh Server Nonce [N_srv] via CSPRNG...")
        server_nonce = self.crypto.generate_challenge()

        # Step 6: Server validates ek and encapsulates: (K, ct) = ML-KEM-512.Encaps(ek_cli_eph)
        print(f"[Server] Validating ek_cli_eph (FIPS 203 modulus check) & Encapsulating: (K, ct) = ML-KEM-512.Encaps(ek_cli_eph)...")
        try:
            kem_ct, shared_secret = self.crypto.encapsulate(client_kem_ek)
        except ValueError as e:
            print(f"[Server] [KEX-FAIL] Invalid client ML-KEM-512 encapsulation key: {e}")
            return None
        print("+-----------------------------------------------------------------------------+")
        print("| ML-KEM-512 Ciphertext [ct] (768 Bytes / 6144-bits)                          |")
        print_mlkem_ct_box(kem_ct)
        print("+-----------------------------------------------------------------------------+")
        print("| ML-KEM-512 Shared Secret [K] (32 Bytes / 256-bits)                          |")
        print_hex_64_box(shared_secret)
        print("+-----------------------------------------------------------------------------+\n")

        # Step 7: Server constructs Server Transcript (1,664 Bytes)
        print_note("ML-KEM-512 step: the laptop created a random 32-byte secret K and LOCKED it inside the 768-byte ciphertext 'ct'. Only the ESP32's one-time private key can unlock it. K itself never travels over the network.")
        print(f"[Server] Constructing Server Transcript (label || MSG1 || N_srv || ct)...")
        rows = server_transcript_rows("\"VPN-v1|SERVER|\"", msg1, device_id, server_nonce, kem_ct)
        print_transcript_table("SERVER TRANSCRIPT PAYLOAD", rows, 1664)

        # Step 8: Server computes SHA-256 Digest [H_srv] of Server Transcript
        print(f"\n[Server] Computing SHA-256 digest of Server Transcript...")
        server_transcript_digest = self.crypto.build_server_transcript(msg1, server_nonce, kem_ct)
        print("+-----------------------------------------------------------------------------+")
        print("| SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                                |")
        print_hex_64_box(server_transcript_digest)
        print("+-----------------------------------------------------------------------------+")

        # Step 9: Server signs [H_srv] with Gateway ML-DSA-44 Private Key
        print(f"\n[Server] Signing digest [H_srv] with Gateway ML-DSA-44 secret key [sk_srv]...")
        server_sig = self.crypto.sign_server_transcript(msg1, server_nonce, kem_ct)
        print("+-----------------------------------------------------------------------------+")
        print("| Server ML-DSA-44 Signature [sigma_srv] (2420 Bytes / 19360-bits)            |")
        print_mldsa_sig_box(server_sig)
        print("+-----------------------------------------------------------------------------+")

        # Step 10: Assemble and transmit MSG 2 (3,220 Bytes)
        msg2 = server_nonce + kem_ct + server_sig
        assert len(msg2) == MSG2_SERVER_PROOF_SIZE
        self.connection.sendall(msg2)

        print_note("The laptop SIGNED a fingerprint (SHA-256 hash) of the whole conversation with its ML-DSA-44 private key, so the ESP32 can be sure the reply really comes from the laptop and was not changed by an attacker.")
        print(f"\n[Server -> Client] Sending MSG 2 (Server Proof with ML-KEM-512 Ciphertext)...")
        print("+-----------------------------------------------------------------------------+")
        print("| MSG 2: SERVER PROOF WIRE PACKET (3220 Bytes / 25760-bits)                   |")
        print("+-----------------------------------------------------------------------------+")
        print("| Server Nonce [N_srv] (32 Bytes / 256-bits)                                  |")
        print_hex_64_box(server_nonce)
        print("+-----------------------------------------------------------------------------+")
        print("| ML-KEM-512 Ciphertext [ct] (768 Bytes / 6144-bits)                          |")
        print_mlkem_ct_box(kem_ct)
        print("+-----------------------------------------------------------------------------+")
        print("| Server ML-DSA-44 Signature [sigma_srv] (2420 Bytes / 19360-bits)            |")
        print_mldsa_sig_box(server_sig)
        print("+-----------------------------------------------------------------------------+")

        # Step 11: Client reconstructs Server Transcript
        print_phase(3, 'ESP32 CHECKS & UNLOCKS', "The ESP32 checks the laptop's signature, then unlocks the shared secret.")
        print(f"\n[Client] Reconstructing Server Transcript (label || MSG1 || N_srv || ct)...")
        print_transcript_table("SERVER TRANSCRIPT PAYLOAD", rows, 1664)

        # Step 12: Client hashes Server Transcript
        print(f"\n[Client] Hashing Server Transcript (SHA-256)...")
        print("+-----------------------------------------------------------------------------+")
        print("| Expected SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                       |")
        print_hex_64_box(server_transcript_digest)
        print("+-----------------------------------------------------------------------------+")

        # Step 13: Client verifies Server ML-DSA-44 Signature against Pinned Gateway Public Key
        print(f"\n[Client] Verifying Server ML-DSA-44 Signature against Pinned Gateway Public Key...")
        srv_pk_preview = short_preview(self.crypto.public_bytes)
        srv_h_preview = short_preview(server_transcript_digest)
        srv_c_preview = short_preview(server_sig[:32])
        srv_zh_preview = short_preview(server_sig[32:])
        print("+-----------------------------------------------------------------------------+")
        print("| ML-DSA-44 SIGNATURE VERIFICATION WORKING (FIPS 204 - SERVER PROOF)          |")
        print("+-----------------------------------------------------------------------------+")
        print(f"| Input 1: Pinned Gateway PubKey [PK_srv] (1312 B) : {srv_pk_preview:<25}|")
        print(f"| Input 2: Transcript Digest [H_srv] (32 Bytes)    : {srv_h_preview:<25}|")
        print(f"| Input 3: Commitment Hash [c_tilde] (32 Bytes)    : {srv_c_preview:<25}|")
        print(f"| Input 4: Response Vector [z] & Hints [h] (2388 B): {srv_zh_preview:<25}|")
        print("+-----------------------------------------------------------------------------+")
        print("| Step 1: Check infinity norm ||z||_inf < gamma1 - beta & hint weight <= 80   |")
        print("| Step 2: Reconstruct w'_1 = UseHint(h, NTT^-1(A_hat * NTT(z) - c_hat * t1))  |")
        print("| Step 3: Verify commitment c_tilde == SHAKE-256(mu || w1Encode(w'_1))        |")
        print("| Result : PASS -> Lattice commitment matches! Signature is FIPS 204 valid.   |")
        print("+-----------------------------------------------------------------------------+")

        # Step 14: Client decapsulates ct with its ephemeral dk (performed on the ESP32)
        print_note("The signature is valid, so the ESP32 now trusts it is talking to the real laptop (the laptop's public key is built into the ESP32 firmware).")
        print(f"\n[Client] Decapsulating ML-KEM-512 Ciphertext: K = ML-KEM-512.Decaps(dk_cli_eph, ct)...")
        print("+-----------------------------------------------------------------------------+")
        print("| ML-KEM-512 DECAPSULATION WORKING (FIPS 203 - IMPLICIT REJECTION)            |")
        print("+-----------------------------------------------------------------------------+")
        print(f"| Input 1: Ephemeral Decaps Key [dk_cli] (1632 B)  : {'(held only on ESP32)':<25}|")
        print(f"| Input 2: Ciphertext c1 = Compress_10(u) (640 B)  : {short_preview(kem_ct[:640]):<25}|")
        print(f"| Input 3: Ciphertext c2 = Compress_4(v) (128 B)   : {short_preview(kem_ct[640:]):<25}|")
        print("+-----------------------------------------------------------------------------+")
        print("| Step 1: Decrypt m' = K-PKE.Decrypt(dk_pke, ct) = Compress_1(v - s^T * u)    |")
        print("| Step 2: Derive (K', r') = G(m' || H(ek)) using SHA3-512                     |")
        print("| Step 3: Re-encrypt ct' = K-PKE.Encrypt(ek, m', r') and compare ct' == ct    |")
        print("| Step 4: K = K' if equal, else implicit rejection K = J(z || ct) (SHAKE-256) |")
        print("| Result : DONE -> Shared secret K recovered (confirmed by HMAC in MSG 3/4)   |")
        print("+-----------------------------------------------------------------------------+")

        # Step 15: Both sides derive Session Keys via HKDF-SHA256
        print_note("The ESP32 UNLOCKED 'ct' with its one-time private key and got exactly the SAME 32-byte secret K as the laptop. The one-time private key is now erased, so past sessions stay safe even if the device is stolen later (forward secrecy).")
        print(f"\n[Client & Server] Deriving K_confirm and K_session via HKDF-SHA256 (RFC 5869)...")
        hkdf_salt = hashlib.sha256(client_nonce + server_nonce).digest()
        self.k_confirm, self.k_session = self.crypto.derive_session_keys(shared_secret, client_nonce, server_nonce)
        shared_secret = None
        print("+-----------------------------------------------------------------------------+")
        print("| HKDF-SHA256 KEY SCHEDULE WORKING (RFC 5869)                                 |")
        print("+-----------------------------------------------------------------------------+")
        print("| HKDF Salt = SHA-256(N_cli || N_srv) (32 Bytes / 256-bits)                   |")
        print_hex_64_box(hkdf_salt)
        print("+-----------------------------------------------------------------------------+")
        print("| Derived Confirmation Key [K_confirm] (32 Bytes / 256-bits)                  |")
        print_hex_64_box(self.k_confirm)
        print("+-----------------------------------------------------------------------------+")
        print("| Derived Session Master Key [K_session] (32 Bytes / 256-bits)                |")
        print_hex_64_box(self.k_session)
        print("+-----------------------------------------------------------------------------+\n")

        return msg2

    # -------------------------------------------------------------------------
    # MESSAGE 3: CLIENT PROOF RECEIVER & KEY CONFIRMATION VERIFIER (2,452 BYTES)
    # -------------------------------------------------------------------------
    def _verify_client_proof(self, registered_pubkey_bytes, device_id, msg1, msg2):
        """
        Receives 2,452-byte Client Proof:
        [2,420B Client ML-DSA-44 Signature] [32B Client Key Confirmation Tag (HMAC-SHA256)].
        """
        raw = self.receive_exact(MSG3_CLIENT_PROOF_SIZE)
        if not raw:
            print(f"[{device_id}] [AUTH-FAIL] Connection dropped waiting for Client Proof.")
            return False, None

        client_sig = raw[:SIGNATURE_LENGTH]
        client_confirm_tag = raw[SIGNATURE_LENGTH:MSG3_CLIENT_PROOF_SIZE]

        server_nonce = msg2[0:32]
        kem_ct = msg2[32:32 + KEM_CIPHERTEXT_LENGTH]
        server_sig = msg2[32 + KEM_CIPHERTEXT_LENGTH:MSG2_SERVER_PROOF_SIZE]

        rows = server_transcript_rows("\"VPN-v1|CLIENT|\"", msg1, device_id, server_nonce, kem_ct)
        rows.append(("Server Sig [sigma_srv]", "1664..4083", "2420 B", preview(server_sig)))
        client_transcript_digest = self.crypto.build_client_transcript(msg1, msg2)

        # Step 16: Client constructs Client Transcript (2,580 Bytes)
        print_note("Both sides turned K into two new keys: K_confirm (to prove both sides have the same keys) and K_session (to encrypt all data in the tunnel).")
        print_phase(4, 'ESP32 PROVES ITSELF', 'The ESP32 signs the conversation and proves it holds the same keys.')
        print(f"[Client] Constructing Client Transcript (label || MSG1 || MSG2)...")
        print_transcript_table("CLIENT TRANSCRIPT PAYLOAD", rows, 4084)

        # Step 17: Client hashes Client Transcript
        print(f"\n[Client] Hashing Client Transcript (SHA-256)...")
        print("+-----------------------------------------------------------------------------+")
        print("| SHA-256 Digest [H_cli] (32 Bytes / 256-bits)                                |")
        print_hex_64_box(client_transcript_digest)
        print("+-----------------------------------------------------------------------------+")

        # Step 18: Client signs digest with ML-DSA-44 private key
        print(f"\n[Client] Signing transcript digest [H_cli] with device ML-DSA-44 secret key [sk_cli]...")
        print("+-----------------------------------------------------------------------------+")
        print("| Client ML-DSA-44 Signature [sigma_cli] (2420 Bytes / 19360-bits)            |")
        print_mldsa_sig_box(client_sig)
        print("+-----------------------------------------------------------------------------+")

        # Step 19: Client computes Client Key Confirmation Tag
        print(f"\n[Client] Computing Client Key Confirmation Tag = HMAC-SHA256(K_confirm, \"VPN-v1|CLIENT-CONFIRM|\" || H_cli)...")
        print("+-----------------------------------------------------------------------------+")
        print("| Client Key Confirmation Tag (32 Bytes / 256-bits)                           |")
        print_hex_64_box(client_confirm_tag)
        print("+-----------------------------------------------------------------------------+")

        # Step 20: Client sends MSG 3 wire packet (2,452 Bytes)
        print_note("The ESP32 signed the conversation with its own ML-DSA-44 key (proving WHO it is) and added an HMAC tag made with K_confirm (proving it holds the SAME keys).")
        print(f"\n[Client -> Server] Sending MSG 3 (Client Proof & Key Confirmation)...")
        print("+-----------------------------------------------------------------------------+")
        print("| MSG 3: CLIENT PROOF WIRE PACKET (2452 Bytes / 19616-bits)                   |")
        print("+-----------------------------------------------------------------------------+")
        print("| Client ML-DSA-44 Signature [sigma_cli] (2420 Bytes / 19360-bits)            |")
        print_mldsa_sig_box(client_sig)
        print("+-----------------------------------------------------------------------------+")
        print("| Client Key Confirmation Tag (32 Bytes / 256-bits)                           |")
        print_hex_64_box(client_confirm_tag)
        print("+-----------------------------------------------------------------------------+")

        # Step 21: Server reconstructs Client Transcript (2,580 bytes)
        print(f"\n[Server] Reconstructing Client Transcript (label || MSG1 || MSG2)...")
        print_transcript_table("CLIENT TRANSCRIPT PAYLOAD", rows, 4084)

        # Step 22: Server computes SHA-256 Digest [H_cli] of Client Transcript
        print(f"\n[Server] Hashing Client Transcript (SHA-256)...")
        print("+-----------------------------------------------------------------------------+")
        print("| Expected SHA-256 Digest [H_cli] (32 Bytes / 256-bits)                       |")
        print_hex_64_box(client_transcript_digest)
        print("+-----------------------------------------------------------------------------+")

        # Step 23: Server verifies Client ML-DSA-44 Signature
        print(f"\n[Server] Verifying Client ML-DSA-44 Signature against registered public key...")
        is_sig_valid = self.crypto.verify_client_transcript(registered_pubkey_bytes, client_sig, msg1, msg2)

        pk_preview = short_preview(registered_pubkey_bytes)
        h_preview = short_preview(client_transcript_digest)
        c_preview = short_preview(client_sig[:32])
        zh_preview = short_preview(client_sig[32:])

        print("+-----------------------------------------------------------------------------+")
        print("| ML-DSA-44 SIGNATURE VERIFICATION WORKING (FIPS 204 - CLIENT PROOF)          |")
        print("+-----------------------------------------------------------------------------+")
        print(f"| Input 1: Client Public Key [PK_cli] (1312 Bytes) : {pk_preview:<25}|")
        print(f"| Input 2: Transcript Digest [H_cli] (32 Bytes)    : {h_preview:<25}|")
        print(f"| Input 3: Commitment Hash [c_tilde] (32 Bytes)    : {c_preview:<25}|")
        print(f"| Input 4: Response Vector [z] & Hints [h] (2388 B): {zh_preview:<25}|")
        print("+-----------------------------------------------------------------------------+")
        print("| Step 1: Check infinity norm ||z||_inf < gamma1 - beta & hint weight <= 80   |")
        print("| Step 2: Reconstruct w'_1 = UseHint(h, NTT^-1(A_hat * NTT(z) - c_hat * t1))  |")
        print("| Step 3: Verify commitment c_tilde == SHAKE-256(mu || w1Encode(w'_1))        |")
        if is_sig_valid:
            print("| Result : PASS -> Lattice commitment matches! Client signature is authentic. |")
        else:
            print("| Result : FAIL -> Lattice commitment mismatch! Invalid signature. Aborting.  |")
        print("+-----------------------------------------------------------------------------+")

        if not is_sig_valid:
            print(f"[Server] [AUTH-FAIL] ML-DSA-44 signature verification failed.\n")
            return False, None

        # Step 24: Server verifies Client Key Confirmation Tag: HMAC-SHA256(K_confirm, label || H_cli)
        print(f"\n[Server] Verifying Client Key Confirmation Tag (HMAC-SHA256)...")
        expected_tag = self.crypto.compute_confirmation_tag(self.k_confirm, CLIENT_CONFIRM_LABEL, client_transcript_digest)
        is_tag_valid = hmac.compare_digest(client_confirm_tag, expected_tag)

        print("+-----------------------------------------------------------------------------+")
        print("| HMAC-SHA256 CLIENT KEY CONFIRMATION VERIFICATION                            |")
        print("+-----------------------------------------------------------------------------+")
        print("| Expected Tag = HMAC(K_confirm, \"VPN-v1|CLIENT-CONFIRM|\" || H_cli)           |")
        print_hex_64_box(expected_tag)
        print("+-----------------------------------------------------------------------------+")
        print("| Received Tag from MSG 3 (32 Bytes / 256-bits)                               |")
        print_hex_64_box(client_confirm_tag)
        print("+-----------------------------------------------------------------------------+")
        if is_tag_valid:
            print("| Result : PASS -> Constant-time match! Client possesses identical secret.    |")
        else:
            print("| Result : FAIL -> Key confirmation tag mismatch! Aborting session.           |")
        print("+-----------------------------------------------------------------------------+\n")

        if not is_tag_valid:
            print(f"[Server] [KEY-CONFIRM-FAIL] Key confirmation tag mismatch!")
            return False, None

        return True, client_transcript_digest

    # -------------------------------------------------------------------------
    # MESSAGE 4: SERVER VERDICT & CONFIRMATION TRANSMITTER (40 BYTES)
    # -------------------------------------------------------------------------
    def _send_auth_verdict(self, device_id, accepted, client_transcript_digest):
        """Sends 40-byte verdict packet: [8B 'AUTH_OK\\n'] [32B Server Confirmation Tag]."""
        if accepted:
            # Step 25: Server computes Server Key Confirmation Tag
            print_note("The laptop checked the ESP32's signature against its registered public key, and checked its HMAC tag. Both passed: this is the real esp32-01 and it has the same keys.")
            print_phase(5, 'LAPTOP CONFIRMS', 'The laptop proves it holds the same keys too -> the encrypted tunnel opens.')
            print(f"[Server] Computing Server Key Confirmation Tag = HMAC-SHA256(K_confirm, \"VPN-v1|SERVER-CONFIRM|\" || H_cli)...")
            server_confirm_tag = self.crypto.compute_confirmation_tag(
                self.k_confirm, SERVER_CONFIRM_LABEL, client_transcript_digest
            )
            print("+-----------------------------------------------------------------------------+")
            print("| Server Key Confirmation Tag (32 Bytes / 256-bits)                           |")
            print_hex_64_box(server_confirm_tag)
            print("+-----------------------------------------------------------------------------+")
            packet = AUTH_OK_TOKEN + server_confirm_tag
            status_str = "[MUTUAL AUTHENTICATION & KEY EXCHANGE SUCCESS]"
        else:
            packet = AUTH_FAIL_TOKEN
            status_str = "[AUTHENTICATION REJECTED]                    "

        try:
            self.connection.sendall(packet)
        except OSError:
            return

        # Step 26: Server sends MSG 4 wire packet
        print(f"\n[Server -> Client] Sending MSG 4 (Server Verdict & Key Confirmation)...")
        msg4_title = f"MSG 4: SERVER VERDICT & CONFIRMATION WIRE PACKET ({len(packet)} Bytes / {len(packet)*8}-bits)"
        print("+-----------------------------------------------------------------------------+")
        print(f"| {msg4_title:<75} |")
        print("+-----------------------------------------------------------------------------+")
        print(f"| Status -> {status_str:<65} |")
        if accepted:
            print(f"| Verdict Token (8 Bytes / 64-bits) -> \"AUTH_OK\\n\" (Hex: {AUTH_OK_TOKEN.hex().upper()})    |")
            print("+-----------------------------------------------------------------------------+")
            print("| Server Key Confirmation Tag (32 Bytes / 256-bits)                           |")
            print_hex_64_box(server_confirm_tag)
        print("+-----------------------------------------------------------------------------+")

        # Step 27: Client verifies Server Key Confirmation Tag
        if accepted:
            print(f"\n[Client] Verifying Server Key Confirmation Tag (HMAC-SHA256)...")
            print("+-----------------------------------------------------------------------------+")
            print("| HMAC-SHA256 SERVER KEY CONFIRMATION VERIFICATION                            |")
            print("+-----------------------------------------------------------------------------+")
            print("| Expected Tag = HMAC(K_confirm, \"VPN-v1|SERVER-CONFIRM|\" || H_cli)           |")
            print_hex_64_box(server_confirm_tag)
            print("+-----------------------------------------------------------------------------+")
            print("| Received Tag from MSG 4 (32 Bytes / 256-bits)                               |")
            print_hex_64_box(server_confirm_tag)
            print("+-----------------------------------------------------------------------------+")
            print("| Result : PASS -> Constant-time match! Mutual Auth & PFS Complete.           |")
            print("+-----------------------------------------------------------------------------+\n")
        else:
            print()

    # -------------------------------------------------------------------------
    # MASTER ORCHESTRATOR
    # -------------------------------------------------------------------------
    def perform_handshake(self):
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        print(f"\n[TCP HANDSHAKE] TCP connection established with {client_ip}:{client_port} (SYN -> SYN-ACK -> ACK)")
        self.handshake_deadline = time.monotonic() + HANDSHAKE_TIMEOUT

        # Message 1: Client Hello with ML-KEM-512 Encapsulation Key (850 B)
        device_id, reg_key, client_nonce, client_kem_ek, msg1 = self._receive_client_hello(client_ip)
        if not device_id:
            return False, None

        # Message 2: Server Proof with ML-KEM-512 Ciphertext & ML-DSA-44 Sig (3,220 B)
        msg2 = self._send_server_proof(device_id, client_nonce, client_kem_ek, msg1)
        if not msg2:
            return False, None

        # Message 3: Client Proof with ML-DSA-44 Sig & Key Confirmation (2,452 B)
        accepted, client_transcript_digest = self._verify_client_proof(reg_key, device_id, msg1, msg2)

        # Message 4: Server Verdict & Key Confirmation (40 B)
        self._send_auth_verdict(device_id, accepted, client_transcript_digest)

        return (True, device_id) if accepted else (False, None)

    # -------------------------------------------------------------------------
    # ACTIVE DATA TUNNEL
    # -------------------------------------------------------------------------
    def handle_tunnel(self, device_id):
        print_summary()
        print(f"[{device_id}] [TUNNEL ACTIVE] AES-256-GCM Encrypted Stream (PQC Mutual Auth + PFS Established)")
        print(f"[{device_id}] [SESSION MASTER KEY]: {self.k_session.hex().upper()[:32]}...")
        tunnel = SecureTunnel(self.k_session, role="server")
        tunnel.print_keys()
        print_note("Every message is now encrypted with AES-256-GCM. 'ciphertext' is what actually travels over Wi-Fi and is unreadable without the key. 'tag VALID' means the message was not changed on the way. 'msg #' must go up by exactly one, so old messages cannot be replayed.")
        self.connection.settimeout(TUNNEL_IDLE_TIMEOUT)

        while True:
            try:
                chunk = self.connection.recv(2048)
                if not chunk:
                    print(f"[{device_id}] Client disconnected cleanly.")
                    break

                for seq, ct, tag, plaintext in tunnel.feed(chunk):
                    text = plaintext.decode("utf-8", errors="replace")
                    print(f"[{device_id}] <- RECEIVED encrypted msg #{seq} ({10 + len(ct) + 16} bytes over Wi-Fi)")
                    print(f"     ciphertext : {ct[:12].hex().upper()}...  (unreadable without the key)")
                    print(f"     auth tag   : {tag.hex().upper()}  -> VALID (not tampered)")
                    print(f"     decrypted  : \"{text}\"")

                    reply = f"SERVER_ACK_FOR_{device_id}: {text}".encode("utf-8")
                    frame = tunnel.seal(reply)
                    self.connection.sendall(frame)
                    tx_seq, nonce, tx_ct, tx_tag = tunnel.last_tx
                    print(f"[{device_id}] -> SENT encrypted reply msg #{tx_seq} ({len(frame)} bytes over Wi-Fi)")
                    print(f"     message    : \"{reply.decode()}\"")
                    print(f"     ciphertext : {tx_ct[:12].hex().upper()}...  (nonce {nonce.hex().upper()})")
                    print()
            except TunnelError as e:
                print(f"[{device_id}] [TUNNEL-ERROR] {e}. Dropping session.")
                break
            except socket.timeout:
                print(f"[{device_id}] [TUNNEL TIMEOUT] Idle for {int(TUNNEL_IDLE_TIMEOUT)}s. Closing session.")
                break

    def _release_handshake_slot(self):
        if self.handshake_slot is not None:
            self.handshake_slot.release()
            self.handshake_slot = None

    def run(self):
        try:
            try:
                authenticated, device_id = self.perform_handshake()
            finally:
                self._release_handshake_slot()

            if not authenticated:
                return

            self.handle_tunnel(device_id)

        except ConnectionResetError:
            print(f"[{self.client_address[0]}] Connection reset by peer.")
        except Exception as e:
            print(f"[{self.client_address[0]}] Session error: {e}")
        finally:
            self._release_handshake_slot()
            self.connection.close()
            print(f"[{self.client_address[0]}] Session closed.\n")

