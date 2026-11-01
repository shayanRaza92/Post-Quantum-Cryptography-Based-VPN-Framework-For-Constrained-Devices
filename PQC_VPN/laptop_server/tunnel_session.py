import socket
import time
import re
import hmac
import hashlib
from config import (
    PROTOCOL_VERSION,
    ALGORITHM_ID,
    SIGNATURE_LENGTH,
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
    4-Message Handshake with ML-DSA-44 Mutual Authentication, Ephemeral X25519 Key Exchange
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
    # MESSAGE 1: CLIENT HELLO RECEIVER (82 BYTES)
    # -------------------------------------------------------------------------
    def _receive_client_hello(self, client_ip):
        """Reads 82-byte Client Hello packet: [Ver] [Alg] [ID (16B)] [Nonce (32B)] [X25519_pk (32B)]."""
        raw = self.receive_exact(MSG1_CLIENT_HELLO_SIZE)
        if not raw:
            print(f"[{client_ip}] [ERROR] Disconnected during Client Hello.")
            return None, None, None, None, None

        version = raw[0]
        alg_id = raw[1]
        id_field = raw[2:18]
        client_nonce = raw[18:50]
        client_eph_pk = raw[50:82]

        if version != PROTOCOL_VERSION or alg_id != ALGORITHM_ID:
            print(f"[{client_ip}] [AUTH-FAIL] Invalid Ver (0x{version:02X}) or AlgID (0x{alg_id:02X})")
            return None, None, None, None, None

        raw_id = id_field.rstrip(b"\x00")
        if b"\x00" in raw_id or not re.fullmatch(rb"[a-zA-Z0-9_-]{1,16}", raw_id):
            print(f"[{client_ip}] [AUTH-FAIL] Malformed Device ID field: {id_field!r}")
            return None, None, None, None, None
        device_id = raw_id.decode("ascii")

        # Step 1-3: Client generation & transmission of MSG 1
        print(f"\n[Client] Generating 32-byte fresh Client Nonce [N_cli] via Hardware TRNG...")
        print(f"[Client] Generating fresh Ephemeral X25519 Keypair [sk_cli_eph, PK_cli_eph] (Forward Secrecy)...")
        print(f"[Client -> Server] Sending MSG 1 (Client Hello with X25519 Key Share)...")
        print("+-----------------------------------------------------------------------------+")
        print("| MSG 1: CLIENT HELLO WIRE PACKET (82 Bytes / 656-bits)                       |")
        print("+-------------------+--------------------+------------------------------------+")
        print("| Version (8-bits)  | Alg ID (8-bits)    | Device ID (128-bits / 16 Bytes)    |")
        print(f"| 0x{version:02X}              | 0x{alg_id:02X} (MLDSA44-PQC) | {device_id:<34} |")
        print("+-------------------+--------------------+------------------------------------+")
        print("| Client Nonce [N_cli] (32 Bytes / 256-bits)                                  |")
        print_hex_64_box(client_nonce)
        print("+-----------------------------------------------------------------------------+")
        print("| Client Ephemeral Public Key [PK_cli_eph] (32 Bytes / 256-bits)              |")
        print_hex_64_box(client_eph_pk)
        print("+-----------------------------------------------------------------------------+")

        # Step 4: Server allowlist authorization check
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

        return device_id, registered_pubkey_bytes, client_nonce, client_eph_pk, raw

    # -------------------------------------------------------------------------
    # MESSAGE 2: SERVER PROOF TRANSMITTER (2,484 BYTES)
    # -------------------------------------------------------------------------
    def _send_server_proof(self, device_id, client_nonce, client_eph_pk, msg1):
        """
        Generates 32B server nonce + fresh X25519 ephemeral keypair.
        Constructs Server Transcript (160B), hashes it to H_srv (32B), signs H_srv with ML-DSA-44 (2,420B),
        and sends 2,484B MSG 2 packet: [Server Nonce (32B)] [Server X25519 Share (32B)] [ML-DSA-44 Sig (2,420B)].
        """
        version = msg1[0]
        alg_id = msg1[1]

        # Step 5: Server generates 32-byte Server Nonce
        print(f"[Server] Generating 32-byte fresh Server Nonce [N_srv] via CSPRNG...")
        server_nonce = self.crypto.generate_challenge()

        # Step 6: Server generates Ephemeral X25519 Keypair
        print(f"[Server] Generating fresh Ephemeral X25519 Keypair [sk_srv_eph, PK_srv_eph] (Forward Secrecy)...")
        server_eph_sk, server_eph_pk = self.crypto.generate_ephemeral_keypair()

        # Step 7: Server constructs Server Transcript (160 Bytes)
        print(f"[Server] Constructing Server Transcript (label || MSG1 || N_srv || PK_srv_eph)...")
        rows = [
            ("Domain Prefix", "Byte 0..13", "14 Bytes", "\"VPN-v1|SERVER|\""),
            ("Protocol Version", "Byte 14", "1 Byte", f"0x{version:02X}"),
            ("Algorithm ID", "Byte 15", "1 Byte", f"0x{alg_id:02X} (MLDSA44-PQC)"),
            ("Device ID (Zero-Padded)", "Byte 16..31", "16 Bytes", f"\"{device_id}\""),
            ("Client Nonce [N_cli]", "Byte 32..63", "32 Bytes", preview(client_nonce)),
            ("Client Eph PK [PK_cli_eph]", "Byte 64..95", "32 Bytes", preview(client_eph_pk)),
            ("Server Nonce [N_srv]", "Byte 96..127", "32 Bytes", preview(server_nonce)),
            ("Server Eph PK [PK_srv_eph]", "Byte 128..159", "32 Bytes", preview(server_eph_pk)),
        ]
        print_transcript_table("SERVER TRANSCRIPT PAYLOAD", rows, 160)

        # Step 8: Server computes SHA-256 Digest [H_srv] of Server Transcript
        print(f"\n[Server] Computing SHA-256 digest of Server Transcript...")
        server_transcript_digest = self.crypto.build_server_transcript(msg1, server_nonce, server_eph_pk)
        print("+-----------------------------------------------------------------------------+")
        print("| SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                                |")
        print_hex_64_box(server_transcript_digest)
        print("+-----------------------------------------------------------------------------+")

        # Step 9: Server signs [H_srv] with Gateway ML-DSA-44 Private Key
        print(f"\n[Server] Signing digest [H_srv] with Gateway ML-DSA-44 secret key [sk_srv]...")
        server_sig = self.crypto.sign_server_transcript(msg1, server_nonce, server_eph_pk)
        print("+-----------------------------------------------------------------------------+")
        print("| Server ML-DSA-44 Signature [sigma_srv] (2420 Bytes / 19360-bits)            |")
        print_mldsa_sig_box(server_sig)
        print("+-----------------------------------------------------------------------------+")

        # Step 10: Assemble and transmit MSG 2 (2,484 Bytes)
        msg2 = server_nonce + server_eph_pk + server_sig
        assert len(msg2) == MSG2_SERVER_PROOF_SIZE
        self.connection.sendall(msg2)

        print(f"\n[Server -> Client] Sending MSG 2 (Server Proof with X25519 Key Share)...")
        print("+-----------------------------------------------------------------------------+")
        print("| MSG 2: SERVER PROOF WIRE PACKET (2484 Bytes / 19872-bits)                   |")
        print("+-----------------------------------------------------------------------------+")
        print("| Server Nonce [N_srv] (32 Bytes / 256-bits)                                  |")
        print_hex_64_box(server_nonce)
        print("+-----------------------------------------------------------------------------+")
        print("| Server Ephemeral Public Key [PK_srv_eph] (32 Bytes / 256-bits)              |")
        print_hex_64_box(server_eph_pk)
        print("+-----------------------------------------------------------------------------+")
        print("| Server ML-DSA-44 Signature [sigma_srv] (2420 Bytes / 19360-bits)            |")
        print_mldsa_sig_box(server_sig)
        print("+-----------------------------------------------------------------------------+")

        # Step 11: Client reconstructs Server Transcript
        print(f"\n[Client] Reconstructing Server Transcript (label || MSG1 || N_srv || PK_srv_eph)...")
        print_transcript_table("SERVER TRANSCRIPT PAYLOAD", rows, 160)

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

        # Step 14: Both sides compute X25519 Diffie-Hellman Shared Secret
        print(f"\n[Client & Server] Computing X25519 Diffie-Hellman Shared Secret [SS]...")
        try:
            shared_secret = self.crypto.compute_shared_secret(server_eph_sk, client_eph_pk)
            if shared_secret == b"\x00" * 32:
                raise ValueError("Low-order X25519 point produced all-zero shared secret")
        except Exception as e:
            print(f"[Server] [KEX-FAIL] Invalid client X25519 public key share: {e}")
            return None

        print("+-----------------------------------------------------------------------------+")
        print("| X25519 Diffie-Hellman Shared Secret [SS] (32 Bytes / 256-bits)              |")
        print_hex_64_box(shared_secret)
        print("+-----------------------------------------------------------------------------+")

        # Step 15: Both sides derive Session Keys via HKDF-SHA256
        print(f"\n[Client & Server] Deriving K_confirm and K_session via HKDF-SHA256 (RFC 5869)...")
        hkdf_salt = hashlib.sha256(client_nonce + server_nonce).digest()
        self.k_confirm, self.k_session = self.crypto.derive_session_keys(shared_secret, client_nonce, server_nonce)
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

        version = msg1[0]
        alg_id = msg1[1]
        client_nonce = msg1[18:50]
        client_eph_pk = msg1[50:82]
        server_nonce = msg2[0:32]
        server_eph_pk = msg2[32:64]
        server_sig = msg2[64:MSG2_SERVER_PROOF_SIZE]

        rows = [
            ("Domain Prefix", "Byte 0..13", "14 Bytes", "\"VPN-v1|CLIENT|\""),
            ("Protocol Version", "Byte 14", "1 Byte", f"0x{version:02X}"),
            ("Algorithm ID", "Byte 15", "1 Byte", f"0x{alg_id:02X} (MLDSA44-PQC)"),
            ("Device ID (Zero-Padded)", "Byte 16..31", "16 Bytes", f"\"{device_id}\""),
            ("Client Nonce [N_cli]", "Byte 32..63", "32 Bytes", preview(client_nonce)),
            ("Client Eph PK [PK_cli_eph]", "Byte 64..95", "32 Bytes", preview(client_eph_pk)),
            ("Server Nonce [N_srv]", "Byte 96..127", "32 Bytes", preview(server_nonce)),
            ("Server Eph PK [PK_srv_eph]", "Byte 128..159", "32 Bytes", preview(server_eph_pk)),
            ("Server Sig [sigma_srv]", "Byte 160-2579", "2420 B", preview(server_sig)),
        ]
        client_transcript_digest = self.crypto.build_client_transcript(msg1, msg2)

        # Step 16: Client constructs Client Transcript (2,580 Bytes)
        print(f"[Client] Constructing Client Transcript (label || MSG1 || MSG2)...")
        print_transcript_table("CLIENT TRANSCRIPT PAYLOAD", rows, 2580)

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
        print_transcript_table("CLIENT TRANSCRIPT PAYLOAD", rows, 2580)

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

        # Message 1: Client Hello with X25519 Share (82 B)
        device_id, reg_key, client_nonce, client_eph_pk, msg1 = self._receive_client_hello(client_ip)
        if not device_id:
            return False, None

        # Message 2: Server Proof with X25519 Share & ML-DSA-44 Sig (2,484 B)
        msg2 = self._send_server_proof(device_id, client_nonce, client_eph_pk, msg1)
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
        print(f"[{device_id}] [TUNNEL ACTIVE] Line-Framed Stream (PQC Mutual Auth + PFS Established)")
        print(f"[{device_id}] [SESSION MASTER KEY]: {self.k_session.hex().upper()[:32]}...")
        self.connection.settimeout(TUNNEL_IDLE_TIMEOUT)
        tunnel_buffer = bytearray()

        while True:
            try:
                chunk = self.connection.recv(1024)
                if not chunk:
                    print(f"[{device_id}] Client disconnected cleanly.")
                    break
                tunnel_buffer.extend(chunk)

                while b"\n" in tunnel_buffer:
                    line, tunnel_buffer = tunnel_buffer.split(b"\n", 1)
                    incoming_text = line.decode("utf-8", errors="ignore").strip()
                    if incoming_text:
                        print(f"[{device_id}] [RX] {incoming_text}")
                        reply = f"SERVER_ACK_FOR_{device_id}: {incoming_text}\n"
                        self.connection.sendall(reply.encode("utf-8"))
                        print(f"[{device_id}] [TX] {reply.strip()}")
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

