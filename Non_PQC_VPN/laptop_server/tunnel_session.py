import socket  # Network socket library for TCP communications
import time    # High-resolution monotonic timers for deadline enforcement
import re      # Regular expressions for strict device ID sanitization
from config import (
    PROTOCOL_VERSION,        # Protocol version identifier (0x01)
    ALGORITHM_ID,            # Cipher suite identifier (0x01: Ed25519-SHA256)
    MSG1_CLIENT_HELLO_SIZE,  # 50-byte Client Hello (Version + AlgID + ID + Nonce)
    MSG2_SERVER_PROOF_SIZE,  # 96-byte Server Proof (Server Nonce + Server Sig)
    MSG3_CLIENT_PROOF_SIZE,  # 64-byte Client Proof (Client Signature over Client Transcript)
    AUTH_OK_TOKEN,           # 8-byte success verdict (b"AUTH_OK\n")
    AUTH_FAIL_TOKEN,         # 8-byte failure verdict (b"AUTH_NO\n")
    SERVER_TRANSCRIPT_LABEL, # b"VPN-v1|SERVER|"
    CLIENT_TRANSCRIPT_LABEL, # b"VPN-v1|CLIENT|"
    HANDSHAKE_TIMEOUT,       # Overall 10.0 seconds allowed to complete handshake
    TUNNEL_IDLE_TIMEOUT      # Inactivity timeout for authenticated data tunnel
)


def print_hex_64_box(data_bytes):
    """Prints up to 64 bytes in 32-byte (64 hex characters) lines formatted to 75 chars."""
    hex_str = data_bytes.hex().upper()
    if len(hex_str) <= 64:
        print(f"| {hex_str:<75} |")
    else:
        print(f"| {hex_str[:64]:<75} |")
        print(f"| {hex_str[64:]:<75} |")


def print_transcript_table(title, rows, total_len):
    """Prints a structured transcript payload table showing exact byte offsets and sizes."""
    c1, c2, c3, c4 = 26, 13, 9, 18
    sep_inner = f"+{'-'*(c1+2)}+{'-'*(c2+2)}+{'-'*(c3+2)}+{'-'*(c4+2)}+"
    sep_outer = "+" + "-"*77 + "+"

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
    """Short hex preview: first 6 bytes .. last 2 bytes (fits the 18-char table column)."""
    return f"{data[:6].hex().upper()}..{data[-2:].hex().upper()}"


def msg1_rows(label, msg1):
    """Transcript rows for the label + the raw 50-byte MSG 1 (bytes 0..63 of every transcript)."""
    device_id = msg1[2:18].rstrip(b"\x00").decode("utf-8", errors="replace")
    return [
        ("Domain Prefix", "Byte 0..13", "14 Bytes", f"\"{label.decode()}\""),
        ("MSG1 Version", "Byte 14", "1 Byte", f"0x{msg1[0]:02X}"),
        ("MSG1 Algorithm ID", "Byte 15", "1 Byte", f"0x{msg1[1]:02X} (Ed25519)"),
        ("MSG1 Device ID (0-padded)", "Byte 16..31", "16 Bytes", f"\"{device_id}\""[:18]),
        ("MSG1 Client Nonce [N_cli]", "Byte 32..63", "32 Bytes", preview(msg1[18:50])),
    ]


class VpnSession:
    """
    Manages the lifecycle of a single connected ESP32 client:
    Option A 4-Message Handshake -> Line-Framed Data Tunnel.
    Prints ONLY the work the server itself performs. The client's side
    (verifying the server signature, signing its own transcript) is printed
    on the ESP32 Serial Monitor.
    """

    def __init__(self, connection, client_address, crypto_engine, allowlist, handshake_slot=None):
        self.connection = connection          # TCP socket connection object for this client
        self.client_address = client_address  # Tuple containing (client_ip, client_port)
        self.crypto = crypto_engine            # GatewayCrypto instance for signing and verifying
        self.allowlist = allowlist            # DeviceAllowlist instance for checking registrations
        self.handshake_deadline = 0.0         # Monotonic timestamp deadline for entire handshake
        self.handshake_slot = handshake_slot  # Optional semaphore released when the handshake ends

    def receive_exact(self, expected_byte_count):
        """
        Reads exactly expected_byte_count bytes from the TCP stream.
        Enforces a cumulative handshake deadline to defeat drip-feed Slowloris attacks.
        """
        buffer = bytearray()
        while len(buffer) < expected_byte_count:
            if self.handshake_deadline > 0:
                time_remaining = self.handshake_deadline - time.monotonic()
                if time_remaining <= 0:
                    return None  # Total handshake deadline expired
                self.connection.settimeout(min(time_remaining, 5.0))

            try:
                chunk = self.connection.recv(expected_byte_count - len(buffer))
                if not chunk:
                    return None  # Connection closed by client
                buffer.extend(chunk)
            except socket.timeout:
                return None
        return bytes(buffer)

    # -------------------------------------------------------------------------
    # MESSAGE 1: CLIENT HELLO RECEIVER & PACKET HEADER DISPLAY
    # -------------------------------------------------------------------------
    def _receive_client_hello(self, client_ip):
        """
        Reads 50-byte Client Hello packet:
        [1B Version] [1B AlgID] [16B Device ID (zero-padded)] [32B Client Nonce]
        Returns (device_id, registered_pubkey_bytes, raw_msg1) or (None, None, None).
        """
        raw = self.receive_exact(MSG1_CLIENT_HELLO_SIZE)
        if not raw:
            print(f"[{client_ip}] [ERROR] Disconnected during Client Hello.")
            return None, None, None

        version = raw[0]
        alg_id = raw[1]
        id_field = raw[2:18]
        client_nonce = raw[18:50]

        # Verify Protocol Version and Algorithm Suite (Downgrade Defense)
        if version != PROTOCOL_VERSION or alg_id != ALGORITHM_ID:
            print(f"[{client_ip}] [AUTH-FAIL] Invalid Ver (0x{version:02X}) or AlgID (0x{alg_id:02X})")
            return None, None, None

        # Device ID must be 1-16 allowed chars followed only by zero padding.
        # (Strict check: the raw 16 bytes are signed, so they must have one canonical form.)
        raw_id = id_field.rstrip(b"\x00")
        if b"\x00" in raw_id or not re.fullmatch(rb"[a-zA-Z0-9_-]{1,16}", raw_id):
            print(f"[{client_ip}] [AUTH-FAIL] Malformed Device ID field: {id_field!r}")
            return None, None, None
        device_id = raw_id.decode("ascii")

        # Print structured packet payload diagram (strictly the 50 bytes received over the wire)
        print("\n+-----------------------------------------------------------------------------+")
        print("| MSG 1: CLIENT HELLO WIRE PACKET (50 Bytes / 400-bits)                       |")
        print("+-------------------+--------------------+------------------------------------+")
        print("| Version (8-bits)  | Alg ID (8-bits)    | Device ID (128-bits / 16 Bytes)    |")
        print(f"| 0x{version:02X}              | 0x{alg_id:02X}               | {device_id:<34} |")
        print("+-------------------+--------------------+------------------------------------+")
        print("| Client Nonce [N_cli] (32 Bytes / 256-bits)                                  |")
        print_hex_64_box(client_nonce)
        print("+-----------------------------------------------------------------------------+")

        # Authorize client via local server database (local step, NOT in the wire packet)
        print(f"\n[{device_id}] [AUTHORIZATION] Checking Device ID '{device_id}' against local allowlist database...")
        registered_pubkey_bytes = self.allowlist.get_device_public_key(device_id)
        if not registered_pubkey_bytes:
            print(f"[{device_id}] [AUTHORIZATION] Status: DENIED (Device ID not in allowlist)")
            return None, None, None
        print(f"[{device_id}] [AUTHORIZATION] Status: ALLOWED (Authorized client public key loaded from database)\n")

        return device_id, registered_pubkey_bytes, raw

    # -------------------------------------------------------------------------
    # MESSAGE 2: SERVER PROOF TRANSMITTER (SERVER AUTHENTICATES FIRST!)
    # -------------------------------------------------------------------------
    def _send_server_proof(self, device_id, msg1):
        """
        Generates 32B server nonce, signs the Server Transcript, and sends the 96B packet:
        [32B Server Nonce] [64B Server Signature]
        Returns the raw 96-byte MSG 2 (needed for the Client Transcript).
        """
        print(f"[{device_id}] Server generating 32-byte fresh Server Nonce [N_srv] via CSPRNG...")
        server_nonce = self.crypto.generate_challenge()

        print(f"[{device_id}] Server constructing Server Transcript (label || MSG1 || N_srv)...")
        rows = msg1_rows(SERVER_TRANSCRIPT_LABEL, msg1) + [
            ("Server Nonce [N_srv]", "Byte 64..95", "32 Bytes", preview(server_nonce)),
        ]
        print_transcript_table("SERVER TRANSCRIPT PAYLOAD", rows, len(SERVER_TRANSCRIPT_LABEL) + len(msg1) + len(server_nonce))

        print(f"\n[{device_id}] Server computing SHA-256 digest...")
        server_transcript_digest = self.crypto.build_server_transcript(msg1, server_nonce)
        print("+-----------------------------------------------------------------------------+")
        print("| SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                                |")
        print_hex_64_box(server_transcript_digest)
        print("+-----------------------------------------------------------------------------+")

        print(f"\n[{device_id}] Server signing digest with private key...")
        server_sig = self.crypto.sign_server_transcript(msg1, server_nonce)
        print("+-----------------------------------------------------------------------------+")
        print("| Server Signature [sigma_srv] (64 Bytes / 512-bits)                          |")
        print_hex_64_box(server_sig)
        print("+-----------------------------------------------------------------------------+")

        msg2 = server_nonce + server_sig
        assert len(msg2) == MSG2_SERVER_PROOF_SIZE
        self.connection.sendall(msg2)

        print(f"\n[{device_id}] Server sending MSG 2 (client will verify it against its pinned key)...")
        print("+-----------------------------------------------------------------------------+")
        print("| MSG 2: SERVER PROOF WIRE PACKET (96 Bytes / 768-bits)                       |")
        print("+-----------------------------------------------------------------------------+")
        print("| Server Nonce [N_srv] (32 Bytes / 256-bits)                                  |")
        print_hex_64_box(server_nonce)
        print("+-----------------------------------------------------------------------------+")
        print("| Server Signature [sigma_srv] (64 Bytes / 512-bits)                          |")
        print_hex_64_box(server_sig)
        print("+-----------------------------------------------------------------------------+")
        print(f"\n[{device_id}] Waiting for MSG 3 (Client Proof)...\n")

        return msg2

    # -------------------------------------------------------------------------
    # MESSAGE 3: CLIENT PROOF RECEIVER & TRANSCRIPT VERIFIER
    # -------------------------------------------------------------------------
    def _verify_client_proof(self, registered_pubkey_bytes, device_id, msg1, msg2):
        """
        Receives the 64-byte client signature and verifies it over the Client Transcript
        (label || MSG1 || MSG2) using the device's registered public key.
        """
        client_sig = self.receive_exact(MSG3_CLIENT_PROOF_SIZE)
        if not client_sig:
            print(f"[{device_id}] [AUTH-FAIL] Connection dropped or timed out waiting for Client Proof.")
            return False

        # 1. Print MSG 3 wire packet received from client
        print("+-----------------------------------------------------------------------------+")
        print("| MSG 3: CLIENT PROOF WIRE PACKET (64 Bytes / 512-bits)                       |")
        print("+-----------------------------------------------------------------------------+")
        print("| Client Signature [sigma_cli] (64 Bytes / 512-bits)                          |")
        print_hex_64_box(client_sig)
        print("+-----------------------------------------------------------------------------+")

        # 2. Server reconstructing Client Transcript
        print(f"\n[{device_id}] Server reconstructing Client Transcript (label || MSG1 || MSG2)...")
        rows = msg1_rows(CLIENT_TRANSCRIPT_LABEL, msg1) + [
            ("MSG2 Server Nonce [N_srv]", "Byte 64..95", "32 Bytes", preview(msg2[:32])),
            ("MSG2 Server Sig [sig_srv]", "Byte 96..159", "64 Bytes", preview(msg2[32:])),
        ]
        print_transcript_table("CLIENT TRANSCRIPT PAYLOAD", rows, len(CLIENT_TRANSCRIPT_LABEL) + len(msg1) + len(msg2))

        # 3. Server hashing Client Transcript
        print(f"\n[{device_id}] Server hashing Client Transcript (SHA-256)...")
        client_transcript_digest = self.crypto.build_client_transcript(msg1, msg2)
        print("+-----------------------------------------------------------------------------+")
        print("| Expected SHA-256 Digest [H_cli] (32 Bytes / 256-bits)                       |")
        print_hex_64_box(client_transcript_digest)
        print("+-----------------------------------------------------------------------------+")

        # 4. Server verifying Client Signature against the registered public key (REAL check)
        print(f"\n[{device_id}] Server verifying Client Signature against registered public key...")
        is_valid = self.crypto.verify_client_transcript(registered_pubkey_bytes, client_sig, msg1, msg2)

        pk_preview = f"{registered_pubkey_bytes[:4].hex().upper()}..{registered_pubkey_bytes[-2:].hex().upper()}"
        h_preview = f"{client_transcript_digest[:4].hex().upper()}..{client_transcript_digest[-2:].hex().upper()}"
        r_preview = f"{client_sig[:4].hex().upper()}..{client_sig[30:32].hex().upper()}"
        s_preview = f"{client_sig[32:36].hex().upper()}..{client_sig[-2:].hex().upper()}"

        print("+-----------------------------------------------------------------------------+")
        print("| ED25519 SIGNATURE VERIFICATION WORKING                                      |")
        print("+-----------------------------------------------------------------------------+")
        print(f"| Input 1: Client Public Key [PK_cli]     : {pk_preview:<34}|")
        print(f"| Input 2: Transcript Digest [H_cli]      : {h_preview:<34}|")
        print(f"| Input 3: Signature Point [R] (32 Bytes) : {r_preview:<34}|")
        print(f"| Input 4: Signature Scalar [s] (32 Bytes): {s_preview:<34}|")
        print("+-----------------------------------------------------------------------------+")
        print("| Step 1: Compute challenge scalar k = SHA-512(R || PK_cli || H_cli)          |")
        print("| Step 2: Evaluate Curve Equation   : [s]B == R + [k]PK_cli                   |")
        if is_valid:
            print("| Result : PASS -> Point identity matches! Client signature is authentic.     |")
        else:
            print("| Result : FAIL -> Point mismatch! Invalid client signature. Aborting.        |")
        print("+-----------------------------------------------------------------------------+\n")

        return is_valid

    # -------------------------------------------------------------------------
    # MESSAGE 4: SERVER VERDICT TRANSMITTER
    # -------------------------------------------------------------------------
    def _send_auth_verdict(self, device_id, accepted):
        """Sends the 8-byte verdict: AUTH_OK\\n on success, AUTH_NO\\n on failure."""
        token = AUTH_OK_TOKEN if accepted else AUTH_FAIL_TOKEN
        try:
            self.connection.sendall(token)
        except OSError:
            return  # Client already gone; nothing to report

        status = "[MUTUAL AUTHENTICATION SUCCESS]" if accepted else "[AUTHENTICATION REJECTED]     "
        text = token.decode().strip()
        print("+-----------------------------------------------------------------------------+")
        print("| MSG 4: SERVER VERDICT WIRE PACKET (8 Bytes / 64-bits)                       |")
        print("+-----------------------------------------------------------------------------+")
        print(f"| Verdict Token (8 Bytes / 64-bits) -> {status:<39}|")
        print(f"| {chr(34) + text + chr(92) + 'n' + chr(34) + ' (Hex: ' + token.hex().upper() + ')':<75} |")
        print("+-----------------------------------------------------------------------------+\n")

    # -------------------------------------------------------------------------
    # MASTER ORCHESTRATOR: 4-MESSAGE MUTUAL AUTHENTICATION HANDSHAKE
    # -------------------------------------------------------------------------
    def perform_handshake(self):
        """
        Coordinates the 4-message handshake sequentially with deadline enforcement.
        Returns: (True, device_id) on success, or (False, None) on failure.
        """
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        print(f"\n[TCP HANDSHAKE] TCP connection established with {client_ip}:{client_port} (SYN -> SYN-ACK -> ACK)")
        self.handshake_deadline = time.monotonic() + HANDSHAKE_TIMEOUT

        # Message 1: Client Hello (50 B)
        device_id, reg_key, msg1 = self._receive_client_hello(client_ip)
        if not device_id:
            return False, None

        # Message 2: Server Proof (96 B) - Server authenticates first
        msg2 = self._send_server_proof(device_id, msg1)

        # Message 3: Client Proof (64 B) - Client signs label || MSG1 || MSG2
        accepted = self._verify_client_proof(reg_key, device_id, msg1, msg2)

        # Message 4: Server Verdict (8 B) - always sent so the client never hangs
        self._send_auth_verdict(device_id, accepted)

        return (True, device_id) if accepted else (False, None)

    # -------------------------------------------------------------------------
    # ACTIVE DATA TUNNEL (LINE-BUFFERED STREAM FRAMING & IDLE TIMEOUT)
    # -------------------------------------------------------------------------
    def handle_tunnel(self, device_id):
        """
        Maintains the active data tunnel.
        Implements line-buffered stream framing (newline-delimited) and idle timeout.
        NOTE: Tunnel traffic is not yet encrypted/authenticated (no session key);
        key exchange is planned as the next step.
        """
        print(f"[{device_id}] [TUNNEL ACTIVE] Line-Framed Stream (Idle Timeout: {int(TUNNEL_IDLE_TIMEOUT)}s)")
        self.connection.settimeout(TUNNEL_IDLE_TIMEOUT)
        tunnel_buffer = bytearray()

        while True:
            try:
                chunk = self.connection.recv(1024)
                if not chunk:
                    print(f"[{device_id}] Client disconnected cleanly.")
                    break
                tunnel_buffer.extend(chunk)

                # Process complete newline-delimited messages
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
        """Runs the complete session lifecycle: Handshake -> Tunnel -> Clean socket close."""
        try:
            try:
                authenticated, device_id = self.perform_handshake()
            finally:
                self._release_handshake_slot()  # Free the slot whether the handshake passed or failed

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
