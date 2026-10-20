import socket  # Network socket library for TCP communications
from config import (
    DEVICE_ID_LENGTH,        # 16-byte fixed buffer size for device identifier
    CHALLENGE_NONCE_LENGTH,  # 32-byte fresh random challenge number
    SIGNATURE_LENGTH,        # 64-byte Ed25519 digital signature length
    AUTH_CONFIRMATION_TOKEN, # 7-byte confirmation token ("AUTH_OK") sent by ESP32
    HANDSHAKE_TIMEOUT        # 10.0 seconds allowed to finish the handshake
)


class VpnSession:
    """Manages the lifecycle of a single connected ESP32 client: Handshake then Data Tunnel."""

    def __init__(self, connection, client_address, crypto_engine, allowlist):
        self.connection = connection          # TCP socket connection object for this client
        self.client_address = client_address  # Tuple containing (client_ip, client_port)
        self.crypto = crypto_engine            # GatewayCrypto instance for signing and verifying
        self.allowlist = allowlist            # DeviceAllowlist instance for checking registrations

    def receive_exact(self, expected_byte_count):  # Keeps reading until exactly expected_byte_count arrives
        buffer = bytearray()                       # Temporary buffer to assemble incoming chunks
        while len(buffer) < expected_byte_count:   # Loop until all required bytes are gathered
            try:
                remaining = expected_byte_count - len(buffer)  # Calculate bytes still needed
                chunk = self.connection.recv(remaining)        # Read next packet chunk from socket
                if not chunk:                                  # Empty read indicates client disconnected
                    return None
                buffer.extend(chunk)                           # Append newly arrived chunk to buffer
            except socket.timeout:                             # Return None if client takes too long
                return None
        return bytes(buffer)                                   # Convert bytearray to immutable bytes and return

    def perform_handshake(self):
        """
        Executes the security handshake:
        Stage 1: Authorization check via allowlist
        Stage 2: Mutual authentication challenge-response via Ed25519 signatures
        Stage 3: Client confirms server verification (AUTH_OK)
        """
        client_ip = self.client_address[0]  # Grab client IP address string
        print(f"\n[{client_ip}:{self.client_address[1]}] Starting handshake...")

        # --- STAGE 1: Authorization Check ---
        raw_id_packet = self.receive_exact(DEVICE_ID_LENGTH)  # Read 16-byte device ID packet
        if not raw_id_packet:
            print(f"[{client_ip}] Disconnected during identification.")
            return False, None

        device_id = raw_id_packet.decode("utf-8", errors="ignore").rstrip("\x00").strip()  # Clean string
        print(f"[{device_id}] [AUTHORIZATION] Claimed ID: \"{device_id}\"")

        # Check if this device name is pre-registered in the allowlist
        registered_pubkey_bytes = self.allowlist.get_device_public_key(device_id)
        if not registered_pubkey_bytes:
            print(f"[{device_id}] [AUTHORIZATION] DENIED - device not in allowlist.")
            return False, None  # Drop connection immediately if unregistered

        print(f"[{device_id}] [AUTHORIZATION] APPROVED - registered key: {registered_pubkey_bytes.hex()}")

        # --- STAGE 2: Mutual Authentication ---
        print(f"[{device_id}] [AUTHENTICATION] Sending challenge...")
        server_challenge_nonce = self.crypto.generate_challenge()   # Generate 32 fresh random bytes
        self.connection.sendall(server_challenge_nonce)             # Send challenge nonce to ESP32

        # Receive ESP32 response: 64-byte signature + 32-byte client challenge = 96 bytes
        client_response = self.receive_exact(SIGNATURE_LENGTH + CHALLENGE_NONCE_LENGTH)
        if not client_response:
            print(f"[{device_id}] Connection dropped waiting for client authentication response.")
            return False, None

        esp32_signature = client_response[:SIGNATURE_LENGTH]        # First 64 bytes are client signature
        esp32_challenge_nonce = client_response[SIGNATURE_LENGTH:]  # Remaining 32 bytes are client challenge

        # Verify client's signature against the public key registered in the allowlist
        is_valid = self.crypto.verify_client_signature(
            registered_pubkey_bytes,
            esp32_signature,
            server_challenge_nonce
        )

        if not is_valid:
            print(f"[{device_id}] [AUTHENTICATION] Client signature INVALID.")
            return False, None  # Signature verification failed; drop connection

        print(f"[{device_id}] [AUTHENTICATION] Client signature VALID.")

        # Sign the ESP32's challenge nonce to prove server's own identity
        server_signature = self.crypto.sign_challenge(esp32_challenge_nonce)
        self.connection.sendall(server_signature)  # Send 64-byte server proof back to ESP32
        print(f"[{device_id}] [AUTHENTICATION] Server proof sent. Waiting for client confirmation...")

        # --- STAGE 3: Client Confirms Server Verification ---
        # The client will only send AUTH_OK if it successfully verified our server proof
        confirmation = self.receive_exact(len(AUTH_CONFIRMATION_TOKEN))
        if confirmation != AUTH_CONFIRMATION_TOKEN:
            print(f"[{device_id}] [AUTHENTICATION] FAILED - Client rejected server identity or disconnected!")
            return False, None

        print(f"[{device_id}] [AUTHENTICATION] Client accepted server proof (AUTH_OK).")
        print(f"[{device_id}] Mutual authentication successful.\n")
        return True, device_id  # Handshake fully verified and confirmed on both sides!

    def handle_tunnel(self, device_id):
        """Maintains the active data tunnel and responds to incoming client data packets."""
        print(f"[{device_id}] [TUNNEL ACTIVE] Ready for data transmission.\n")

        while True:  # Tunnel loop
            raw_data = self.connection.recv(1024)  # Wait for incoming data packet from ESP32
            if not raw_data:
                print(f"[{device_id}] Client disconnected.")
                break  # Exit loop when client disconnects

            incoming_text = raw_data.decode("utf-8", errors="ignore").strip()  # Decode incoming message
            if incoming_text:
                print(f"[{device_id}] [RX] {incoming_text}")  # Print received client message
                reply = f"SERVER_ACK_FOR_{device_id}: {incoming_text}\n"  # Construct server ACK reply
                self.connection.sendall(reply.encode("utf-8"))            # Send ACK back to ESP32
                print(f"[{device_id}] [TX] {reply.strip()}")

    def run(self):
        """Runs the complete session lifecycle: Handshake -> Tunnel -> Clean socket close."""
        self.connection.settimeout(HANDSHAKE_TIMEOUT)  # Set 10-second timeout for handshake

        try:
            authenticated, device_id = self.perform_handshake()  # Run the security handshake
            if not authenticated:
                self.connection.close()  # Drop socket if handshake fails
                return

            self.connection.settimeout(None)  # Remove timeout so tunnel can run indefinitely
            self.handle_tunnel(device_id)      # Run active data tunnel loop

        except ConnectionResetError:
            print(f"[{self.client_address[0]}] Connection reset by peer.")
        except Exception as e:
            print(f"[{self.client_address[0]}] Session error: {e}")
        finally:
            self.connection.close()  # Ensure socket is freed in all cases
            print(f"[{self.client_address[0]}] Session closed. Waiting for new connection...\n")
