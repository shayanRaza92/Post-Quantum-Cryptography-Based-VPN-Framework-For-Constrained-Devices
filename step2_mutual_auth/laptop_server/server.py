import socket
import os
from cryptography.hazmat.primitives.asymmetric import ed25519

# Server Ed25519 Keypair (Raw 32-byte seed)
SERVER_PRIV_BYTES = bytes.fromhex(
    "c765812d5a94054cbbead0e4335b248329891fbc0343fbee337d2399db1186fb"
)
server_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(SERVER_PRIV_BYTES)
server_public_key = server_private_key.public_key()

# Authorized ESP32 Client Public Key
CLIENT_PUB_BYTES = bytes.fromhex(
    "7edd147c31ad36a424d378610ef89dd38c0922a8a9bb1402bcd20b975f8a0e31"
)
client_public_key = ed25519.Ed25519PublicKey.from_public_bytes(CLIENT_PUB_BYTES)

HOST = "0.0.0.0"
PORT = 9000

CHALLENGE_LEN = 32
SIGNATURE_LEN = 64


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


def recv_exact(conn, n):
    """Receive exactly n bytes from the socket."""
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


def authenticate_client(conn):
    print("\n[MUTUAL AUTHENTICATION]")

    # Step 1: Generate server challenge and send to ESP32
    laptop_challenge = os.urandom(CHALLENGE_LEN)
    conn.sendall(laptop_challenge)

    print("[MSG1] Server Challenge")
    print(f"       Length         : {CHALLENGE_LEN} bytes")
    print(f"       Nonce (Hex)    : {laptop_challenge.hex()}")
    print("       Status         : SENT")

    # Step 2: Receive ESP32 response (64-byte Ed25519 signature + 32-byte ESP32 challenge)
    data = recv_exact(conn, SIGNATURE_LEN + CHALLENGE_LEN)
    if not data:
        print("[FAIL] ESP32 disconnected during authentication")
        return False

    client_sig = data[:SIGNATURE_LEN]
    esp32_challenge = data[SIGNATURE_LEN:]

    print("\n[MSG2] ESP32 Authentication Proof")
    print("       Algorithm      : Ed25519 Digital Signature")
    print(f"       Signature (Hex): {client_sig.hex()}")
    print(f"       Client Nonce   : {esp32_challenge.hex()}")
    print("       Status         : RECEIVED")

    # Verify ESP32 signature
    try:
        client_public_key.verify(client_sig, laptop_challenge)
        print("\n[VERIFY] ESP32 Digital Signature")
        print("         Result       : SUCCESS (Valid Ed25519 Signature)")
    except Exception:
        print("\n[VERIFY] ESP32 Digital Signature")
        print("         Result       : FAILED (Invalid Signature / Untrusted Client)")
        return False

    # Step 3: Server signs ESP32's challenge with its private key
    laptop_sig = server_private_key.sign(esp32_challenge)
    conn.sendall(laptop_sig)

    print("\n[MSG3] Server Authentication Proof")
    print("       Algorithm      : Ed25519 Digital Signature")
    print(f"       Signature (Hex): {laptop_sig.hex()}")
    print("       Status         : SENT")

    print("\n============================================================")
    print("        MUTUAL AUTHENTICATION SUCCESSFUL (Ed25519)")
    print("============================================================\n")
    print("[DATA TUNNEL]")
    return True


def main():
    local_ip = get_local_ip()

    print("\n============================================================")
    print("         PQC VPN - LAPTOP GATEWAY (Ed25519 AUTH)")
    print("============================================================")
    print("\n[NETWORK]")
    print("[OK] Server listening")
    print(f"     Server IP      : {local_ip}")
    print(f"     Server Port    : {PORT}")
    print(f"     Server PubKey  : {server_public_key.public_bytes_raw().hex()}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(5)

        while True:
            print("\n[TCP TRANSPORT]")
            print("Waiting for ESP32 connection...")
            conn, addr = server.accept()
            conn.settimeout(5.0)
            print(f"[OK] ESP32 connected from {addr[0]}:{addr[1]}")

            # Run Ed25519 mutual authentication first
            if not authenticate_client(conn):
                conn.close()
                print("[ERROR] Connection terminated due to authentication failure.\n")
                continue

            # If authenticated, exchange tunnel messages (no timeout)
            conn.settimeout(None)
            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        print("\n[INFO] ESP32 disconnected.")
                        break

                    message = data.decode("utf-8", errors="ignore").strip()
                    if message:
                        print(f"[RX] {message}")
                        reply = f"ACK: {message}\n"
                        conn.sendall(reply.encode("utf-8"))
                        print(f"[TX] ACK: {message}")

            except ConnectionResetError:
                print("\n[INFO] ESP32 connection reset.")
            finally:
                conn.close()
                print("[INFO] Session closed. Waiting for next connection...\n")

    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
