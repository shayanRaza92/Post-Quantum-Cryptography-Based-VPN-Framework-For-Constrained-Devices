import socket
import hmac
import hashlib
import os

# Pre-Shared Key (must match on ESP32 and Laptop)
PSK = b"vpn_secret_key_123"

HOST = "0.0.0.0"
PORT = 9000

CHALLENGE_LEN = 16
HMAC_LEN = 32


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


def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def recv_exact(conn, n):
    """Receive exactly n bytes from the socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def authenticate_client(conn):
    print("\n[MUTUAL AUTHENTICATION]")

    # Step 1: Generate server challenge and send to ESP32
    laptop_challenge = os.urandom(CHALLENGE_LEN)
    conn.sendall(laptop_challenge)

    print("[MSG1] Server Challenge")
    print(f"       Length         : {CHALLENGE_LEN} bytes")
    print("       Status         : SENT")

    # Step 2: Receive ESP32 response (32 bytes HMAC + 16 bytes Challenge)
    data = recv_exact(conn, HMAC_LEN + CHALLENGE_LEN)
    if not data:
        print("[FAIL] ESP32 disconnected during authentication")
        return False

    client_hmac = data[:HMAC_LEN]
    esp32_challenge = data[HMAC_LEN:]

    print("\n[MSG2] ESP32 Authentication Proof")
    print("       Algorithm      : HMAC-SHA256")
    print(f"       Proof Length   : {HMAC_LEN} bytes")
    print(f"       Challenge      : {CHALLENGE_LEN} bytes")
    print("       Status         : RECEIVED")

    # Verify ESP32 response
    expected_client_hmac = compute_hmac(PSK, laptop_challenge)
    if not hmac.compare_digest(client_hmac, expected_client_hmac):
        print("\n[VERIFY] ESP32 Authentication")
        print("         Result       : FAILED (Invalid HMAC / Untrusted Client)")
        return False

    print("\n[VERIFY] ESP32 Authentication")
    print("         Result       : SUCCESS")

    # Step 3: Compute response to ESP32 challenge and send it
    laptop_hmac = compute_hmac(PSK, esp32_challenge)
    conn.sendall(laptop_hmac)

    print("\n[MSG3] Server Authentication Proof")
    print("       Algorithm      : HMAC-SHA256")
    print(f"       Proof Length   : {HMAC_LEN} bytes")
    print("       Status         : SENT")

    print("\n============================================================")
    print("        MUTUAL AUTHENTICATION SUCCESSFUL")
    print("============================================================\n")
    print("[DATA TUNNEL]")
    return True


def main():
    local_ip = get_local_ip()

    print("\n============================================================")
    print("              PQC VPN - LAPTOP GATEWAY")
    print("============================================================")
    print("\n[NETWORK]")
    print("[OK] Server listening")
    print(f"     Server IP      : {local_ip}")
    print(f"     Server Port    : {PORT}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(1)

        while True:
            print("\n[TCP TRANSPORT]")
            print("Waiting for ESP32 connection...")
            conn, addr = server.accept()
            print(f"[OK] ESP32 connected from {addr[0]}:{addr[1]}")

            # Run mutual authentication first
            if not authenticate_client(conn):
                conn.close()
                print("[ERROR] Connection terminated due to authentication failure.\n")
                continue

            # If authenticated, exchange tunnel messages
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
