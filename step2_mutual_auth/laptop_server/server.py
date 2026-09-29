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
    # Step 1: Generate laptop challenge and send it to ESP32
    laptop_challenge = os.urandom(CHALLENGE_LEN)
    conn.sendall(laptop_challenge)
    print("Sent challenge to ESP32.")

    # Step 2: Receive ESP32 response (32 bytes) + ESP32 challenge (16 bytes)
    data = recv_exact(conn, HMAC_LEN + CHALLENGE_LEN)
    if not data:
        print("ESP32 disconnected during authentication.")
        return False

    client_hmac = data[:HMAC_LEN]
    esp32_challenge = data[HMAC_LEN:]

    # Verify ESP32 response
    expected_client_hmac = compute_hmac(PSK, laptop_challenge)
    if not hmac.compare_digest(client_hmac, expected_client_hmac):
        print("FAILED: ESP32 sent invalid HMAC! Disconnecting.")
        return False
    print("ESP32 authenticated successfully.")

    # Step 3: Compute response to ESP32 challenge and send it
    laptop_hmac = compute_hmac(PSK, esp32_challenge)
    conn.sendall(laptop_hmac)
    print("Sent HMAC proof to ESP32.")
    print(">>> Mutual Authentication Succeeded! <<<\n")
    return True


def main():
    local_ip = get_local_ip()
    print(f"Step 2 Server listening on {local_ip}:{PORT}")
    print("Waiting for ESP32 connection...\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(1)

        while True:
            conn, addr = server.accept()
            print(f"\nESP32 connected from {addr[0]}:{addr[1]}")

            # Run mutual authentication first
            if not authenticate_client(conn):
                conn.close()
                print("Connection closed due to authentication failure.\n")
                continue

            # If authenticated, exchange messages
            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        print("ESP32 disconnected.")
                        break

                    message = data.decode("utf-8", errors="ignore").strip()
                    print(f"[From ESP32]: {message}")

                    # Reply with ACK
                    reply = f"ACK: {message}\n"
                    conn.sendall(reply.encode("utf-8"))

            except ConnectionResetError:
                print("ESP32 connection reset.")
            finally:
                conn.close()
                print("Ready for next connection...\n")

    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
