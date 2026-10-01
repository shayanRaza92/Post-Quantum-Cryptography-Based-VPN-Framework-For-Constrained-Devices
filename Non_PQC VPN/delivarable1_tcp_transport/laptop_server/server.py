import socket
import sys

# Server settings
HOST = "0.0.0.0"  # Listen on all network interfaces
PORT = 9000       # Port number for our VPN connection


def get_local_ip():
    """Finds the laptop's local IP on Wi-Fi."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def main():
    local_ip = get_local_ip()
    print(f"Server started on {local_ip}:{PORT}")
    print("Waiting for ESP32 to connect...\n")

    # Create TCP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(1)

        while True:
            # Wait for ESP32
            conn, addr = server.accept()
            print(f"ESP32 connected from {addr[0]}")

            while True:
                data = conn.recv(1024)
                if not data:
                    print("ESP32 disconnected.\n")
                    break

                message = data.decode("utf-8", errors="replace").strip()
                print(f"[From ESP32]: {message}")

                # Send back a short reply
                reply = f"ACK: {message}\n"
                conn.sendall(reply.encode("utf-8"))

            conn.close()

    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
