import socket
import threading
import time       # Timestamp tracking for per-IP rate limiting
from config import (
    HOST, PORT,
    MAX_CONCURRENT_HANDSHAKES,
    RATE_LIMIT_WINDOW_SEC,
    RATE_LIMIT_MAX_PER_IP
)  # Import host, port, and security settings
from crypto_engine import GatewayCrypto, DeviceAllowlist  # Import crypto and allowlist managers
from tunnel_session import VpnSession  # Import session handler class


class VpnGateway:
    """Main VPN Gateway server class that binds the socket and accepts incoming ESP32 clients."""

    def __init__(self, host=HOST, port=PORT):  # Initialize gateway with network parameters
        self.host = host                       # IP interface to bind to
        self.port = port                       # Port number to listen on
        self.crypto = GatewayCrypto()          # Crypto engine holding server keys and signature methods
        self.allowlist = DeviceAllowlist()      # Allowlist manager to look up authorized ESP32 keys
        self.handshake_semaphore = threading.Semaphore(MAX_CONCURRENT_HANDSHAKES)
        self._ip_history = {}                  # {ip: [timestamp, ...]}
        self._ip_lock = threading.Lock()

    def _is_rate_limited(self, ip):
        """Sliding-window rate limiter per remote IP address."""
        now = time.monotonic()
        with self._ip_lock:
            history = self._ip_history.get(ip, [])
            # Prune entries outside sliding window
            history = [t for t in history if now - t < RATE_LIMIT_WINDOW_SEC]
            if len(history) >= RATE_LIMIT_MAX_PER_IP:
                self._ip_history[ip] = history
                return True
            history.append(now)
            self._ip_history[ip] = history
            return False

    @staticmethod
    def get_local_ip():  # Helper to find this laptop's local Wi-Fi IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create quick UDP test socket
        try:
            s.connect(("8.8.8.8", 80))  # Test route to public DNS (no packets sent)
            ip = s.getsockname()[0]     # Grab local IP chosen by OS
        except Exception:
            ip = "127.0.0.1"            # Fallback to localhost if disconnected
        finally:
            s.close()                   # Close test socket
        return ip

    def print_banner(self, local_ip):  # Displays gateway startup banner and configuration
        print("=" * 64)
        print("                         Classical VPN")
        print("=" * 64)
        print(f"Server IP         : {local_ip}")
        print(f"Port              : {self.port}")
        print(f"Server Public Key : {self.crypto.public_hex}")
        print("=" * 64)

        devices = self.allowlist.load_authorized_devices()  # Read registered devices from JSON
        print(f"Loaded {len(devices)} authorized device(s) from allowlist:")
        for dev_id, pub_bytes in devices.items():
            print(f"  - {dev_id}: {pub_bytes.hex()}")
        print()

    def start(self):  # Starts the TCP server socket and the concurrent connection accept loop
        local_ip = self.get_local_ip()  # Detect laptop Wi-Fi IP address
        self.print_banner(local_ip)     # Display banner with configuration info

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow fast reuse of port

        try:
            server_socket.bind((self.host, self.port))  # Bind socket to interface and port
            server_socket.listen(10)                    # Start listening for incoming connections
            print("Server listening for incoming ESP32 connections...\n")

            while True:  # Accept loop: dispatch each client to an independent worker thread
                connection, client_address = server_socket.accept()  # Block until client connects
                client_ip = client_address[0]

                # DoS Defense: Check per-IP rate limit
                if self._is_rate_limited(client_ip):
                    print(f"[RATE-LIMIT] Dropping excessive connection attempt from {client_ip}")
                    connection.close()
                    continue

                # DoS Defense: Enforce global concurrent handshake cap
                if not self.handshake_semaphore.acquire(blocking=False):
                    print(f"[DOS-PROTECT] Server busy: handshake capacity ({MAX_CONCURRENT_HANDSHAKES}) reached. Dropping {client_ip}")
                    connection.close()
                    continue

                print(f"[CONNECT] Incoming connection from {client_address[0]}:{client_address[1]}")
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                # Create an OOP session instance with the acquired handshake slot
                session = VpnSession(
                    connection, client_address, self.crypto, self.allowlist,
                    handshake_slot=self.handshake_semaphore
                )
                client_thread = threading.Thread(target=session.run, daemon=True)
                client_thread.start()

        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Server stopped by user.")
        finally:
            server_socket.close()  # Safely close listening socket on exit


def main():
    gateway = VpnGateway()  # Instantiate the VPN Gateway
    gateway.start()         # Start listening and serving clients


if __name__ == "__main__":
    main()  # Run server when executed from terminal
