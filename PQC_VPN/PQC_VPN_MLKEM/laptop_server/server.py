import socket
import threading
import time
from config import (
    HOST, PORT,
    MAX_CONCURRENT_HANDSHAKES,
    RATE_LIMIT_WINDOW_SEC,
    RATE_LIMIT_MAX_PER_IP
)
from crypto_engine import GatewayCrypto, DeviceAllowlist
from tunnel_session import VpnSession


class VpnGateway:
    """Main Post-Quantum VPN Gateway server class that binds the socket and accepts incoming ESP32 clients."""

    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.crypto = GatewayCrypto()
        self.allowlist = DeviceAllowlist()
        self.handshake_semaphore = threading.Semaphore(MAX_CONCURRENT_HANDSHAKES)
        self._ip_history = {}
        self._ip_lock = threading.Lock()

    def _is_rate_limited(self, ip):
        """Sliding-window rate limiter per remote IP address."""
        now = time.monotonic()
        with self._ip_lock:
            history = self._ip_history.get(ip, [])
            history = [t for t in history if now - t < RATE_LIMIT_WINDOW_SEC]
            if len(history) >= RATE_LIMIT_MAX_PER_IP:
                self._ip_history[ip] = history
                return True
            history.append(now)
            self._ip_history[ip] = history
            return False

    @staticmethod
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

    def print_banner(self, local_ip):
        pk_hex = self.crypto.public_hex
        print("=" * 64)
        print("    Post-Quantum VPN (ML-DSA-44 + ML-KEM-512 + AES-256-GCM)")
        print("=" * 64)
        print(f"Server IP         : {local_ip}")
        print(f"Port              : {self.port}")
        print(f"Auth Algorithm    : ML-DSA-44 (NIST FIPS 204, 1312B PK / 2420B Sig)")
        print(f"KEX Algorithm     : Ephemeral ML-KEM-512 (NIST FIPS 203, 800B ek / 768B ct) + HKDF-SHA256")
        print(f"Tunnel Cipher     : AES-256-GCM (per-direction keys from K_session, 64-bit seq nonce, replay-protected)")
        print(f"Server Public Key : {pk_hex[:32]}...{pk_hex[-16:]} (1312 Bytes)")
        print("=" * 64)

        devices = self.allowlist.load_authorized_devices()
        print(f"Loaded {len(devices)} authorized device(s) from allowlist:")
        for dev_id, pub_bytes in devices.items():
            h = pub_bytes.hex().upper()
            print(f"  - {dev_id}: {h[:32]}...{h[-16:]} ({len(pub_bytes)} Bytes)")
        print()

    def start(self):
        local_ip = self.get_local_ip()
        self.print_banner(local_ip)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)
            print("Server listening for incoming ESP32 connections...\n")

            while True:
                connection, client_address = server_socket.accept()
                client_ip = client_address[0]

                if self._is_rate_limited(client_ip):
                    print(f"[RATE-LIMIT] Dropping excessive connection attempt from {client_ip}")
                    connection.close()
                    continue

                if not self.handshake_semaphore.acquire(blocking=False):
                    print(f"[DOS-PROTECT] Server busy: handshake capacity ({MAX_CONCURRENT_HANDSHAKES}) reached. Dropping {client_ip}")
                    connection.close()
                    continue

                print(f"[CONNECT] Incoming connection from {client_address[0]}:{client_address[1]}")
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                session = VpnSession(
                    connection, client_address, self.crypto, self.allowlist,
                    handshake_slot=self.handshake_semaphore
                )
                client_thread = threading.Thread(target=session.run, daemon=True)
                client_thread.start()

        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Server stopped by user.")
        finally:
            server_socket.close()


def main():
    gateway = VpnGateway()
    gateway.start()


if __name__ == "__main__":
    main()

