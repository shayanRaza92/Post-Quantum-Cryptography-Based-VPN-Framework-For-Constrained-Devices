import socket
import threading
import time
from config import (
    HOST, PORT,
    MAX_CONCURRENT_HANDSHAKES,
    MAX_HANDSHAKES_PER_IP,
    RATE_LIMIT_WINDOW_SEC,
    RATE_LIMIT_MAX_PER_IP
)
from crypto_engine import GatewayCrypto, DeviceAllowlist
from tunnel_session import VpnSession
from session_registry import SessionRegistry  # Tracks which devices have a live tunnel
from console import safe_print as print  # Thread-safe printing (no interleaved lines)


class HandshakeSlot:
    """
    One reserved handshake slot: a unit of the global semaphore plus one unit of the
    per-IP counter. release() is idempotent, so it is safe to call from several
    cleanup paths without ever releasing a slot twice.
    """

    def __init__(self, gateway, ip):
        self._gateway = gateway
        self._ip = ip
        self._released = False
        self._lock = threading.Lock()

    def release(self):
        with self._lock:
            if self._released:
                return
            self._released = True
        self._gateway._release_handshake(self._ip)


class VpnGateway:
    """Main Post-Quantum VPN Gateway server class that binds the socket and accepts incoming ESP32 clients."""

    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.crypto = GatewayCrypto()
        self.allowlist = DeviceAllowlist()
        self.registry = SessionRegistry()      # Live tunnels, one per device ID
        self.handshake_semaphore = threading.Semaphore(MAX_CONCURRENT_HANDSHAKES)
        self._ip_history = {}                  # {ip: [timestamp, ...]}
        self._ip_handshakes = {}               # {ip: number of handshakes currently in progress}
        self._ip_lock = threading.Lock()

    def _is_rate_limited(self, ip):
        """Sliding-window rate limiter per remote IP address."""
        now = time.monotonic()
        with self._ip_lock:
            # Prune every IP's history so the dict cannot grow without bound
            for known_ip in list(self._ip_history):
                kept = [t for t in self._ip_history[known_ip] if now - t < RATE_LIMIT_WINDOW_SEC]
                if kept:
                    self._ip_history[known_ip] = kept
                else:
                    del self._ip_history[known_ip]

            history = self._ip_history.setdefault(ip, [])
            if len(history) >= RATE_LIMIT_MAX_PER_IP:
                return True
            history.append(now)
            return False

    def _try_acquire_handshake(self, ip):
        """Reserves a global + per-IP handshake slot. Returns a HandshakeSlot or an error string."""
        with self._ip_lock:
            if self._ip_handshakes.get(ip, 0) >= MAX_HANDSHAKES_PER_IP:
                return f"per-IP handshake limit ({MAX_HANDSHAKES_PER_IP}) reached"
            if not self.handshake_semaphore.acquire(blocking=False):
                return f"global handshake capacity ({MAX_CONCURRENT_HANDSHAKES}) reached"
            self._ip_handshakes[ip] = self._ip_handshakes.get(ip, 0) + 1
        return HandshakeSlot(self, ip)

    def _release_handshake(self, ip):
        with self._ip_lock:
            remaining = self._ip_handshakes.get(ip, 0) - 1
            if remaining > 0:
                self._ip_handshakes[ip] = remaining
            else:
                self._ip_handshakes.pop(ip, None)
            self.handshake_semaphore.release()

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

    def _dispatch(self, connection, client_address):
        """
        Hands one accepted connection to its own worker thread.
        Every failure here is contained to THIS connection: the socket is closed, the
        handshake slot is returned, and the accept loop keeps serving other ESP32s.
        """
        client_ip = client_address[0]
        slot = None
        try:
            # DoS Defense: Check per-IP rate limit
            if self._is_rate_limited(client_ip):
                print(f"[RATE-LIMIT] Dropping excessive connection attempt from {client_ip}")
                connection.close()
                return

            # DoS Defense: Enforce global + per-IP concurrent handshake caps
            slot = self._try_acquire_handshake(client_ip)
            if isinstance(slot, str):
                print(f"[DOS-PROTECT] Server busy: {slot}. Dropping {client_ip}")
                slot = None
                connection.close()
                return

            print(f"[CONNECT] Incoming connection from {client_ip}:{client_address[1]}")
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            session = VpnSession(
                connection, client_address, self.crypto, self.allowlist,
                handshake_slot=slot, registry=self.registry
            )
            client_thread = threading.Thread(
                target=session.run, daemon=True, name=f"session-{client_ip}:{client_address[1]}"
            )
            client_thread.start()
            slot = None  # Ownership of the slot now belongs to the session thread
        except Exception as e:
            print(f"[DISPATCH-ERROR] Could not start session for {client_ip}:{client_address[1]}: {e}")
            if slot is not None:
                slot.release()
            try:
                connection.close()
            except OSError:
                pass

    def start(self):
        local_ip = self.get_local_ip()
        self.print_banner(local_ip)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(10)
            print("Server listening for incoming ESP32 connections...\n")

            while True:  # Accept loop: dispatch each client to an independent worker thread
                try:
                    connection, client_address = server_socket.accept()
                except OSError as e:
                    # e.g. ECONNABORTED (client gave up during accept) or EMFILE (out of file
                    # handles). Never let this end the loop: it would kill every live tunnel.
                    print(f"[ACCEPT-ERROR] {e}. Continuing to serve other devices.")
                    time.sleep(0.1)  # Avoid a busy loop if the error repeats (e.g. EMFILE)
                    continue
                self._dispatch(connection, client_address)

        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Server stopped by user.")
        finally:
            server_socket.close()


def main():
    gateway = VpnGateway()
    gateway.start()


if __name__ == "__main__":
    main()

