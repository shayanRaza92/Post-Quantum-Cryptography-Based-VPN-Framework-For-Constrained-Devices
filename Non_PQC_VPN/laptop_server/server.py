import socket  # Network socket library for TCP listener
from config import HOST, PORT  # Import host and port settings
from crypto_engine import GatewayCrypto, DeviceAllowlist  # Import crypto and allowlist managers
from tunnel_session import VpnSession  # Import session handler class


class VpnGateway:
    """Main VPN Gateway server class that binds the socket and accepts incoming ESP32 clients."""

    def __init__(self, host=HOST, port=PORT):  # Initialize gateway with network parameters
        self.host = host                       # IP interface to bind to
        self.port = port                       # Port number to listen on
        self.crypto = GatewayCrypto()          # Crypto engine holding server keys and signature methods
        self.allowlist = DeviceAllowlist()      # Allowlist manager to look up authorized ESP32 keys

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
        print("=" * 60)
        print("      PQC VPN GATEWAY - MUTUAL AUTHENTICATION")
        print("=" * 60)
        print(f"Server IP         : {local_ip}")
        print(f"Port              : {self.port}")
        print(f"Server Public Key : {self.crypto.public_hex}")
        print("=" * 60)

        devices = self.allowlist.load_authorized_devices()  # Read registered devices from JSON
        print(f"Loaded {len(devices)} authorized device(s) from allowlist:")
        for dev_id, pub_bytes in devices.items():
            print(f"  - {dev_id}: {pub_bytes.hex()}")
        print()

    def start(self):  # Starts the TCP server socket and the main connection accept loop
        local_ip = self.get_local_ip()  # Detect laptop Wi-Fi IP address
        self.print_banner(local_ip)     # Display banner with configuration info

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create TCP socket
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow fast reuse of port

        try:
            server_socket.bind((self.host, self.port))  # Bind socket to interface and port
            server_socket.listen(5)                     # Start listening for incoming connections
            print("Server listening for ESP32 connection...\n")

            while True:  # Accept loop: wait for clients, handle each one synchronously
                connection, client_address = server_socket.accept()  # Block until ESP32 connects
                print(f"[CONNECT] Incoming connection from {client_address[0]}:{client_address[1]}")

                # Create an OOP session instance for this client and run it
                session = VpnSession(connection, client_address, self.crypto, self.allowlist)
                session.run()

        except KeyboardInterrupt:
            print("\n[SHUTDOWN] Server stopped by user.")
        finally:
            server_socket.close()  # Safely close listening socket on exit


def main():
    gateway = VpnGateway()  # Instantiate the VPN Gateway
    gateway.start()         # Start listening and serving clients


if __name__ == "__main__":
    main()  # Run server when executed from terminal
