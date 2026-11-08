
import socket
import sys

from nacl.bindings import (
    crypto_scalarmult,
    crypto_scalarmult_base,
)
from nacl.utils import random as random_bytes


# ESP32 Wi-Fi access point settings
ESP32_IP = "192.168.4.1"
TCP_PORT = 5000
TIMEOUT_SECONDS = 20


def receive_exact(sock, length):
    """Receive exactly the requested number of bytes."""
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError(
                "ESP32 disconnected before sending all expected data."
            )

        data.extend(chunk)

    return bytes(data)


def main():
    print("======================================")
    print("Laptop X25519 Wi-Fi Client")
    print("======================================")

    try:
        # STEP 1: Connect to the ESP32.
        print(
            f"\n[STEP 1] Connecting to "
            f"{ESP32_IP}:{TCP_PORT}..."
        )

        with socket.create_connection(
            (ESP32_IP, TCP_PORT),
            timeout=TIMEOUT_SECONDS,
        ) as sock:

            sock.settimeout(TIMEOUT_SECONDS)

            print("[OK] Connected to ESP32.")

            # STEP 2: Receive the ESP32 public key.
            print(
                "\n[STEP 2] Receiving ESP32 public key..."
            )

            esp_public = receive_exact(sock, 32)

            print(
                "ESP32 public key (32 bytes): "
                + esp_public.hex()
            )

            # STEP 3: Generate a laptop private key.
            print(
                "\n[STEP 3] Generating laptop X25519 "
                "private key..."
            )

            laptop_private = random_bytes(32)

            print(
                "[OK] Private key generated. "
                "It will not be printed."
            )

            # STEP 4: Calculate the laptop public key.
            print(
                "\n[STEP 4] Generating laptop public key..."
            )

            laptop_public = crypto_scalarmult_base(
                laptop_private
            )

            print(
                "Laptop public key (32 bytes): "
                + laptop_public.hex()
            )

            # STEP 5: Send the laptop public key.
            print(
                "\n[STEP 5] Sending laptop public key "
                "to ESP32..."
            )

            sock.sendall(laptop_public)

            print("[OK] Public key sent.")

            # STEP 6: Calculate the shared secret.
            print(
                "\n[STEP 6] Calculating shared secret..."
            )

            laptop_shared = crypto_scalarmult(
                laptop_private,
                esp_public,
            )

            print(
                "[OK] Laptop calculated the shared secret."
            )

            # STEP 7: Wait for ESP32 confirmation.
            print(
                "\n[STEP 7] Waiting for ESP32 confirmation..."
            )

            status = receive_exact(sock, 3)

            if status != b"OK\n":
                raise RuntimeError(
                    f"Unexpected response from ESP32: {status!r}"
                )

            print("[SUCCESS] ESP32 confirmed its calculation.")

            # Print only for learning/testing.
            print(
                "\nShared secret (demo only): "
                + laptop_shared.hex()
            )

            print(
                "\nCompare this shared secret with the "
                "value printed in the ESP32 Serial Monitor."
            )

            print(
                "The two values should match exactly."
            )

            print(
                "\nWARNING: Never print shared secrets "
                "in a production application."
            )

            # Drop references to sensitive data.
            # Python cannot guarantee secure memory wiping.
            del laptop_private
            del laptop_shared

    except (OSError, ConnectionError, RuntimeError) as error:
        print(f"\n[ERROR] {error}", file=sys.stderr)

        print(
            "\nCheck the following:",
            "\n1. ESP32 is powered on.",
            "\n2. Laptop is connected to ESP32-X25519-Demo.",
            "\n3. ESP32 Serial Monitor shows the TCP server.",
            "\n4. ESP32 IP address is 192.168.4.1.",
            "\n5. The ESP32 sketch and laptop script are running.",
            file=sys.stderr,
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
