import os
from cryptography.hazmat.primitives.asymmetric import ed25519


def format_cpp_array(name: str, data: bytes) -> str:
    lines = []
    lines.append(f"const uint8_t {name}[32] = {{")
    for i in range(0, 32, 8):
        chunk = data[i : i + 8]
        hex_items = [f"0x{b:02x}" for b in chunk]
        line = "  " + ", ".join(hex_items)
        if i + 8 < 32:
            line += ","
        lines.append(line)
    lines.append("};")
    return "\n".join(lines)


def generate_keypair():
    seed = os.urandom(32)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes_raw()
    return seed, public_key


def main():
    print("=" * 60)
    print("      Ed25519 Identity Keypair Generator for VPN")
    print("=" * 60)

    # 1. Server Keys
    server_seed, server_pub = generate_keypair()
    print("\n--- [1] SERVER IDENTITY KEYS ---")
    print(f"Server Private Seed (Hex) : {server_seed.hex()}")
    print(f"Server Public Key (Hex)   : {server_pub.hex()}")

    # 2. ESP32 Client Keys
    client_seed, client_pub = generate_keypair()
    print("\n--- [2] ESP32 CLIENT IDENTITY KEYS ---")
    print(f"ESP32 Private Seed (Hex)  : {client_seed.hex()}")
    print(f"ESP32 Public Key (Hex)    : {client_pub.hex()}")

    # Format for code insertion
    print("\n" + "=" * 60)
    print("   COPY-PASTE READY CODE SNIPPETS")
    print("=" * 60)

    print("\n[For laptop_server/server.py]:")
    print(f'SERVER_PRIV_BYTES = bytes.fromhex("{server_seed.hex()}")')
    print(f'CLIENT_PUB_BYTES = bytes.fromhex("{client_pub.hex()}")')

    print("\n[For esp32_client/esp32_client.ino]:")
    print(format_cpp_array("ESP32_PRIVATE_SEED", client_seed))
    print()
    print(format_cpp_array("SERVER_PUBLIC_KEY", server_pub))
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
