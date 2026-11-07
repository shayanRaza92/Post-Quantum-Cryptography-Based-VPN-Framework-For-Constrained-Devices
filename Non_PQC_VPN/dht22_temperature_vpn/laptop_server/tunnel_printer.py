"""
Boxed 79-column printouts for the encrypted data tunnel, in the same style as the
handshake log. Every function returns a list of lines; the caller prints them with
console.print_block() so one record's output is never split by another device's.
"""
from secure_channel import split_record

INNER = 75                                   # Text columns inside "| " ... " |"
BAR = "+" + "-" * (INNER + 2) + "+"
C1 = 26                                      # "Field" column width
C2 = INNER - C1 - 3                          # "Value" column width (46)
FIELD_BAR = f"+{'-' * (C1 + 2)}+{'-' * (C2 + 2)}+"


def row(text=""):
    return f"| {text:<{INNER}.{INNER}} |"


def hex_rows(data: bytes):
    """Hex dump, 32 bytes (64 hex characters) per row."""
    h = data.hex().upper()
    return [row(h[i:i + 64]) for i in range(0, len(h), 64)] or [row("(empty)")]


def text_rows(text: str):
    """Text wrapped at 75 columns, breaking after a comma where possible (keeps JSON fields whole)."""
    rows = []
    while len(text) > INNER:
        cut = text.rfind(",", 0, INNER) + 1   # 0 when there is no comma: hard cut instead
        cut = cut or INNER
        rows.append(row(text[:cut]))
        text = text[cut:]
    if text or not rows:
        rows.append(row(text or "(empty)"))
    return rows


def field_table(title, fields):
    lines = [BAR, row(title), FIELD_BAR, f"| {'Field':<{C1}} | {'Value':<{C2}} |", FIELD_BAR]
    lines += [f"| {name:<{C1}.{C1}} | {str(value):<{C2}.{C2}} |" for name, value in fields]
    lines.append(BAR)
    return lines


def data_key_lines(k_c2s: bytes, k_s2c: bytes):
    return [
        BAR,
        row("DATA TUNNEL KEYS (derived from K_session via HMAC-SHA256)"),
        BAR,
        row('K_c2s = HMAC-SHA256(K_session, "VPN-v1|DATA|C2S")   [ESP32 -> Server]'),
        *hex_rows(k_c2s),
        BAR,
        row('K_s2c = HMAC-SHA256(K_session, "VPN-v1|DATA|S2C")   [Server -> ESP32]'),
        *hex_rows(k_s2c),
        BAR,
    ]


def record_lines(title, wire: bytes, key_name):
    """Breakdown of one wire record: Length, Sequence, Nonce, Ciphertext, GCM Tag."""
    length, seq, nonce, ciphertext, tag = split_record(wire)
    return [
        BAR,
        row(f"{title} ({len(wire)} Bytes / {len(wire) * 8}-bits on wire)"),
        BAR,
        row(f"Length Field   (2 Bytes)  : 0x{length:04X}  ({length} Bytes follow)"),
        row(f"Sequence No.   (8 Bytes)  : 0x{seq:016X}  (#{seq})"),
        row(f"GCM IV / Nonce (12 Bytes) : {nonce.hex().upper()}"),
        row(f"AEAD Cipher / Key         : AES-256-GCM / {key_name}"),
        BAR,
        row(f"Ciphertext ({len(ciphertext)} Bytes / {len(ciphertext) * 8}-bits)"),
        *hex_rows(ciphertext),
        BAR,
        row("GCM Authentication Tag (16 Bytes / 128-bits)"),
        *hex_rows(tag),
        BAR,
    ]


def payload_lines(title, plaintext: bytes):
    """'title (N Bytes)' plus the wrapped payload text, as a closed box."""
    return [
        BAR,
        row(f"{title} ({len(plaintext)} Bytes)"),
        *text_rows(plaintext.decode("utf-8", errors="replace")),
        BAR,
    ]
