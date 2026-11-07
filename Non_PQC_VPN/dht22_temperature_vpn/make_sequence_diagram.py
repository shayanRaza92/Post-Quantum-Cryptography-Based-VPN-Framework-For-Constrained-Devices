"""
Generates sequence_diagram.png for the DHT22 temperature VPN.

Same visual layout as ../sequence_diagram.png (classical VPN handshake), extended with
everything that happens AFTER the key exchange: directional AES-256 key derivation,
AES-256-GCM encrypted sensor records, encrypted ACKs, and tunnel teardown rules.

    python make_sequence_diagram.py
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle

# Sans-serif math so bold note titles and inline variables match the body text
plt.rcParams.update({
    "mathtext.fontset": "custom",
    "mathtext.rm": "DejaVu Sans",
    "mathtext.it": "DejaVu Sans:italic",
    "mathtext.bf": "DejaVu Sans:bold",
})

OUT = Path(__file__).parent / "sequence_diagram.png"

W, H = 100, 229                 # Data-coordinate canvas (y grows downward)
FIG_W, FIG_H = 26, 30.6           # Inches
CLIENT_X, SERVER_X = 30, 72     # Lifelines
CHAR_W = 0.335                  # Width of one 10.5pt monospace character in x-units
MONO = "DejaVu Sans Mono"
SERIF = "DejaVu Serif"

C_MSG1, C_MSG2, C_MSG3, C_MSG4 = "#1010c0", "#d9700a", "#0f7070", "#a0103c"
C_DATA, C_ACK, C_TUNNEL = "#1f5fbf", "#7a2fb0", "#1a9a1a"

fig = plt.figure(figsize=(FIG_W, FIG_H), dpi=150)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W)
ax.set_ylim(H, 0)
ax.axis("off")


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------
def header(x, title, subtitle, face, width):
    ax.add_patch(FancyBboxPatch((x - width / 2, 0.8), width, 5.0,
                                boxstyle="round,pad=0,rounding_size=0.6", fc=face, ec="#444", lw=1.3))
    ax.text(x, 2.5, title, ha="center", va="center", fontsize=19, fontweight="bold")
    ax.text(x, 4.6, subtitle, ha="center", va="center", fontsize=12, family=SERIF, color="#333")


def lifelines(y_end):
    for x in (CLIENT_X, SERVER_X):
        ax.plot([x, x], [5.8, y_end], ls=(0, (5, 4)), color="#999", lw=1.4, zorder=0)


def pill(x, y, text, face="#f6f6f6", edge="#bbb", size=12, family=None):
    ax.text(x, y, text, ha="center", va="center", fontsize=size, family=family,
            bbox=dict(boxstyle="round,pad=0.55,rounding_size=0.35", fc=face, ec=edge, lw=1.1))


def arrow(y, left_to_right, label, color, both=False):
    x0, x1 = (CLIENT_X, SERVER_X) if left_to_right else (SERVER_X, CLIENT_X)
    style = "<|-|>" if both else "-|>"
    ax.annotate("", xy=(x1, y), xytext=(x0, y),
                arrowprops=dict(arrowstyle=style, color=color, lw=2.0, mutation_scale=22))
    ax.text((CLIENT_X + SERVER_X) / 2, y - 1.15, label, ha="center", va="bottom",
            fontsize=16, family=SERIF, fontweight="bold", color=color)


def note(x, y, title, lines, side, face="#f3f3f3", edge="#888", size=12.5):
    """Dashed side note. side='left' -> right edge at x; side='right' -> left edge at x."""
    text = r"$\bf{" + title.replace(" ", r"\ ") + "}$\n" + "\n".join(lines)
    ax.text(x, y, text, ha="right" if side == "left" else "left", va="top", fontsize=size,
            linespacing=1.45, multialignment="left",
            bbox=dict(boxstyle="round,pad=0.7,rounding_size=0.4", fc=face, ec=edge, lw=1.3, ls=(0, (5, 3))))


def packet(cx, y, cols, edge, face, row_h=1.25):
    """Two-row packet table (header row + value row), centred on cx."""
    widths = [max(len(h), len(v)) * CHAR_W + 1.6 for h, v in cols]
    total = sum(widths)
    x = cx - total / 2
    pad = 0.7
    ax.add_patch(FancyBboxPatch((x - pad, y - pad), total + 2 * pad, 2 * row_h + 2 * pad,
                                boxstyle="round,pad=0,rounding_size=0.5", fc=face, ec=edge, lw=1.2))
    for (h, v), w in zip(cols, widths):
        ax.add_patch(Rectangle((x, y), w, row_h, fc="white", ec="black", lw=1.0))
        ax.add_patch(Rectangle((x, y + row_h), w, row_h, fc="white", ec="black", lw=1.0))
        ax.text(x + w / 2, y + row_h / 2, h, ha="center", va="center", fontsize=10.5, family=MONO, fontweight="bold")
        ax.text(x + w / 2, y + 1.5 * row_h, v, ha="center", va="center", fontsize=10.5, family=MONO)
        x += w


def banner(y, title, lines, face, edge, width=60, line_h=1.9):
    cx = (CLIENT_X + SERVER_X) / 2
    height = (len(lines) + 1) * line_h + 1.6
    ax.add_patch(FancyBboxPatch((cx - width / 2, y), width, height,
                                boxstyle="round,pad=0,rounding_size=0.6", fc=face, ec=edge, lw=1.5))
    ax.text(cx, y + 0.8 + line_h / 2, title, ha="center", va="center", fontsize=15.5, fontweight="bold")
    for i, line in enumerate(lines, start=1):
        ax.text(cx, y + 0.8 + line_h * (i + 0.5), line, ha="center", va="center", fontsize=13, family=SERIF)


def section(y, text, color="#555"):
    ax.plot([2, W - 2], [y, y], color=color, lw=1.0, ls=(0, (2, 3)))
    ax.text(3, y - 0.5, text, ha="left", va="bottom", fontsize=14, fontweight="bold", color=color)


LN, RN = CLIENT_X - 1.2, SERVER_X + 1.2   # Note anchors left / right of the lifelines

# ---------------------------------------------------------------------------
# Participants
# ---------------------------------------------------------------------------
header(CLIENT_X, "ESP32 IoT Client + DHT22 Sensor",
       "[Hardware TRNG | Libsodium Ed25519 & X25519 | mbedTLS AES-256-GCM (HW AES)]", "#e0e0fb", 30)
header(SERVER_X, "Gateway Server (Responder)",
       "[Laptop Gateway | Python cryptography: Ed25519, X25519, AESGCM]", "#f8e1ea", 25)
lifelines(H - 3)
pill(51, 8.6, r"TCP 3-Way Handshake (SYN $\rightarrow$ SYN-ACK $\rightarrow$ ACK) on Port 9000 (TCP_NODELAY Enabled)")

# ---------------------------------------------------------------------------
# PHASE 1: Handshake (condensed, identical to the classical VPN)
# ---------------------------------------------------------------------------
section(12, "PHASE 1 - MUTUAL AUTHENTICATION & EPHEMERAL X25519 KEY EXCHANGE  (unchanged; full detail in Non_PQC_VPN/sequence_diagram.png)")

y = 17
arrow(y, True, "MSG 1: CLIENT HELLO (82 Bytes)", C_MSG1)
packet(51, y + 1.6, [("Ver (1B)", "0x01"), ("Alg (1B)", "0x01"), ("Device ID (16B)", '"esp32-03\\0..."'),
                     ("N_cli (32B)", "HW TRNG nonce"), ("PK_cli_eph (32B)", "X25519 share")], "#555", "#f3f3ff")
note(LN, y - 1.5, "Client Hello:", [r"Generate $N_{cli}$ and ephemeral X25519 $(sk_{cli\_eph}, PK_{cli\_eph})$"], "left")
note(RN, y + 1.5, "Allowlist Check:", [r'Lookup DeviceID $\rightarrow$ load registered $PK_{cli}$'], "right", face="#fdf3dd", edge="#d9a040")

y = 28
arrow(y, False, "MSG 2: SERVER PROOF & KEY SHARE (128 Bytes)", C_MSG2)
packet(51, y + 1.6, [("N_srv (32B)", "CSPRNG nonce"), ("PK_srv_eph (32B)", "X25519 share"),
                     ("sigma_srv (64B)", "Ed25519 Sign(SK_srv, H_srv)")], "#555", "#fff6ec")
note(RN, y - 1.0, "Server Proof:", [r"Sign $H_{srv}$; derive $(K_{confirm}, K_{session})$ via HKDF-SHA256"], "right")
note(LN, y + 4.6, "Client Verifies Server First:", [r"Verify $\sigma_{srv}$ with pinned $PK_{srv}$ $\rightarrow$ PASS",
                                                    r"$SS = $X25519$(sk_{cli\_eph}, PK_{srv\_eph})$ $\rightarrow$ HKDF $\rightarrow$ $K_{session}$"],
     "left", face="#e3fbe3", edge="#3aa83a")

y = 41
arrow(y, True, "MSG 3: CLIENT PROOF & KEY CONFIRMATION (96 Bytes)", C_MSG3)
packet(51, y + 1.6, [("sigma_cli (64B)", "Ed25519 Sign(SK_cli, H_cli)"),
                     ("tau_cli (32B)", 'HMAC(K_confirm, "CLIENT-CONFIRM" || H_cli)')], "#555", "#eefaf8")
note(RN, y + 5.0, "Server Verifies Client:", [r"Verify $\sigma_{cli}$ with $PK_{cli}$ and $\tau_{cli}$ $\rightarrow$ PASS"],
     "right", face="#e3fbe3", edge="#3aa83a")

y = 52
arrow(y, False, "MSG 4: SERVER VERDICT & KEY CONFIRMATION (40 Bytes)", C_MSG4)
packet(51, y + 1.6, [("Verdict (8B)", '"AUTH_OK\\n"'), ("tau_srv (32B)", 'HMAC(K_confirm, "SERVER-CONFIRM" || H_cli)')],
       "#555", "#fdf0f3")
note(LN, y + 4.6, "Client Verifies Verdict:", [r"Constant-time check of $\tau_{srv}$ $\rightarrow$ PASS; wipe $K_{confirm}$"],
     "left", face="#e3fbe3", edge="#3aa83a")

banner(62.5, "MUTUAL AUTHENTICATION & EPHEMERAL X25519 KEY EXCHANGE ESTABLISHED",
       [r"Both sides now hold the same 32-byte session master key $K_{session}$ (never sent on the wire, unique per connection: PFS)"],
       "#e3fbe3", "#3aa83a", width=66)

# ---------------------------------------------------------------------------
# PHASE 2: Data-key derivation
# ---------------------------------------------------------------------------
section(71.5, "PHASE 2 - DIRECTIONAL AES-256 DATA KEY DERIVATION  (local computation on both sides, nothing sent)", "#1f5fbf")

key_lines = [
    r'1. $K_{c2s} = $ HMAC-SHA256$(K_{session},$ "VPN-v1|DATA|C2S"$)$',
    r'    32-byte AES-256 key for ESP32 $\rightarrow$ Server',
    r'2. $K_{s2c} = $ HMAC-SHA256$(K_{session},$ "VPN-v1|DATA|S2C"$)$',
    r'    32-byte AES-256 key for Server $\rightarrow$ ESP32',
]
note(LN, 74.5, "ESP32 Derives Tunnel Keys:", key_lines + [
    r"3. Load both keys into mbedTLS GCM contexts",
    r"    (AES rounds run on the ESP32 hardware AES engine)",
    r"4. $tx\_seq = 0$,  $rx\_seq = 0$",
], "left", face="#e6effc", edge="#1f5fbf")
note(RN, 74.5, "Gateway Derives Tunnel Keys:", key_lines + [
    r"3. Create AESGCM($K_{c2s}$) for receive, AESGCM($K_{s2c}$) for send",
    r"4. $rx\_seq = 0$,  $tx\_seq = 0$",
], "right", face="#e6effc", edge="#1f5fbf")
pill(51, 93, r"Separate keys per direction $\Rightarrow$ the same (key, IV) pair can never be used twice, even though both counters start at 0",
     face="#f4f8ff", edge="#9db7e0", size=12)

# ---------------------------------------------------------------------------
# PHASE 3: Encrypted telemetry loop
# ---------------------------------------------------------------------------
section(97, "PHASE 3 - AES-256-GCM ENCRYPTED TELEMETRY TUNNEL", C_DATA)

loop_top, loop_bottom = 99.5, 189
ax.add_patch(Rectangle((1.5, loop_top), W - 3, loop_bottom - loop_top, fc="none", ec="#555", lw=1.4))
ax.add_patch(Rectangle((1.5, loop_top), 20, 2.4, fc="#ececec", ec="#555", lw=1.4))
ax.text(2.3, loop_top + 1.2, "loop  [every SENSOR_INTERVAL_MS = 5 s]", ha="left", va="center",
        fontsize=12.5, fontweight="bold")

note(LN, 103.5, "DHT22 Sampling & Record Encryption:", [
    r"1. Read temperature $T$ and humidity $RH$ from DHT22 on GPIO 4",
    r"2. Compute heat index $HI = f(T, RH)$",
    r'3. Build JSON payload $P$ (94 Bytes), e.g.',
    r'    {"reading":1,"uptime_ms":5000,"temperature_c":24.60,',
    r'     "humidity_pct":51.30,"heat_index_c":24.50}',
    r"    (sensor failure $\Rightarrow$ {..., " + '"error":"dht22_read_failed"})',
    r"4. $Hdr = Len\,(2B) \,\|\, Seq\,(8B)$,   $Len = 8 + |P| + 16$",
    r"5. $IV = $ 0x00000000 $\|\, Seq$   (96-bit GCM nonce)",
    r"6. $(C, Tag) = $AES-256-GCM-Enc$(K_{c2s}, IV, P, AAD = Hdr)$",
    r"7. Send $Hdr \,\|\, C \,\|\, Tag$;   $tx\_seq \leftarrow tx\_seq + 1$",
], "left", face="#f3f3f3", edge="#888")

y = 128
arrow(y, True, "DATA RECORD: ENCRYPTED SENSOR READING (120 Bytes / 960-bits)", C_DATA)
packet(51, y + 1.6, [("Length (2B)", "0x0076 (118)"), ("Sequence (8B)", "0x00..00 (#0)"),
                     ("AES-256-GCM Ciphertext C (94B)", "AES-CTR(K_c2s, IV) XOR P"),
                     ("GCM Tag (16B)", "GHASH(AAD, C)")], C_DATA, "#eef3fc")

note(RN, 132.5, "Gateway Verifies & Decrypts:", [
    r"1. Check $24 \leq Len \leq 504$  (else close session)",
    r"2. Check $Seq = rx\_seq$  (replay / reorder $\Rightarrow$ close)",
    r"3. $P = $AES-256-GCM-Dec$(K_{c2s}, IV, C, Tag, AAD = Hdr)$",
    r"    tag verified before any plaintext is released $\rightarrow$ PASS",
    r"4. $rx\_seq \leftarrow rx\_seq + 1$",
    r"5. Validate JSON: $-40 \leq T \leq 80\,^{\circ}C$, $0 \leq RH \leq 100\,\%$",
    r"6. Append row to temperature_log.csv using the",
    r"    DeviceID proven in the handshake (not the payload)",
], "right", face="#e3fbe3", edge="#3aa83a")

note(RN, 153.5, "Gateway Builds Encrypted ACK:", [
    r'1. $A = $ {"seq":0,"reading":1,"status":"stored"}  (39 Bytes)',
    r'    (invalid reading $\Rightarrow$ "status":"rejected" + reason)',
    r"2. $IV = $ 0x00000000 $\|\, tx\_seq$",
    r"3. $(C, Tag) = $AES-256-GCM-Enc$(K_{s2c}, IV, A, AAD = Hdr)$",
    r"4. Send record;  $tx\_seq \leftarrow tx\_seq + 1$",
], "right", face="#f3f3f3", edge="#888")

y = 167.5
arrow(y, False, "ACK RECORD: ENCRYPTED ACKNOWLEDGEMENT (65 Bytes / 520-bits)", C_ACK)
packet(51, y + 1.6, [("Length (2B)", "0x003F (63)"), ("Sequence (8B)", "0x00..00 (#0)"),
                     ("AES-256-GCM Ciphertext C (39B)", "AES-CTR(K_s2c, IV) XOR A"),
                     ("GCM Tag (16B)", "GHASH(AAD, C)")], C_ACK, "#f5eefc")

note(LN, 172.5, "ESP32 Verifies ACK:", [
    r"1. Check $Seq = rx\_seq$",
    r"2. $A = $AES-256-GCM-Dec$(K_{s2c}, IV, C, Tag, AAD = Hdr)$ $\rightarrow$ PASS",
    r"3. Print ACK;  $rx\_seq \leftarrow rx\_seq + 1$",
    r"Any failure $\Rightarrow$ close tunnel & reconnect",
], "left", face="#e3fbe3", edge="#3aa83a")

pill(51, 186, r"Next iteration: $Seq = 1, 2, 3, \ldots$  (new IV for every record; the 64-bit counter never wraps in practice)",
     face="#f6f6f6", edge="#bbb", size=12)

# ---------------------------------------------------------------------------
# PHASE 4: Teardown
# ---------------------------------------------------------------------------
section(193, "PHASE 4 - TUNNEL TEARDOWN & RE-KEYING", C_MSG4)

note(RN, 196, "Gateway Closes the Session When:", [
    r"$\bullet$ GCM tag mismatch (tampered record or wrong key)",
    r"$\bullet$ $Seq \neq rx\_seq$ (replayed, dropped, or reordered record)",
    r"$\bullet$ Invalid length field",
    r"$\bullet$ No record for 30 s (idle timeout)",
    r"$\bullet$ Device removed from authorized_devices.json",
    r"$\bullet$ Same device opens a newer session",
], "right", face="#fdecef", edge="#c0405a")
note(LN, 196, "ESP32 Recovers:", [
    r"1. Wipe $K_{c2s}$, $K_{s2c}$, GCM contexts and counters",
    r"2. Back off 3 s $\rightarrow$ 6 s $\rightarrow$ ... $\rightarrow$ 30 s",
    r"3. New TCP connection + new handshake (MSG 1-4)",
    r"4. Fresh ephemeral X25519 $\Rightarrow$ fresh $K_{session}$",
    r"    $\Rightarrow$ fresh $K_{c2s}$, $K_{s2c}$ (Perfect Forward Secrecy)",
], "left", face="#fdecef", edge="#c0405a")

arrow(215, True, r"Authenticated & Encrypted VPN Data Tunnel (AES-256-GCM, keys from $K_{session}$)", C_TUNNEL, both=True)

banner(218, "AES-256-GCM PROTECTED DHT22 TELEMETRY TUNNEL", [
    r"Confidentiality: AES-256 (CTR mode)  |  Integrity & Authenticity: 128-bit GCM tag over header + ciphertext",
    r"Replay / Reorder Protection: strict 64-bit sequence  |  Forward Secrecy: new $K_{c2s}$ / $K_{s2c}$ every session",
    r"Per-record overhead: 26 Bytes (2B Length + 8B Sequence + 16B Tag)  |  Sensor record $\approx$ 120 B, ACK $\approx$ 65 B",
], "#e3fbe3", "#3aa83a", width=68)

fig.savefig(OUT, dpi=150, facecolor="white")
print(f"Saved {OUT}")
