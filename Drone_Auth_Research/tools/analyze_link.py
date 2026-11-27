#!/usr/bin/env python3
"""Tables and figures for Step 3 (E3): drone authentication on a real Wi-Fi link.

    python3 tools/analyze_link.py results/e3/raw/link_<date>_<time>

Reads gcs_log.csv (written by gcs_link_test.py) and capture.pcapng (the Wireshark capture),
counts what really went over the air for every authentication, and writes to
results/e3/<run name>/:
  per_message.csv  one line per authentication: packets, bytes on the wire, times
  summary.csv      per algorithm, link style and data size
  one_packet.csv   largest data that still fitted in ONE packet (measured), per algorithm and style
  results.md       readable tables
  figures/fig6_link_packets   packets per signed message vs data size (measured)
  figures/fig7_link_time      authentication time with 64 bytes of data (measured)

"Packets" are IP packets seen by Wireshark. In style "udp" a large message is one UDP datagram
that the IP layer splits into several packets; in style "mav" every MAVLink-sized frame is its
own UDP datagram; in styles "tunnel" and "v2ext" every real MAVLink 2 packet (TUNNEL or
V2_EXTENSION) is its own UDP datagram. "Bytes on the wire" are IP bytes (IP + UDP headers +
payload), without the Wi-Fi radio framing; for the real MAVLink styles the MAVLink bytes (the UDP
payloads, i.e. exactly what a serial radio would carry) are counted too. The capture file is read
directly, so tshark is not needed.
"""
import csv
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
ORDER = ["Ed25519", "ECDSA-P256", "RSA-3072", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
CHALLENGE, AUTH, RESULT = 4, 5, 6
STYLE_ORDER = ["udp", "mav", "tunnel", "v2ext"]
STYLE_TITLE = {"udp": "Wi-Fi UDP", "mav": "MAVLink-sized frames (emulated)",
               "tunnel": "Real MAVLink 2 TUNNEL packets", "v2ext": "Real MAVLink 2 V2_EXTENSION packets"}
MAVLINK_IDS = {385: "TUNNEL", 248: "V2_EXTENSION"}


# ---- minimal pcapng reader (Ethernet, Linux cooked v1/v2, raw IP) ------------------------
def read_pcapng(path):
    data = Path(path).read_bytes()
    pos, endian, ifaces, packets = 0, "<", [], []
    while pos + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, pos)[0]
        if btype == 0x0A0D0D0A:                                   # section header: byte order
            endian = "<" if struct.unpack_from("<I", data, pos + 8)[0] == 0x1A2B3C4D else ">"
        blen = struct.unpack_from(endian + "I", data, pos + 4)[0]
        body = data[pos + 8:pos + blen - 4]
        if btype == 1:                                            # interface description
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            res, opt = 1e-6, 8
            while opt + 4 <= len(body):
                code, olen = struct.unpack_from(endian + "HH", body, opt)
                if code == 0:
                    break
                if code == 9 and olen >= 1:                       # if_tsresol
                    v = body[opt + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opt += 4 + ((olen + 3) & ~3)
            ifaces.append((linktype, res))
        elif btype == 6:                                          # enhanced packet
            iid, th, tl, caplen = struct.unpack_from(endian + "IIII", body, 0)
            linktype, res = ifaces[iid]
            packets.append((((th << 32) | tl) * res, linktype, body[20:20 + caplen]))
        pos += blen
    return packets


def ip_payload(linktype, frame):
    if linktype == 1:                                             # Ethernet
        off, etype = 14, struct.unpack_from(">H", frame, 12)[0]
        while etype == 0x8100:
            etype = struct.unpack_from(">H", frame, off + 2)[0]
            off += 4
        return frame[off:] if etype == 0x0800 else None
    if linktype == 113:                                           # Linux cooked v1
        return frame[16:] if struct.unpack_from(">H", frame, 14)[0] == 0x0800 else None
    if linktype == 276:                                           # Linux cooked v2
        return frame[20:] if struct.unpack_from(">H", frame, 0)[0] == 0x0800 else None
    if linktype in (101, 228):                                    # raw IP / raw IPv4
        return frame
    return None


def udp_datagrams(packets):
    """Group IP fragments into UDP datagrams. Returns a list of dicts in time order."""
    groups = {}
    for t, lt, frame in packets:
        ip = ip_payload(lt, frame)
        if not ip or ip[0] >> 4 != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total, ident, frag = struct.unpack_from(">HHH", ip, 2)
        key = (ip[12:16], ip[16:20], ident)
        g = groups.setdefault(key, {"t_first": t, "t_last": t, "packets": 0, "ip_bytes": 0, "payload": None,
                                    "ip_payload": 0, "udp_len": 0})
        g["t_first"], g["t_last"] = min(g["t_first"], t), max(g["t_last"], t)
        g["packets"] += 1
        g["ip_bytes"] += total
        g["ip_payload"] += total - ihl                            # pieces must add up to udp_len
        if frag & 0x1FFF == 0:                                    # first fragment: UDP header + start
            g["payload"] = ip[ihl + 8:]
            g["udp_len"] = struct.unpack_from(">H", ip, ihl + 4)[0]
            g["src"] = ".".join(map(str, ip[12:16]))
    return sorted((g for g in groups.values() if g["payload"] is not None), key=lambda g: g["t_first"])


def messages_from_capture(datagrams):
    """Per sequence number: the AUTH message (packets, bytes, times), the CHALLENGE and RESULT."""
    auth = defaultdict(lambda: {"datagrams": 0, "packets": 0, "ip_bytes": 0, "t_first": None, "t_last": None,
                                "incomplete": 0, "mavlink_bytes": 0})
    other = defaultdict(dict)
    for g in datagrams:
        p = g["payload"]
        if p[:2] == b"DA" and len(p) >= 12:
            mtype, seq = p[3], int.from_bytes(p[6:8], "big")
        elif p[:2] == b"DF" and len(p) >= 10:
            mtype, seq = p[2], int.from_bytes(p[4:6], "big")
        elif p[:1] == b"\xfd" and len(p) >= 17 and (p[7] | p[8] << 8 | p[9] << 16) in MAVLINK_IDS:
            # real MAVLink 2 packet: 10-byte header, then the payload; TUNNEL and V2_EXTENSION both have
            # 5 bytes of fields before their payload array, where our fragment header (sequence first) starts
            mtype, seq = AUTH, int.from_bytes(p[15:17], "big")
            auth[seq]["mavlink_bytes"] += g["udp_len"] - 8
        else:
            continue
        if mtype == AUTH:
            a = auth[seq]
            a["datagrams"] += 1
            a["packets"] += g["packets"]
            a["incomplete"] += int(g["ip_payload"] < g["udp_len"])     # a piece of a split message is missing
            a["ip_bytes"] += g["ip_bytes"]
            a["t_first"] = g["t_first"] if a["t_first"] is None else min(a["t_first"], g["t_first"])
            a["t_last"] = g["t_last"] if a["t_last"] is None else max(a["t_last"], g["t_last"])
        elif mtype in (CHALLENGE, RESULT):
            other[seq][mtype] = g
    return auth, other


def pct(v, p):
    v = np.sort(np.asarray(v, float))
    return float(v[max(0, int(np.ceil(p / 100 * len(v))) - 1)]) if len(v) else float("nan")


def median_ci(v, reps=10000, seed=1):
    """95% bootstrap confidence interval of the median (percentile method, fixed seed)."""
    v = np.asarray(v, float)
    if len(v) < 2:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    meds = np.median(rng.choice(v, size=(reps, len(v)), replace=True), axis=1)
    return float(np.percentile(meds, 2.5)), float(np.percentile(meds, 97.5))


def figures(summary, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from plot_sig_bench import COLOR, DASH, name
    plt.rcParams.update({"font.size": 8, "legend.fontsize": 6.5, "xtick.labelsize": 7, "ytick.labelsize": 7,
                         "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                         "grid.color": "#e4e3df", "grid.linewidth": 0.6, "axes.axisbelow": True,
                         "legend.frameon": False, "savefig.dpi": 300, "savefig.bbox": "tight", "pdf.fonttype": 42})
    out.mkdir(parents=True, exist_ok=True)

    # Figure 6: packets per signed message vs data size, measured
    fig, axes = plt.subplots(1, 2, figsize=(3.5, 2.4), sharey=True)
    for ax, style, title in ((axes[0], "udp", "Wi-Fi UDP"), (axes[1], "mav", "MAVLink-sized frames")):
        for a in ORDER:
            pts = sorted((r["data_len"], r["packets_median"]) for r in summary
                         if r["algorithm"] == a and r["style"] == style and r["packets_median"] == r["packets_median"])
            if pts:
                ax.plot([p[0] for p in pts], [p[1] for p in pts], color=COLOR[a], ls=DASH[a], lw=1.2,
                        marker="o", ms=2.2, label=name(a))
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xticks([64, 1024, 8192], ["64 B", "1 KB", "8 KB"])
        ax.set_yticks([1, 2, 5, 10, 20, 50], ["1", "2", "5", "10", "20", "50"])
        ax.minorticks_off()
        ax.set_title(title, fontsize=7, loc="left")
        ax.set_xlabel("Data signed (bytes)")
    axes[0].set_ylabel("Packets per signed message")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", bbox_to_anchor=(0.5, 0.98), ncol=3)
    fig.savefig(out / "fig6_link_packets.pdf")
    fig.savefig(out / "fig6_link_packets.png")
    plt.close(fig)

    # Figure 7: where the time of one authentication goes (64 bytes of data, Wi-Fi UDP)
    fig, ax = plt.subplots(figsize=(3.5, 2.4))
    rows = [r for r in summary if r["style"] == "udp" and r["data_len"] == 64]
    rows.sort(key=lambda r: ORDER.index(r["algorithm"]))
    x = np.arange(len(rows))
    sign = np.array([r["drone_sign_median_ms"] for r in rows])
    link = np.array([r["link_median_ms"] for r in rows])
    ax.bar(x, sign, 0.6, color="#2a78d6", edgecolor="white", linewidth=0.5, label="Drone signing")
    ax.bar(x, link, 0.6, bottom=sign, color="#eb6834", edgecolor="white", linewidth=0.5,
           label="Network + ground station")
    for xi, r in zip(x, rows):
        ax.plot([xi, xi], [r["rtt_median_ms"], r["rtt_p95_ms"]], color="#52514e", lw=0.8)
        ax.text(xi, r["rtt_p95_ms"] + 8, f"{r['rtt_median_ms']:.0f}", ha="center", va="bottom", fontsize=6)
    ax.plot([], [], color="#52514e", lw=0.8, label="line up to p95 (total)")
    two = {"ECDSA-P256": "ECDSA\nP-256", "RSA-3072": "RSA\n3072", "ML-DSA-44": "ML-DSA\n44",
           "ML-DSA-65": "ML-DSA\n65", "ML-DSA-87": "ML-DSA\n87"}
    ax.set_xticks(x, [two.get(r["algorithm"], name(r["algorithm"])) for r in rows])
    ax.tick_params(axis="x", length=0, labelsize=6.5)
    ax.set_ylabel("Challenge to verified signature (ms)")
    ax.set_ylim(0, max(r["rtt_p95_ms"] for r in rows) * 1.25)
    ax.grid(axis="x", visible=False)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, fontsize=6.5)
    fig.savefig(out / "fig7_link_time.pdf")
    fig.savefig(out / "fig7_link_time.png")
    plt.close(fig)


RADIO_BPS = 57600          # a common MAVLink telemetry radio serial speed (baud)
BITS_PER_BYTE = 10         # serial line 8N1: start bit + 8 data bits + stop bit
MAVLINK2_OVERHEAD = 12     # MAVLink 2 per packet: 10-byte header + 2-byte checksum (mavlink.io serialization)
MAVLINK2_SIGNATURE = 13    # optional MAVLink 2 signing: link id 1 + timestamp 6 + signature 6 (mavlink.io)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run = Path(sys.argv[1])
    meta = json.loads((run / "meta.json").read_text())
    log = list(csv.DictReader(open(run / "gcs_log.csv")))
    cap_path = run / "capture.pcapng"
    auth, other = ({}, {})
    if cap_path.exists():
        auth, other = messages_from_capture(udp_datagrams(read_pcapng(cap_path)))
    out = ROOT / "results" / "e3" / run.name
    out.mkdir(parents=True, exist_ok=True)

    # ---- one line per authentication
    per = []
    for r in log:
        seq = int(r["seq"])
        c = auth.get(seq)
        ch = other.get(seq, {}).get(CHALLENGE)
        rs = other.get(seq, {}).get(RESULT)
        f = lambda k: float(r[k]) if r.get(k) not in (None, "") else float("nan")
        row = {"algorithm": r["algorithm"], "style": r["style"], "data_len": int(r["data_len"]), "seq": seq,
               "lost": int(r["lost"]), "verified": int(r.get("auth_ok") or 0) * int(r.get("challenge_ok") or 0),
               "sig_len": r.get("sig_len", ""), "message_len": r.get("message_len", ""),
               "rtt_ms": f("rtt_ms"), "verify_ms": f("verify_ms"), "drone_sign_ms": f("drone_sign_ms"),
               "drone_total_ms": f("drone_total_ms"), "drone_send_waits": f("drone_send_waits"),
               "packets": c["packets"] if c else float("nan"), "datagrams": c["datagrams"] if c else float("nan"),
               "auth_ip_bytes": c["ip_bytes"] if c else float("nan"),
               "mavlink_bytes": c["mavlink_bytes"] if c and c["mavlink_bytes"] else float("nan"),
               "exchange_ip_bytes": (c["ip_bytes"] + (ch["ip_bytes"] if ch else 0) + (rs["ip_bytes"] if rs else 0))
               if c else float("nan"),
               "transfer_ms": (c["t_last"] - c["t_first"]) * 1000 if c else float("nan"),
               "link_ms": f("rtt_ms") - f("drone_sign_ms"),     # network + ground station, without signing
               "air_time_ms": (c["t_last"] - ch["t_first"]) * 1000 if c and ch else float("nan")}
        per.append(row)
    cols = list(per[0].keys())
    with open(out / "per_message.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(per)

    # ---- summary per algorithm, style and size
    groups = defaultdict(list)
    for p in per:
        groups[(p["algorithm"], p["style"], p["data_len"])].append(p)
    summary = []
    for (a, st, dl), ps in sorted(groups.items(), key=lambda kv: (ORDER.index(kv[0][0]), STYLE_ORDER.index(kv[0][1]),
                                                                    kv[0][2])):
        ok = [p for p in ps if not p["lost"]]
        val = lambda k: [p[k] for p in ok if p[k] == p[k]]
        sig = [int(p["sig_len"]) for p in ok if p["sig_len"]]
        summary.append({
            "algorithm": a, "style": st, "data_len": dl, "n": len(ps), "lost_percent": 100 * (len(ps) - len(ok)) / len(ps),
            "verified_percent": 100 * sum(p["verified"] for p in ps) / len(ps),
            "signature_B": max(sig) if sig else float("nan"),
            "packets_median": float(np.median(val("packets"))) if val("packets") else float("nan"),
            "packets_max": max(val("packets")) if val("packets") else float("nan"),
            "auth_ip_bytes_median": float(np.median(val("auth_ip_bytes"))) if val("auth_ip_bytes") else float("nan"),
            "mavlink_bytes_median": float(np.median(val("mavlink_bytes"))) if val("mavlink_bytes") else float("nan"),
            "exchange_ip_bytes_median": float(np.median(val("exchange_ip_bytes"))) if val("exchange_ip_bytes") else float("nan"),
            "signature_share_percent": 100 * (max(sig) if sig else 0) / float(np.median(val("auth_ip_bytes")))
            if val("auth_ip_bytes") and sig else float("nan"),
            "rtt_median_ms": float(np.median(val("rtt_ms"))) if val("rtt_ms") else float("nan"),
            "rtt_p95_ms": pct(val("rtt_ms"), 95) if val("rtt_ms") else float("nan"),
            "rtt_median_ci_low_ms": median_ci(val("rtt_ms"))[0],
            "rtt_median_ci_high_ms": median_ci(val("rtt_ms"))[1],
            "rtt_mean_ms": float(np.mean(val("rtt_ms"))) if val("rtt_ms") else float("nan"),
            "drone_sign_median_ms": float(np.median(val("drone_sign_ms"))) if val("drone_sign_ms") else float("nan"),
            "transfer_median_ms": float(np.median(val("transfer_ms"))) if val("transfer_ms") else float("nan"),
            "link_median_ms": float(np.median(val("link_ms"))) if val("link_ms") else float("nan"),
            "link_p95_ms": pct(val("link_ms"), 95) if val("link_ms") else float("nan"),
            "verify_median_ms": float(np.median(val("verify_ms"))) if val("verify_ms") else float("nan"),
        })
    with open(out / "summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0].keys()))
        w.writeheader()
        for s in summary:
            w.writerow({k: (round(v, 3) if isinstance(v, float) else v) for k, v in s.items()})

    # ---- largest data that still went in ONE packet (measured)
    one = []
    for a in ORDER:
        for st in STYLE_ORDER:
            rows = [s for s in summary if s["algorithm"] == a and s["style"] == st]
            if not rows:
                continue
            fits = [s["data_len"] for s in rows if s["packets_max"] == 1]
            splits = [s["data_len"] for s in rows if s["packets_max"] == s["packets_max"] and s["packets_max"] > 1]
            one.append({"algorithm": a, "style": st, "largest_tested_one_packet_B": max(fits) if fits else 0,
                        "smallest_tested_split_B": min(splits) if splits else ""})
    with open(out / "one_packet.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(one[0].keys()))
        w.writeheader()
        w.writerows(one)

    if auth and any(s["style"] == "udp" for s in summary):
        figures(summary, out / "figures")

    # ---- readable tables
    fmt = lambda v, d=1: "-" if v != v else f"{v:,.{d}f}"
    L = [f"# Step 3 (E3): drone authentication on a real Wi-Fi link\n",
         f"Run `{run.name}`. Drone {meta.get('drone_id')} at {meta.get('drone_ip')}, captured on {meta.get('iface')}. "
         f"{meta.get('runs')} authentications per algorithm, style and size. Git commit `{meta.get('git_commit', '?')[:12]}`. "
         f"Ground station Wi-Fi power saving: {meta.get('gcs_wifi_power_save', 'not recorded')}.\n",
         "Styles: **udp** = one UDP datagram per message (split by the IP layer into 1,500-byte packets); "
         "**mav** = MAVLink-sized frames of at most 255 payload bytes, one UDP datagram each (emulated); "
         "**tunnel** / **v2ext** = real MAVLink 2 TUNNEL / V2_EXTENSION packets from the official C library, "
         "parsed and CRC-checked by pymavlink, one UDP datagram each.\n"]
    if meta.get("pymavlink"):
        L.append(f"pymavlink {meta['pymavlink']}: {meta.get('mavlink_packets_parsed')} MAVLink packets parsed, "
                 f"{meta.get('mavlink_bad_packets')} rejected (bad CRC or malformed).\n")
    if not auth:
        L.append("**No capture found: packet counts and bytes are missing.**\n")
    L += ["\n## Largest data that still fitted in ONE packet (measured)\n",
          "| Algorithm | Wi-Fi UDP: one packet up to | first size that needed 2+ | MAVLink-sized: one frame up to | first size that needed 2+ |",
          "|---|---:|---:|---:|---:|"]
    for a in ORDER if any(o["style"] in ("udp", "mav") for o in one) else []:
        u = next((o for o in one if o["algorithm"] == a and o["style"] == "udp"), None)
        m = next((o for o in one if o["algorithm"] == a and o["style"] == "mav"), None)
        if u or m:
            c = lambda o, k: "-" if not o else (f"{o[k]:,} B" if o[k] not in ("", 0) else ("none" if k.startswith("largest") else "-"))
            L.append(f"| {a} | {c(u, 'largest_tested_one_packet_B')} | {c(u, 'smallest_tested_split_B')} | "
                     f"{c(m, 'largest_tested_one_packet_B')} | {c(m, 'smallest_tested_split_B')} |")
    L.append("\n'none' = even the smallest message (64 bytes of data) needed more than one packet.")
    for st in [x for x in STYLE_ORDER if any(s["style"] == x for s in summary)]:
        title = STYLE_TITLE[st]
        L += [f"\n## {title}: every algorithm and data size (medians)\n",
              "| Algorithm | Data (B) | Packets | Bytes on wire (auth msg) | Signature share | Challenge to verified (ms) | 95% CI of the median (ms) | p95 (ms) | Drone signing (ms) | Network + ground station (ms) | Transfer of the message (ms) | Lost |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for s in summary:
            if s["style"] == st:
                L.append(f"| {s['algorithm']} | {s['data_len']:,} | {fmt(s['packets_median'], 0)} | {fmt(s['auth_ip_bytes_median'], 0)} | "
                         f"{fmt(s['signature_share_percent'])}% | {fmt(s['rtt_median_ms'])} | {fmt(s['rtt_median_ci_low_ms'])}-{fmt(s['rtt_median_ci_high_ms'])} | {fmt(s['rtt_p95_ms'])} | "
                         f"{fmt(s['drone_sign_median_ms'])} | {fmt(s['link_median_ms'])} | {fmt(s['transfer_median_ms'], 2)} | {fmt(s['lost_percent'])}% |")
    missing = sum(1 for c in auth.values() if c["incomplete"])
    if missing:
        L.append(f"\n**WARNING: for {missing} messages the capture is missing pieces of a split message "
                 "(packet counts and bytes of the udp style are too low). Capture with gcs_link_test.py "
                 "version that keeps IP fragments.**")
    L += ["\n## Calculated: sending the signed message over a 57.6 kbit/s MAVLink telemetry radio\n",
          "Uses the measured message length and frame count (MAVLink-sized style) and adds MAVLink 2's 12 bytes of "
          "header and checksum per frame. No IP/UDP headers on a serial radio. A 57,600-baud serial line sends 10 bits "
          "per byte (start bit, 8 data bits, stop bit), so time = bytes x 10 / 57,600. Last column: with MAVLink 2's "
          "own message signing switched on as well (13 more bytes per frame).\n",
          "| Algorithm | Data (B) | Frames | Bytes on the radio | Time on the radio (ms) | With MAVLink signing (ms) |",
          "|---|---:|---:|---:|---:|---:|"]
    for s_ in summary:
        if s_["style"] == "mav" and s_["data_len"] in (64, 1024):
            ml = [int(p["message_len"]) for p in per if p["algorithm"] == s_["algorithm"] and p["style"] == "mav"
                  and p["data_len"] == s_["data_len"] and p["message_len"]]
            if ml and s_["packets_median"] == s_["packets_median"]:
                byts = max(ml) + int(s_["packets_median"]) * MAVLINK2_OVERHEAD
                signed = byts + int(s_["packets_median"]) * MAVLINK2_SIGNATURE
                L.append(f"| {s_['algorithm']} | {s_['data_len']:,} | {int(s_['packets_median'])} | {byts:,} | "
                         f"{byts * BITS_PER_BYTE * 1000 / RADIO_BPS:,.0f} | {signed * BITS_PER_BYTE * 1000 / RADIO_BPS:,.0f} |")
    real = [s_ for s_ in summary if s_["style"] in ("tunnel", "v2ext") and s_["mavlink_bytes_median"] == s_["mavlink_bytes_median"]]
    if real:
        L += ["\n## Real MAVLink 2 packets on a 57,600-baud telemetry radio (calculated from the MEASURED packet bytes)\n",
              "Bytes = the MAVLink 2 packets exactly as captured (header, payload after MAVLink 2's trailing-zero "
              "truncation, checksum; no IP/UDP). Time = bytes x 10 / 57,600. Last column: MAVLink 2 signing on "
              "(13 more bytes per packet).\n",
              "| Style | Algorithm | Data (B) | Packets | MAVLink bytes | Time on the radio (ms) | With MAVLink signing (ms) |",
              "|---|---|---:|---:|---:|---:|---:|"]
        for s_ in real:
            byts, pk = s_["mavlink_bytes_median"], s_["packets_median"]
            L.append(f"| {s_['style']} | {s_['algorithm']} | {s_['data_len']:,} | {pk:.0f} | {byts:,.0f} | "
                     f"{byts * BITS_PER_BYTE * 1000 / RADIO_BPS:,.0f} | "
                     f"{(byts + pk * MAVLINK2_SIGNATURE) * BITS_PER_BYTE * 1000 / RADIO_BPS:,.0f} |")
    total = len(per)
    lost = sum(p["lost"] for p in per)
    verified = sum(p["verified"] for p in per)
    L.append("\nNetwork + ground station = challenge-to-verified time minus the drone's signing time (per message, then median). "
             "Transfer = time between the first and the last packet of the signed message in the capture.")
    L.append(f"\nAll runs: {total} authentications, {verified} verified by the ground station, {lost} lost "
             f"(no complete answer within 5 s).")
    (out / "results.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))
    print(f"\nFiles written to {out}")


if __name__ == "__main__":
    main()
