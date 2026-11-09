#!/usr/bin/env python3
"""Make the graphs for the whole-VPN benchmark (classical vs. post-quantum).

Reads the result files in both projects and saves PNGs in results/graphs/.
Run from anywhere:  python3 make_graphs.py
"""
import csv
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CLASSICAL_DIR = REPO / "Non_PQC_VPN/benchmarking/system_benchmark/results"
PQC_DIR = HERE / "results"
OUT = PQC_DIR / "graphs"

# Same two colours on every graph: blue = classical, orange = post-quantum.
C_CLASSIC = "#2a78d6"
C_PQC = "#eb6834"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
SURFACE = "#fcfcfb"
REFUSED = "#b9b8b2"
NAMES = ("Classical (Ed25519 + X25519)", "Post-quantum (ML-DSA-44 + ML-KEM-512)")

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "axes.edgecolor": INK2, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "axes.grid.axis": "y", "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.axisbelow": True, "font.size": 10, "axes.titlesize": 12,
    "axes.titleweight": "bold", "axes.titlecolor": INK, "axes.titlelocation": "left",
    "legend.frameon": False, "savefig.dpi": 200, "savefig.bbox": "tight",
})


def load(path):
    rows = {}
    with open(path) as f:
        for r in csv.DictReader(f):
            rows[(r["id"], r["metric"])] = {k: float(r[k]) for k in ("median", "p95", "mean")}
    return rows


def part_c(path):
    """Read the alternating-rounds table from gateway_crypto_comparison.md."""
    out = []
    pat = re.compile(r"^\| (.+?) \| ([\d.]+) ms \(p95 ([\d.]+)\) \| ([\d.]+) ms \(p95 ([\d.]+)\) \|")
    for line in path.read_text().splitlines():
        m = pat.match(line)
        if m:
            out.append((m.group(1), *map(float, m.groups()[1:])))
    return out


def label(ax, x, y, text, dy=0):
    ax.annotate(text, (x, y), xytext=(0, 3 + dy), textcoords="offset points",
                ha="center", va="bottom", fontsize=9, color=INK)


def paired_bars(ax, groups, cm, cp95, pm, pp95, fmt, show_p95=True):
    """Median bars, p95 whiskers, classical left / PQC right."""
    w = 0.36
    xs = range(len(groups))
    for off, med, p95, col in ((-w / 2 - 0.01, cm, cp95, C_CLASSIC), (w / 2 + 0.01, pm, pp95, C_PQC)):
        for i, (m, p) in enumerate(zip(med, p95)):
            x = i + off
            ax.bar(x, m, w, color=col, edgecolor=SURFACE, linewidth=1)
            if show_p95 and p is not None and p > m:
                ax.errorbar(x, m, yerr=[[0], [p - m]], color=INK2, capsize=4, linewidth=1)
                label(ax, x, p, fmt(m))
            else:
                label(ax, x, m, fmt(m))
    ax.set_xticks(list(xs), groups)
    ax.tick_params(axis="x", length=0)


def legend(ax, extra_p95=True, **kw):
    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    h = [Patch(color=C_CLASSIC, label=NAMES[0]), Patch(color=C_PQC, label=NAMES[1])]
    if extra_p95:
        h.append(Line2D([], [], color=INK2, marker="_", markersize=10, linewidth=1, label="whisker = p95"))
    ax.legend(handles=h, **kw)


def save(fig, name):
    fig.savefig(OUT / name)
    plt.close(fig)
    print("saved", OUT / name)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ce = load(CLASSICAL_DIR / "esp32_results.csv")
    pe = load(PQC_DIR / "esp32_results.csv")
    cl = load(CLASSICAL_DIR / "laptop_gateway_results.csv")
    pl = load(PQC_DIR / "laptop_gateway_results.csv")

    # 1. Handshake time on the ESP32
    fig, ax = plt.subplots(figsize=(7, 4.2))
    keys = [("B2", "tcp_connect_time"), ("B2", "handshake_msg1_to_msg4"), ("B2", "connect_plus_handshake_total")]
    paired_bars(ax, ["TCP connect", "Handshake (MSG1-MSG4)", "Connect + handshake"],
                [ce[k]["median"] for k in keys], [ce[k]["p95"] for k in keys],
                [pe[k]["median"] for k in keys], [pe[k]["p95"] for k in keys],
                lambda v: f"{v:.0f} ms")
    ax.set_ylabel("Time on the ESP32 (ms), median")
    ax.set_title("The post-quantum handshake takes about 2.4x longer on the ESP32")
    legend(ax, loc="upper left")
    ax.set_ylim(0, 520)
    save(fig, "1_esp32_handshake_time.png")

    # 2. Handshake size per message (grouped bars, one pair per message)
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    c_sizes, p_sizes = [82, 128, 96, 40], [850, 3220, 2452, 40]
    paired_bars(ax, ["MSG1\nESP32 hello", "MSG2\ngateway reply", "MSG3\nESP32 proof", "MSG4\nconfirm"],
                c_sizes, [None] * 4, p_sizes, [None] * 4, lambda v: f"{v:,.0f} B", show_p95=False)
    ax.set_ylabel("Bytes sent")
    ax.set_ylim(0, 3700)
    ax.set_title("The post-quantum handshake sends 19x more bytes (6,562 vs. 346 in total)")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=C_CLASSIC, label="Classical"), Patch(color=C_PQC, label="Post-quantum")],
              loc="upper left")
    save(fig, "2_handshake_bytes.png")

    # 3. Gateway crypto per handshake, per step (Part C)
    rows = part_c(PQC_DIR / "gateway_crypto_comparison.md")
    steps = [r for r in rows if not r[0].startswith("TOTAL")]
    total = [r for r in rows if r[0].startswith("TOTAL")][0]
    names = ["Key\nexchange", "Sign", "Verify", "HKDF", "HMAC tags"]
    fig, axes = plt.subplots(1, 2, figsize=(9.5, 4.2), gridspec_kw={"width_ratios": [5, 1.4]})
    paired_bars(axes[0], names, [r[1] for r in steps], [r[2] for r in steps],
                [r[3] for r in steps], [r[4] for r in steps], lambda v: f"{v:.3f}")
    axes[0].set_ylabel("Time on the laptop gateway (ms), median")
    axes[0].set_ylim(0, 1.0)
    paired_bars(axes[1], ["Total"], [total[1]], [total[2]], [total[3]], [total[4]], lambda v: f"{v:.3f}")
    axes[1].set_ylim(0, 1.0)
    axes[1].set_yticklabels([])
    fig.suptitle("Gateway: post-quantum costs 0.32 ms per handshake vs. 0.18 ms; signing is the slow step",
                 x=0.01, ha="left", fontweight="bold", color=INK, fontsize=12)
    legend(axes[0], loc="upper right")
    fig.tight_layout()
    save(fig, "3_gateway_crypto_per_step.png")

    # 4. After the handshake: added latency and CPU (two separate panels, no dual axis)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
    k = [("B3", "added_latency_median_64B"), ("B3", "added_latency_median_1023B")]
    paired_bars(axes[0], ["64 B message", "1,023 B message"],
                [ce[x]["median"] for x in k], [None, None], [pe[x]["median"] for x in k], [None, None],
                lambda v: f"+{v:.2f} ms", show_p95=False)
    axes[0].set_ylabel("Extra round-trip time vs. plain TCP (ms)")
    axes[0].set_title("Extra delay from encryption", fontsize=11)
    axes[0].set_ylim(0, 3.5)
    k = [("B6", "cpu_idle_tunnel_average"), ("B6", "cpu_normal_ping_average"), ("B6", "cpu_sustained_512B_average")]
    paired_bars(axes[1], ["Idle tunnel", "Normal use", "Stream 512 B\nevery 40 ms"],
                [ce[x]["median"] for x in k], [None] * 3, [pe[x]["median"] for x in k], [None] * 3,
                lambda v: f"{v:.1f}%", show_p95=False)
    axes[1].set_ylabel("ESP32 CPU used (%, both cores)")
    axes[1].set_title("CPU use", fontsize=11)
    axes[1].set_ylim(0, 12)
    fig.suptitle("After the handshake both VPNs cost the same (same AES-256-GCM tunnel)",
                 x=0.01, ha="left", fontweight="bold", color=INK, fontsize=12)
    legend(axes[1], extra_p95=False, loc="upper left")
    fig.tight_layout()
    save(fig, "4_after_handshake_latency_cpu.png")

    # 5. Rekey time
    fig, ax = plt.subplots(figsize=(5.5, 4))
    k = ("B5", "rekey_time")
    paired_bars(ax, ["Rekey inside the tunnel"], [ce[k]["median"]], [ce[k]["p95"]],
                [pe[k]["median"]], [pe[k]["p95"]], lambda v: f"{v:.1f} ms")
    ax.set_ylabel("Time on the ESP32 (ms), median")
    ax.set_ylim(0, 75)
    ax.set_title("Rekeying is faster with ML-KEM-512\n(25 ms vs. 43 ms)")
    legend(ax, loc="upper right", fontsize=8.5)
    save(fig, "5_rekey_time.png")

    # 6. Memory: heap peak and program size (two panels, different units)
    fig, axes = plt.subplots(1, 2, figsize=(9, 4))
    for ax, key, title, ylim in ((axes[0], ("B7", "heap_peak_used"), "Highest heap use (KB)", 260),
                                 (axes[1], ("B7", "flash_firmware_size"), "Program size, benchmark build (KB)", 1300)):
        c, p = ce[key]["median"] / 1024, pe[key]["median"] / 1024
        for x, v, col in ((0, c, C_CLASSIC), (1, p, C_PQC)):
            ax.bar(x, v, 0.6, color=col)
            label(ax, x, v, f"{v:,.0f} KB")
        ax.set_xticks([0, 1], ["Classical", "Post-quantum"])
        ax.tick_params(axis="x", length=0)
        ax.set_title(title, fontsize=11)
        ax.set_ylim(0, ylim)
    fig.suptitle("Post-quantum needs about 66 KB more heap (mostly its 64 KB stack) and 11 KB more program",
                 x=0.01, ha="left", fontweight="bold", color=INK, fontsize=12)
    fig.tight_layout()
    save(fig, "6_esp32_memory.png")

    # 7. Burst of devices connecting at once (small multiples)
    sizes = [1, 5, 10, 20, 40]
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    for ax, d, col, name in ((axes[0], cl, C_CLASSIC, "Classical"), (axes[1], pl, C_PQC, "Post-quantum")):
        acc = [d[("L5", f"burst_{n}_devices_accepted")]["median"] for n in sizes]
        ref = [d[("L5", f"burst_{n}_devices_refused_by_dos_cap")]["median"] for n in sizes]
        xs = range(len(sizes))
        ax.bar(xs, acc, 0.6, color=col, edgecolor=SURFACE, linewidth=1)
        ax.bar(xs, ref, 0.6, bottom=acc, color=REFUSED, hatch="///", edgecolor=SURFACE, linewidth=1)
        for x, a, r in zip(xs, acc, ref):
            label(ax, x, a + r, f"{a:.0f} in" + (f", {r:.0f} told to retry" if r else ""))
        ax.set_xticks(list(xs), [f"{n}" for n in sizes])
        ax.set_xlabel("Devices connecting at the same moment")
        ax.set_title(name, fontsize=11)
        ax.tick_params(axis="x", length=0)
    axes[0].set_ylabel("Devices")
    axes[0].set_ylim(0, 46)
    from matplotlib.patches import Patch
    axes[1].legend(handles=[Patch(color=C_CLASSIC, label="Let in (classical)"),
                            Patch(color=C_PQC, label="Let in (post-quantum)"),
                            Patch(facecolor=REFUSED, hatch="///", edgecolor=SURFACE,
                                  label="Refused by the 8-handshake limit (they retry)")],
                   loc="upper left", fontsize=8.5)
    fig.suptitle("The slower post-quantum handshake hits the 8-at-once limit sooner; nobody is dropped for good",
                 x=0.01, ha="left", fontweight="bold", color=INK, fontsize=12)
    fig.tight_layout()
    save(fig, "7_gateway_burst.png")

    # 8. Many open tunnels at once (two panels, no dual axis)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for d, col, name, mk in ((cl, C_CLASSIC, NAMES[0], "o"), (pl, C_PQC, NAMES[1], "s")):
        mps = [d[("L6", f"tunnels_{n}_aggregate_messages_per_s")]["median"] / 1000 for n in sizes]
        rtt = [d[("L6", f"tunnels_{n}_round_trip")]["median"] for n in sizes]
        axes[0].plot(sizes, mps, color=col, marker=mk, markersize=6, linewidth=2, label=name)
        axes[1].plot(sizes, rtt, color=col, marker=mk, markersize=6, linewidth=2, label=name)
    axes[0].set_ylabel("Messages per second, all tunnels (thousands)")
    axes[0].set_ylim(0, 28)
    axes[0].set_title("Gateway throughput", fontsize=11)
    axes[1].set_ylabel("Round-trip time, median (ms)")
    axes[1].set_ylim(0, 4)
    axes[1].set_title("Round-trip time per message", fontsize=11)
    for ax in axes:
        ax.set_xlabel("Open tunnels at the same time")
        ax.set_xticks(sizes)
        ax.grid(axis="x", visible=False)
    axes[1].legend(loc="upper left", fontsize=8.5)
    fig.suptitle("With tunnels open, classical and post-quantum lines lie on top of each other",
                 x=0.01, ha="left", fontweight="bold", color=INK, fontsize=12)
    fig.tight_layout()
    save(fig, "8_gateway_many_tunnels.png")


if __name__ == "__main__":
    main()
