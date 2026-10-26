#!/usr/bin/env python3
"""
Clean, Single-KPI Scientific Graphs for Phase A (ESP32)
Each graph features:
  - Clean bar chart with exact numeric values
  - Clear title and axis labels
  - Humanized one-liner explanation neatly wrapped below the plot area
  - Guaranteed zero text clipping (auto-wrapped and bbox_inches='tight')

Generated Graphs:
  1. fig_keygen_mean.png        : Key Generation Mean Latency (SIG-1)
  2. fig_crypto_auth_cost.png   : Crypto Auth Cost - Sign + Verify (SIG-6)
  3. fig_signature_wire_size.png: Signature Wire Size (SIG-4)
  4. fig_heap_steady_state.png  : Steady-State Dynamic Heap RAM (SIG-7a)
  5. fig_heap_keygen.png        : KeyGen Peak Heap RAM (SIG-7b)
  6. fig_stack_usage.png        : Peak Crypto Stack Usage (SIG-8)
"""

import os
import glob
import textwrap
import matplotlib.pyplot as plt

# Scientific typography
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 11
plt.rcParams['axes.titlesize'] = 13
plt.rcParams['axes.titleweight'] = 'bold'
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.labelweight'] = 'bold'
plt.rcParams['xtick.labelsize'] = 11
plt.rcParams['ytick.labelsize'] = 11

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "graphs")
os.makedirs(OUT_DIR, exist_ok=True)

ALGS = ["Ed25519", "ECDSA P-256", "RSA-3072"]
COLORS = ["#10B981", "#3B82F6", "#EF4444"]  # Green, Blue, Red


def cleanup_old_graphs():
    """Remove previous or unwanted graph files so only the 6 core graphs remain."""
    patterns = [
        "fig_timing_*.png", "fig_size_*.png", "fig_memory_*.png",
        "fig_radar_*.png", "fig_sign_vs_verify.png"
    ]
    for pat in patterns:
        for f in glob.glob(os.path.join(OUT_DIR, pat)):
            try:
                os.remove(f)
            except OSError:
                pass


def create_kpi_graph(title, y_label, values, y_max, value_format, caption, filename):
    """Generates a clean single-KPI bar chart with a neatly wrapped explanation below the plot."""
    # Generous figure proportions to ensure zero text clipping
    fig, ax = plt.subplots(figsize=(8.0, 5.4))
    fig.patch.set_facecolor('white')

    bars = ax.bar(ALGS, values, color=COLORS, width=0.48, edgecolor='black', linewidth=1)

    ax.set_title(title, pad=12)
    ax.set_ylabel(y_label)
    ax.set_ylim(0, y_max)
    ax.grid(axis='y', linestyle='--', alpha=0.4)

    # Numbers on top of each bar
    for bar in bars:
        h = bar.get_height()
        label = value_format(h)
        offset = y_max * 0.02
        ax.text(bar.get_x() + bar.get_width() / 2.0, h + offset, label,
                ha='center', va='bottom', fontsize=11, fontweight='bold')

    # Leave dedicated room at the bottom for the explanation
    plt.subplots_adjust(bottom=0.24, top=0.90, left=0.12, right=0.95)

    # Automatically wrap text to 55 characters per line so it stays safely within the image margins
    wrapped_caption = "\n".join(textwrap.wrap(caption, width=58))

    # Centered explanation below the graph
    fig.text(0.53, 0.05, wrapped_caption, ha='center', va='center',
             fontsize=10.5, style='italic', color='#374151',
             bbox=dict(boxstyle="round,pad=0.35", fc="#F3F4F6", ec="#D1D5DB", lw=0.8))

    out_path = os.path.join(OUT_DIR, filename)
    # bbox_inches='tight' guarantees that no text is cropped or cut off
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[OK] Generated: {out_path}")


def main():
    print("=" * 65)
    print("Generating 6 Clean Graphs (Wrapped One-Liners, Zero Clipping)")
    print("=" * 65)

    cleanup_old_graphs()

    # 1. KeyGen Mean Latency (SIG-1)
    create_kpi_graph(
        title="Key Generation Mean Latency (SIG-1)",
        y_label="Latency (ms)",
        values=[8.68, 146.02, 17081.90],
        y_max=19500,
        value_format=lambda h: f"{h:.1f} ms" if h < 1000 else f"{h:,.1f} ms",
        caption="Measures how long the ESP32 takes to create its identity keys once during initial device setup.",
        filename="fig_keygen_mean.png"
    )

    # 2. Crypto Auth Cost: Sign + Verify (SIG-6)
    create_kpi_graph(
        title="Cryptographic Authentication Cost (SIG-6)",
        y_label="Latency (ms)",
        values=[29.35, 470.09, 388.27],
        y_max=530,
        value_format=lambda h: f"{h:.2f} ms",
        caption="Measures total CPU time for the ESP32 to prove its identity and verify the server on every connection.",
        filename="fig_crypto_auth_cost.png"
    )

    # 3. Signature Wire Size (SIG-4)
    create_kpi_graph(
        title="Signature Wire Size (SIG-4)",
        y_label="Size (Bytes)",
        values=[64, 71.0, 384],
        y_max=440,
        value_format=lambda h: f"{int(round(h))} B",
        caption="Measures the physical packet data size of the digital signature sent over Wi-Fi to prove authentication.",
        filename="fig_signature_wire_size.png"
    )

    # 4. Steady-State Dynamic Heap RAM (SIG-7a)
    create_kpi_graph(
        title="Steady-State Dynamic Heap RAM (SIG-7a)",
        y_label="Heap RAM (Bytes)",
        values=[0, 3568, 11664],
        y_max=13500,
        value_format=lambda h: f"{int(round(h)):,} B",
        caption="Measures dynamic heap RAM allocated during active VPN connection handshakes to sign challenges and verify the server.",
        filename="fig_heap_steady_state.png"
    )

    # 5. KeyGen Peak Heap RAM (SIG-7b)
    create_kpi_graph(
        title="KeyGen Peak Heap RAM (SIG-7b)",
        y_label="Heap RAM (Bytes)",
        values=[0, 2896, 4792],
        y_max=5500,
        value_format=lambda h: f"{int(round(h)):,} B",
        caption="Measures temporary dynamic RAM required only during initial factory keypair generation.",
        filename="fig_heap_keygen.png"
    )

    # 6. Peak Crypto Stack Usage (SIG-8)
    create_kpi_graph(
        title="Peak Cryptographic Stack Usage (SIG-8)",
        y_label="Stack Usage (Bytes)",
        values=[4116, 3944, 3928],
        y_max=4800,
        value_format=lambda h: f"{int(round(h)):,} B",
        caption="Measures maximum execution call-stack memory depth reached inside the FreeRTOS task during crypto math.",
        filename="fig_stack_usage.png"
    )

    print("\n[SUCCESS] All 6 graphs regenerated with perfect text boundaries!")


if __name__ == "__main__":
    main()
