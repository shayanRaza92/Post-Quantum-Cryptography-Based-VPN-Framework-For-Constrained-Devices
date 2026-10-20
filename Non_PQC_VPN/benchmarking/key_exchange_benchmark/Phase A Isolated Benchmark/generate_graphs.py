import matplotlib.pyplot as plt
import numpy as np
import os

output_dir = "/home/shayan/Downloads/VPN1/FYP/Non_PQC VPN/deliverable3_Key Exchange/Key_Exchange algorithms benchmark/Phase A Isolated Benchmark/graphs"
os.makedirs(output_dir, exist_ok=True)

# Styling parameters matching Mutual Auth Phase A
plt.rcParams.update({
    'font.size': 12,
    'font.family': 'sans-serif',
    'axes.labelsize': 14,
    'axes.titlesize': 15,
    'xtick.labelsize': 12,
    'ytick.labelsize': 12,
    'legend.fontsize': 12,
    'figure.titlesize': 16
})

# =========================================================================
# Graph 1: Execution Time Comparison (Logarithmic Scale)
# =========================================================================
fig, ax = plt.subplots(figsize=(10, 6), dpi=300)

operations = ['Key Generation', 'Secret Derivation', 'Total Compute']
x = np.arange(len(operations))
width = 0.25

# Latencies in ms
x25519_times = [8.47, 16.91, 25.38]
p256_times   = [156.83, 156.73, 313.56]
dh2048_times = [31.60, 31.44, 63.04]

rects1 = ax.bar(x - width, x25519_times, width, label='X25519 (RFC 7748)', color='#1f77b4', edgecolor='black', linewidth=1)
rects2 = ax.bar(x,         dh2048_times, width, label='DH-2048 (RFC 3526)', color='#d62728', edgecolor='black', linewidth=1)
rects3 = ax.bar(x + width, p256_times,   width, label='ECDH P-256 (NIST)', color='#ff7f0e', edgecolor='black', linewidth=1)

ax.set_ylabel('Execution Time (ms, Log Scale)', fontsize=14)
ax.set_title('Execution Time Comparison on ESP32 @ 240 MHz (Logarithmic Scale)', pad=15, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(operations, fontweight='bold')
ax.set_yscale('log')
ax.set_ylim(1, 1000)
ax.legend(frameon=True, loc='upper left')
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.grid(axis='x', linestyle='--', alpha=0.3)

for rect in rects1:
    h = rect.get_height()
    ax.annotate(f'{h:.2f} ms', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 4),
                textcoords="offset points", ha='center', va='bottom', fontsize=10, fontweight='bold')

for rect in rects2:
    h = rect.get_height()
    ax.annotate(f'{h:.2f} ms', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 4),
                textcoords="offset points", ha='center', va='bottom', fontsize=10, fontweight='bold')

for rect in rects3:
    h = rect.get_height()
    ax.annotate(f'{h:.2f} ms', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 4),
                textcoords="offset points", ha='center', va='bottom', fontsize=10, fontweight='bold')

plt.tight_layout()
fig.savefig(os.path.join(output_dir, 'fig_timing_comparison.png'))
plt.close(fig)

# =========================================================================
# Graph 2: Wire and Cryptographic Overhead per Handshake (Stacked)
# =========================================================================
fig, ax = plt.subplots(figsize=(10, 6), dpi=300)

algos = ['X25519', 'ECDH P-256', 'DH-2048']
pub_keys = [32, 65, 256]
secrets  = [32, 32, 256]
totals   = [64, 97, 512]

b1 = ax.bar(algos, pub_keys, width=0.45, label='Public Key Wire Size (Bytes)', color='#2b5c8f', edgecolor='black', linewidth=1)
b2 = ax.bar(algos, secrets,  width=0.45, bottom=pub_keys, label='Shared Secret Size (Bytes)', color='#6baed6', edgecolor='black', linewidth=1)

ax.set_ylabel('Size on Wire (Bytes)', fontsize=14)
ax.set_title('Key Exchange Communication Overhead per Handshake (Bytes)', pad=15, fontweight='bold')
ax.set_ylim(0, 660)
ax.legend(frameon=True, loc='upper left')
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.set_xticks(range(len(algos)))
ax.set_xticklabels(algos, fontweight='bold')

# Middle label on bottom bar
for rect, val in zip(b1, pub_keys):
    ax.text(rect.get_x() + rect.get_width()/2, val/2, f'{val} B', ha='center', va='center', color='white', fontweight='bold', fontsize=11)

# Middle label on top bar
for rect, bot, val in zip(b2, pub_keys, secrets):
    ax.text(rect.get_x() + rect.get_width()/2, bot + val/2, f'{val} B', ha='center', va='center', color='black', fontweight='bold', fontsize=11)

# Total text above each bar
multipliers = ['(Baseline)', '(1.5x of X25519)', '(8.0x of X25519)']
for rect, tot, mult in zip(b2, totals, multipliers):
    ax.text(rect.get_x() + rect.get_width()/2, tot + 15, f'Total: {tot} Bytes\n{mult}', ha='center', va='bottom', color='black', fontweight='bold', fontsize=11)

plt.tight_layout()
fig.savefig(os.path.join(output_dir, 'fig_size_overhead.png'))
plt.close(fig)

# =========================================================================
# Graph 3: Dynamic Heap Memory Overhead during Operation (Bytes)
# =========================================================================
fig, ax = plt.subplots(figsize=(10, 6), dpi=300)

heap_values = [0, 348, 636]
colors = ['#1f77b4', '#ff7f0e', '#d62728']

b_heap = ax.bar(algos, heap_values, width=0.45, color=colors, edgecolor='black', linewidth=1)

ax.set_ylabel('Peak Dynamic Heap Consumed (Bytes)', fontsize=14)
ax.set_title('Dynamic Heap Memory Overhead during Operation (Bytes)', pad=15, fontweight='bold')
ax.set_ylim(0, 800)
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.set_xticks(range(len(algos)))
ax.set_xticklabels(algos, fontweight='bold')

annotations = [
    '0 Bytes\n(Stack Only / Baseline)',
    '348 Bytes\n(Mbed TLS Context)',
    '636 Bytes\n(MPI BigNum Context)'
]

for rect, text, val in zip(b_heap, annotations, heap_values):
    h = max(val, 0)
    y_pos = h + 20
    ax.text(rect.get_x() + rect.get_width()/2, y_pos, text, ha='center', va='bottom', color='black', fontweight='bold', fontsize=11)

plt.tight_layout()
fig.savefig(os.path.join(output_dir, 'fig_memory_comparison.png'))
plt.close(fig)

print("Simple, clean graphs successfully generated matching Mutual Auth Phase A style!")
