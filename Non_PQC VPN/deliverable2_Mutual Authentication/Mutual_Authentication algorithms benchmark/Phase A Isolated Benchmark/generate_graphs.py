import matplotlib.pyplot as plt
import numpy as np
import os

output_dir = "/home/shayan/Downloads/VPN1/FYP/Non_PQC VPN/deliverable2_Mutual Authentication/Mutual_Authentication algorithms benchmark/Phase A Isolated Benchmark/graphs"
os.makedirs(output_dir, exist_ok=True)

# Styling parameters matching Phase A / Phase B style
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
# Graph 1: Execution Latency Comparison (Logarithmic Scale)
# =========================================================================
fig, ax = plt.subplots(figsize=(11, 6), dpi=300)

operations = ['Key Generation', 'Message Signing', 'Verification', 'Total Client Sign']
x = np.arange(len(operations))
width = 0.25

# Latencies in ms from hardware run
ed25519_times = [8.56, 9.42, 19.80, 17.99]
p256_times    = [146.93, 158.58, 313.88, 305.51]
rsa_times     = [9630.80, 375.81, 1.71, 10006.61]

rects1 = ax.bar(x - width, ed25519_times, width, label='Ed25519 (Curve25519)', color='#1f77b4', edgecolor='black', linewidth=1)
rects2 = ax.bar(x,         p256_times,    width, label='ECDSA P-256 (NIST)',   color='#ff7f0e', edgecolor='black', linewidth=1)
rects3 = ax.bar(x + width, rsa_times,     width, label='RSA-3072 (PKCS#1 v1.5)', color='#d62728', edgecolor='black', linewidth=1)

ax.set_ylabel('Execution Time (ms, Log Scale)', fontsize=14)
ax.set_title('Digital Signature Execution Time on ESP32 @ 240 MHz (Log Scale)', pad=15, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(operations, fontweight='bold')
ax.set_yscale('log')
ax.set_ylim(0.5, 35000)
ax.legend(frameon=True, loc='upper left')
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.grid(axis='x', linestyle='--', alpha=0.3)

for rect in rects1:
    h = rect.get_height()
    ax.annotate(f'{h:.2f} ms', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 4),
                textcoords="offset points", ha='center', va='bottom', fontsize=9.5, fontweight='bold')

for rect in rects2:
    h = rect.get_height()
    ax.annotate(f'{h:.2f} ms', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 4),
                textcoords="offset points", ha='center', va='bottom', fontsize=9.5, fontweight='bold')

for rect in rects3:
    h = rect.get_height()
    ax.annotate(f'{h:.2f} ms', xy=(rect.get_x() + rect.get_width() / 2, h), xytext=(0, 4),
                textcoords="offset points", ha='center', va='bottom', fontsize=9.5, fontweight='bold')

plt.tight_layout()
fig.savefig(os.path.join(output_dir, 'fig_timing_comparison.png'))
plt.close(fig)

# =========================================================================
# Graph 2: Wire Overhead per Authentication (Stacked: Public Key + Signature)
# =========================================================================
fig, ax = plt.subplots(figsize=(10, 6), dpi=300)

algos = ['Ed25519', 'ECDSA P-256', 'RSA-3072']
pub_keys = [32, 65, 384]
sigs     = [64, 71, 384]
totals   = [96, 136, 768]

b1 = ax.bar(algos, pub_keys, width=0.45, label='Public Key Wire Size (Bytes)', color='#2b5c8f', edgecolor='black', linewidth=1)
b2 = ax.bar(algos, sigs,     width=0.45, bottom=pub_keys, label='Signature Wire Size (Bytes)', color='#6baed6', edgecolor='black', linewidth=1)

ax.set_ylabel('Size on Wire (Bytes)', fontsize=14)
ax.set_title('Digital Signature Communication Overhead per Handshake (Bytes)', pad=15, fontweight='bold')
ax.set_ylim(0, 950)
ax.legend(frameon=True, loc='upper left')
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.set_xticks(range(len(algos)))
ax.set_xticklabels(algos, fontweight='bold')

# Middle label on bottom bar
for rect, val in zip(b1, pub_keys):
    y_center = val / 2 if val > 40 else val / 2
    color = 'white' if val > 40 else 'black'
    ax.text(rect.get_x() + rect.get_width()/2, y_center, f'{val} B', ha='center', va='center', color=color, fontweight='bold', fontsize=11)

# Middle label on top bar
for rect, bot, val in zip(b2, pub_keys, sigs):
    ax.text(rect.get_x() + rect.get_width()/2, bot + val/2, f'{val} B', ha='center', va='center', color='black', fontweight='bold', fontsize=11)

# Total text above each bar
multipliers = ['(Baseline)', '(1.4x of Ed25519)', '(8.0x of Ed25519)']
for rect, tot, mult in zip(b2, totals, multipliers):
    ax.text(rect.get_x() + rect.get_width()/2, tot + 20, f'Total: {tot} Bytes\n{mult}', ha='center', va='bottom', color='black', fontweight='bold', fontsize=11)

plt.tight_layout()
fig.savefig(os.path.join(output_dir, 'fig_size_overhead.png'))
plt.close(fig)

# =========================================================================
# Graph 3: Dynamic Heap Memory Overhead during Operation (Bytes)
# =========================================================================
fig, ax = plt.subplots(figsize=(10, 6), dpi=300)

heap_values = [108, 300, 2068]
colors = ['#1f77b4', '#ff7f0e', '#d62728']

b_heap = ax.bar(algos, heap_values, width=0.45, color=colors, edgecolor='black', linewidth=1)

ax.set_ylabel('Peak Dynamic Heap Consumed (Bytes)', fontsize=14)
ax.set_title('Peak Dynamic Heap Memory Consumed during Cryptographic Operation', pad=15, fontweight='bold')
ax.set_ylim(0, 2600)
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.set_xticks(range(len(algos)))
ax.set_xticklabels(algos, fontweight='bold')

annotations = [
    '108 Bytes\n(Stack / Minimal Libsodium)',
    '300 Bytes\n(Mbed TLS ECP Context)',
    '2,068 Bytes\n(3072-bit MPI BigNum Context)'
]

for rect, text, val in zip(b_heap, annotations, heap_values):
    y_pos = val + 40
    ax.text(rect.get_x() + rect.get_width()/2, y_pos, text, ha='center', va='bottom', color='black', fontweight='bold', fontsize=11)

plt.tight_layout()
fig.savefig(os.path.join(output_dir, 'fig_memory_comparison.png'))
plt.close(fig)

print("Phase A Mutual Authentication graphs successfully generated!")
