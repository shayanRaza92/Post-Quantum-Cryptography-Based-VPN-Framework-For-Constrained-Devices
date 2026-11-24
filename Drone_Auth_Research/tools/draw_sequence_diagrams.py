#!/usr/bin/env python3
"""Sequence diagrams for Step 4 (drone authentication), with numbers from Steps 1-3.

    python3 tools/draw_sequence_diagrams.py

Writes to results/e4/figures/ (PDF for the paper, PNG for viewing):
  fig8_seq_authentication   the challenge-response authentication tested in Step 3
  fig9_seq_packets          one real authentication as packets: Ed25519 vs ML-DSA-44
                            (MAVLink-sized frames; times from the Step 3 Wireshark recording)
  fig10_seq_mission         where authentication fits in a drone mission

The numbers on the arrows are measured values: signing times are the Step 1 medians
(1,000 runs), packet sizes and times come from the Step 3 run link_20261124_210648.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "e4" / "figures"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE, SOFT = "#2a78d6", "#eb6834", "#f3f2ee"
BAND = "#faf9f6"                                # phase band colour
BG = dict(fc=BAND, ec="none", pad=0.6)          # text background, hides the lifelines behind it

plt.rcParams.update({"font.size": 8, "pdf.fonttype": 42, "savefig.dpi": 300, "savefig.bbox": "tight"})


class Diagram:
    """Minimal sequence-diagram drawer: lanes (lifelines), arrows, notes, phase bands."""

    def __init__(self, width, height, lanes, top=1.0):
        self.fig, self.ax = plt.subplots(figsize=(width, height))
        self.ax.set_xlim(0, width)
        self.ax.set_ylim(-height, 0)
        self.ax.axis("off")
        self.lanes = lanes                      # name -> x
        self.height = height
        for name, x in lanes.items():
            bw = max(1.7, 0.085 * len(name) + 0.3)     # box wide enough for the name
            self.ax.add_patch(FancyBboxPatch((x - bw / 2, -top + 0.12), bw, 0.5, boxstyle="round,pad=0.02",
                                             fc=SOFT, ec=INK2, lw=0.8))
            self.ax.text(x, -top + 0.37, name, ha="center", va="center", fontsize=8, weight="bold", color=INK)
            self.ax.plot([x, x], [-top + 0.12, -height + 0.15], color=INK2, lw=0.7, ls=(0, (4, 3)), zorder=0)

    def phase(self, y0, y1, label):
        xs = list(self.lanes.values())
        self.ax.add_patch(plt.Rectangle((0.05, y1), self.ax.get_xlim()[1] - 0.1, y0 - y1, fc=BAND,
                                        ec=GRID, lw=0.8, zorder=-1))
        self.ax.text(0.12, y0 - 0.08, label, ha="left", va="top", fontsize=7, style="italic", color=INK2, bbox=BG)

    def arrow(self, src, dst, y, title, detail=None, color=INK, dashed=False, lw=1.1, title_size=7.5):
        x0, x1 = self.lanes[src], self.lanes[dst]
        self.ax.annotate("", xy=(x1, y), xytext=(x0, y),
                         arrowprops=dict(arrowstyle="-|>", color=color, lw=lw, shrinkA=0, shrinkB=0,
                                         ls=(0, (4, 2)) if dashed else "-"))
        xm = (x0 + x1) / 2
        self.ax.text(xm, y + 0.05, title, ha="center", va="bottom", fontsize=title_size, weight="bold", color=INK,
                     bbox=BG)
        if detail:
            self.ax.text(xm, y - 0.06, detail, ha="center", va="top", fontsize=6.5, color=INK2, linespacing=1.3,
                         bbox=BG)

    def note(self, lane, y, text, width=2.6, side="center", color=SOFT, edge=INK2):
        x = self.lanes[lane]
        lines = text.count("\n") + 1
        h = 0.16 * lines + 0.12
        x0 = {"center": x - width / 2, "right": x + 0.1, "left": x - width - 0.1}[side]
        self.ax.add_patch(FancyBboxPatch((x0, y - h), width, h, boxstyle="round,pad=0.02", fc=color, ec=edge, lw=0.7))
        self.ax.text(x0 + 0.08, y - 0.07, text, ha="left", va="top", fontsize=6.5, color=INK, linespacing=1.3)
        return y - h

    def save(self, stem):
        OUT.mkdir(parents=True, exist_ok=True)
        self.fig.savefig(OUT / f"{stem}.pdf")
        self.fig.savefig(OUT / f"{stem}.png")
        plt.close(self.fig)


def fig8():
    d = Diagram(7.0, 5.45, {"Drone (ESP32)": 1.6, "Ground station": 5.4})
    D, G = "Drone (ESP32)", "Ground station"
    d.phase(-1.0, -1.88, "Before flight: registration (once)")
    d.arrow(D, G, -1.47, "Public key of the drone", "Ed25519 32 B · ECDSA 65 B · RSA 384 B · ML-DSA-44 1,312 B · "
            "ML-DSA-87 2,592 B\n(Step 3: sent on request; in practice stored when the drone is registered)",
            dashed=True, color=INK2)
    d.phase(-1.98, -5.08, "Authentication (measured in Step 3)")
    d.arrow(G, D, -2.45, "1  CHALLENGE", "fresh 32-byte random number (72 B on the network)", color=BLUE)
    d.note(D, -2.82, "2  Build  M = header | challenge | drone ID | clock | data\n"
                     "    Sign:  sig = Sign(secret key, M)\n"
                     "    Ed25519 9.4 ms · ML-DSA-44 55 ms (up to 486 ms) · RSA 373 ms",
           width=4.15, side="right")
    d.arrow(D, G, -3.72, "3  AUTH = M | sig", "64 B of data:  Ed25519 168 B in 1 packet  ·  ML-DSA-44 2,544 B in "
            "2 Wi-Fi packets\n(10 frames if each frame carries at most 255 B, like MAVLink)", color=ORANGE)
    d.note(G, -4.18, "4  Check: challenge is the one sent\n    Verify(public key, M, sig): under 1.2 ms",
           width=2.75, side="left")
    d.arrow(G, D, -4.85, "5  RESULT", "accepted / rejected (41 B)", color=BLUE)
    d.ax.text(3.5, -5.3, "Challenge to verified signature (Wi-Fi, 64 B of data, median):  "
              "Ed25519 19.5 ms  ·  ML-DSA-44 90.7 ms  ·  RSA-3072 440 ms",
              ha="center", va="center", fontsize=7, color=INK, bbox=dict(fc="white", ec="none", pad=0.6))
    d.save("fig8_seq_authentication")


def fig9():
    """Two real exchanges side by side (MAVLink-sized frames, 64 B of data), not to scale."""
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.3))
    cases = [("Ed25519", [("0.00 ms", "CHALLENGE", "G"), ("18.91 ms", "AUTH  frame 1/1  (140 B)", "D"),
                          ("19.98 ms", "RESULT", "G")], "1 frame, 152 B on a radio:\n21 ms at 57.6 kbit/s"),
             ("ML-DSA-44", [("0.00 ms", "CHALLENGE", "G"), ("44.51 ms", "AUTH  frame 1/10  (255 B)", "D"),
                            ("", "frame 2/10", "D"), ("", "frame 3/10", "D"), ("", "...", "dots"),
                            ("", "frame 9/10", "D"), ("44.87 ms", "AUTH  frame 10/10  (201 B)", "D"),
                            ("45.71 ms", "RESULT", "G")], "10 frames, 2,616 B on a radio:\n363 ms at 57.6 kbit/s")]
    for ax, (alg, events, footer) in zip(axes, cases):
        ax.set_xlim(0, 3.6)
        ax.set_ylim(-3.35, 0.4)
        ax.axis("off")
        xd, xg = 0.85, 2.85
        for x, name in ((xd, "Drone"), (xg, "Ground station")):
            ax.add_patch(FancyBboxPatch((x - 0.68, -0.42), 1.36, 0.34, boxstyle="round,pad=0.02", fc=SOFT, ec=INK2, lw=0.8))
            ax.text(x, -0.25, name, ha="center", va="center", fontsize=7.5, weight="bold")
            ax.plot([x, x], [-0.42, -2.85], color=INK2, lw=0.7, ls=(0, (4, 3)), zorder=0)
        ax.text((xd + xg) / 2, 0.3, alg, ha="center", va="top", fontsize=9, weight="bold", color=INK)
        y = -0.72
        step = 2.0 / max(len(events) - 1, 1)
        for t, label, who in events:
            if who == "dots":
                ax.text((xd + xg) / 2, y + 0.02, "⋮", ha="center", va="center", fontsize=9, color=INK2)
            else:
                x0, x1, col = (xg, xd, BLUE) if who == "G" else (xd, xg, ORANGE)
                ax.annotate("", xy=(x1, y), xytext=(x0, y),
                            arrowprops=dict(arrowstyle="-|>", color=col, lw=1.0, shrinkA=0, shrinkB=0))
                ax.text((xd + xg) / 2, y + 0.03, label, ha="center", va="bottom", fontsize=6.3, color=INK)
                if t:
                    ax.text(0.12, y, t, ha="left", va="center", fontsize=6, color=INK2)
            y -= step
        ax.text((xd + xg) / 2, -3.15, footer, ha="center", va="center", fontsize=6.8, color=INK, linespacing=1.3)
    fig.text(0.5, 0.005, "Times: from the Step 3 Wireshark recording (challenge leaving the ground station = 0). "
             "Radio times: calculated from the measured sizes.", ha="center", va="bottom", fontsize=6.3, color=INK2)
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / "fig9_seq_packets.pdf")
    fig.savefig(OUT / "fig9_seq_packets.png")
    plt.close(fig)


def fig10():
    d = Diagram(7.0, 5.85, {"Drone (ESP32 + MPU6050)": 1.7, "Ground station": 5.3})
    D, G = "Drone (ESP32 + MPU6050)", "Ground station"
    d.phase(-1.0, -1.92, "A  Registration, on the ground (once)")
    d.arrow(D, G, -1.42, "Drone public key", None, dashed=True, color=INK2)
    d.arrow(G, D, -1.76, "Ground-station public key", None, dashed=True, color=INK2)
    d.phase(-2.02, -2.97, "B  Before take-off: the drone proves who it is (Figure 8, measured in Step 3)")
    d.arrow(G, D, -2.47, "CHALLENGE", None, color=BLUE)
    d.arrow(D, G, -2.81, "AUTH = data | signature  \u2192  accepted", None, color=ORANGE)
    d.phase(-3.07, -3.9, "C  In flight: commands are signed by the ground station")
    d.arrow(G, D, -3.55, "Signed command (take off, waypoint, land ...)",
            "the drone verifies before acting:  Ed25519 19.8 ms · ML-DSA-44 13.4 ms · RSA 1.8 ms (ESP32, Step 1)",
            color=BLUE)
    d.phase(-4.0, -5.22, "D  In flight: sensor data (MPU6050) is signed by the drone (Step 5)")
    d.arrow(D, G, -4.47, "Signed telemetry (accelerometer, gyroscope)",
            "every message, or every N samples, or authenticate once and then use a fast session key",
            color=ORANGE)
    d.note(D, -4.72, "Step 5 measures: the highest signed rate,\nand whether signing disturbs the sensor sampling",
           width=3.1, side="right", color="#fff7ea", edge=ORANGE)
    d.phase(-5.32, -5.75, "E  Repeat B every few minutes, or after a reconnection")
    d.save("fig10_seq_mission")


if __name__ == "__main__":
    fig8()
    fig9()
    fig10()
    print(f"Diagrams in {OUT}")
