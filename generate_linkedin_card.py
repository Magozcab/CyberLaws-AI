#!/usr/bin/env python3
"""
generate_linkedin_card.py
-------------------------
Generates a high-resolution (16:9, DPI=300) dark-themed cybersecurity
infographic for a LinkedIn post about the "CyberLaws-AI" project.

Output: cyberlaws_infographic.png
"""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")  # headless backend
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
import matplotlib.font_manager as fm

# ──────────────────────────────────────────────────────────────────────
# 1. DESIGN TOKENS
# ──────────────────────────────────────────────────────────────────────
BG          = "#0d1117"   # main background (GitHub dark)
PANEL_BG    = "#161b22"   # slightly lighter panel surface
PANEL_EDGE  = "#30363d"   # panel border
CYAN        = "#00f2fe"   # neon cyan accent
BLUE        = "#4facfe"   # electric blue
RED         = "#ff4b5c"   # alert red
GREEN       = "#00e676"   # security green
TEXT        = "#e6edf3"   # primary text (near-white)
MUTED       = "#8b949e"   # secondary text (muted gray)
AMBER       = "#ffb454"   # warning amber (for 14%)

# Sans-serif font stack (DejaVu Sans ships with matplotlib)
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "axes.unicode_minus": False,
})

# ──────────────────────────────────────────────────────────────────────
# 2. FIGURE  (19.2 x 10.8 in  @ 300 DPI  ->  5760 x 3240 px, 16:9)
# ──────────────────────────────────────────────────────────────────────
FIG_W, FIG_H = 19.2, 10.8
fig = plt.figure(figsize=(FIG_W, FIG_H), facecolor=BG, dpi=300)
ax_bg = fig.add_axes([0, 0, 1, 1])
ax_bg.set_xlim(0, 1)
ax_bg.set_ylim(0, 1)
ax_bg.set_facecolor(BG)
ax_bg.axis("off")

# Subtle top accent bar
ax_bg.add_patch(Rectangle((0, 0.985), 1, 0.015, facecolor=CYAN,
                          edgecolor="none", alpha=0.9, zorder=1))
# Faint vertical divider lines between the three panels
for x_div in (0.345, 0.655):
    ax_bg.plot([x_div, x_div], [0.16, 0.86], color=PANEL_EDGE,
               lw=1.2, alpha=0.6, zorder=1)

# ──────────────────────────────────────────────────────────────────────
# 3. HEADER
# ──────────────────────────────────────────────────────────────────────
ax_bg.text(0.5, 0.955, "CyberLaws-AI: Formal Verification for Autonomous AI Agents",
           ha="center", va="center", fontsize=30, fontweight="bold",
           color=TEXT, zorder=5)
ax_bg.text(0.5, 0.918, "Dual-Layer Safety:  Probabilistic Alignment  +  Deterministic Z3 Solver",
           ha="center", va="center", fontsize=17, fontweight="normal",
           color=CYAN, zorder=5, alpha=0.92)

# Small tag pills in header corners
def _pill(cx, cy, label, color, w=0.085, h=0.022):
    ax_bg.add_patch(FancyBboxPatch(
        (cx - w / 2, cy - h / 2), w, h,
        boxstyle="round,pad=0.004,rounding_size=0.011",
        facecolor=color, edgecolor="none", alpha=0.18, zorder=4))
    ax_bg.text(cx, cy, label, ha="center", va="center",
               fontsize=10.5, fontweight="bold", color=color, zorder=5)

_pill(0.10, 0.935, "Z3 · SMT",     GREEN)
_pill(0.90, 0.935, "85 / 85 PASS", CYAN)

# ──────────────────────────────────────────────────────────────────────
# 4. PANEL HELPERS
# ──────────────────────────────────────────────────────────────────────
def panel_frame(left, bottom, width, height, title, accent=CYAN):
    """Draw a rounded panel background + coloured title bar."""
    ax_bg.add_patch(FancyBboxPatch(
        (left, bottom), width, height,
        boxstyle="round,pad=0.006,rounding_size=0.012",
        facecolor=PANEL_BG, edgecolor=PANEL_EDGE, lw=1.4, zorder=2))
    # accent strip on the left edge
    ax_bg.add_patch(Rectangle(
        (left + 0.006, bottom + 0.006), 0.004, height - 0.012,
        facecolor=accent, edgecolor="none", alpha=0.85, zorder=3))
    # title
    ax_bg.text(left + 0.022, bottom + height - 0.030, title,
               ha="left", va="center", fontsize=15, fontweight="bold",
               color=accent, zorder=5)

# ──────────────────────────────────────────────────────────────────────
# 5. LEFT PANEL  —  Test Battery (85 vectors, horizontal bars)
# ──────────────────────────────────────────────────────────────────────
L_L, L_B, L_W, L_H = 0.015, 0.155, 0.318, 0.685
panel_frame(L_L, L_B, L_W, L_H,
            "PANEL I  ·  Test Battery — 85 Attack Vectors", accent=GREEN)

categories = [
    ("Red-Team & Fuzzing",          50, 50),
    ("Guardrail Base Tests",        20, 20),
    ("Obfuscation & Evasion",       10, 10),
    ("Kernel Isolation / Escape",    5,  5),
]

ax_bar = fig.add_axes([0.055, 0.225, 0.255, 0.50])
ax_bar.set_facecolor(PANEL_BG)
ax_bar.set_xlim(0, 100)
ax_bar.set_ylim(-0.6, len(categories) - 0.4)
ax_bar.invert_yaxis()
ax_bar.tick_params(colors=MUTED, labelsize=10.5, length=0)
ax_bar.set_xticks([0, 25, 50, 75, 100])
ax_bar.set_xticklabels(["0", "25", "50", "75", "100%"])
ax_bar.set_yticks([])
for spine in ax_bar.spines.values():
    spine.set_visible(False)
ax_bar.spines["bottom"].set_visible(True)
ax_bar.spines["bottom"].set_color(PANEL_EDGE)

bar_h = 0.55
for i, (name, blocked, total) in enumerate(categories):
    # background track (full width, muted)
    ax_bar.barh(i, 100, height=bar_h, color=PANEL_EDGE, alpha=0.35, zorder=2)
    # blocked portion (green)
    pct = blocked / total * 100
    ax_bar.barh(i, pct, height=bar_h, color=GREEN, alpha=0.92, zorder=3,
                edgecolor=GREEN, linewidth=0)
    # category label (left of bar)
    ax_bar.text(-3, i, name, ha="right", va="center",
                fontsize=11.5, fontweight="bold", color=TEXT, zorder=4)
    # count label (inside bar, right side)
    ax_bar.text(pct - 3, i, f"{blocked}/{total}", ha="right", va="center",
                fontsize=11, fontweight="bold", color=BG, zorder=5)
    # 100% BLOCKED tag (right of bar)
    ax_bar.text(104, i, "100% BLOCKED", ha="left", va="center",
                fontsize=9.5, fontweight="bold", color=GREEN, zorder=5)

ax_bar.set_xlabel("Blocked Rate", fontsize=10.5, color=MUTED, labelpad=8)

# Summary stat under the chart
ax_bg.text(0.055, 0.185, "85 / 85 vectors blocked",
           ha="left", va="center", fontsize=13, fontweight="bold", color=GREEN,
           zorder=5)
ax_bg.text(0.055, 0.165, "0 bypasses across all attack surfaces",
           ha="left", va="center", fontsize=10.5, color=MUTED, zorder=5)

# ──────────────────────────────────────────────────────────────────────
# 6. CENTER PANEL  —  Critical Finding (donut comparison)
# ──────────────────────────────────────────────────────────────────────
C_L, C_B, C_W, C_H = 0.355, 0.155, 0.295, 0.685
panel_frame(C_L, C_B, C_W, C_H,
            "PANEL II  ·  Critical Finding — LLM vs Z3 Guard", accent=RED)

def draw_donut(cx, cy, r, value_pct, color, label_top, label_center, subtitle):
    """Draw a donut ring with a coloured arc for *value_pct*."""
    theta = np.linspace(0, 2 * np.pi, 360)
    # background ring
    ax_bg.plot(cx + r * np.cos(theta), cy + r * np.sin(theta),
               color=PANEL_EDGE, lw=16, solid_capstyle="round", zorder=3)
    # value arc
    if value_pct > 0:
        end = 2 * np.pi * (value_pct / 100.0)
        a = np.linspace(np.pi / 2, np.pi / 2 - end, 120)
        ax_bg.plot(cx + r * np.cos(a), cy + r * np.sin(a),
                   color=color, lw=16, solid_capstyle="round", zorder=4)
    # center text
    ax_bg.text(cx, cy + 0.012, label_center, ha="center", va="center",
               fontsize=26, fontweight="bold", color=color, zorder=5)
    ax_bg.text(cx, cy - 0.020, subtitle, ha="center", va="center",
               fontsize=9.5, color=MUTED, zorder=5)
    # top label
    ax_bg.text(cx, cy + r + 0.040, label_top, ha="center", va="center",
               fontsize=11.5, fontweight="bold", color=TEXT, zorder=5)

# Donut 1 — LLM vulnerability (14%)
draw_donut(cx=0.425, cy=0.46, r=0.052,
           value_pct=14, color=RED,
           label_top="LLM Prompt\nManipulated",
           label_center="14%",
           subtitle="probabilistic layer")

# Donut 2 — Z3 resilience (0% bypass = 100% blocked)
draw_donut(cx=0.580, cy=0.46, r=0.052,
           value_pct=0, color=GREEN,
           label_top="Z3 Execution\nBypassed",
           label_center="0%",
           subtitle="deterministic guard")

# VS divider
ax_bg.text(0.5025, 0.46, "VS", ha="center", va="center",
           fontsize=13, fontweight="bold", color=MUTED, alpha=0.7, zorder=5)

# Highlighted comparison banner
banner_y = 0.255
ax_bg.add_patch(FancyBboxPatch(
    (0.370, banner_y - 0.022), 0.265, 0.044,
    boxstyle="round,pad=0.005,rounding_size=0.012",
    facecolor="#1c2128", edgecolor=RED, lw=1.6, zorder=4))
ax_bg.text(0.5025, banner_y + 0.004,
           "LLM Manipulated: 14%   |   Z3 Bypassed: 0%",
           ha="center", va="center", fontsize=12.5, fontweight="bold",
           color=TEXT, zorder=5)
ax_bg.text(0.5025, banner_y - 0.013,
           "Deterministic solver eliminates the 14% LLM attack surface",
           ha="center", va="center", fontsize=9.5, color=MUTED, zorder=5)

# ──────────────────────────────────────────────────────────────────────
# 7. RIGHT PANEL  —  Architecture Flow (vertical boxes)
# ──────────────────────────────────────────────────────────────────────
R_L, R_B, R_W, R_H = 0.665, 0.155, 0.320, 0.685
panel_frame(R_L, R_B, R_W, R_H,
            "PANEL III  ·  Architecture Flow", accent=BLUE)

flow_steps = [
    ("Operator Prompt",                       "user input",                  BLUE),
    ("Qwen2.5-Coder + LoRA v2",               "Probabilistic Layer",         CYAN),
    ("AST De-obfuscator + Z3 Solver",         "Deterministic Layer  →  UNSAT / SAT", GREEN),
    ("Docker Sandbox + Seccomp Filter",       "Containment  ·  Kernel Isolation",   BLUE),
]

box_w, box_h = 0.275, 0.085
box_x = R_L + (R_W - box_w) / 2          # horizontally centred in panel
top_y = R_B + R_H - 0.075                # first box top
gap = (top_y - (R_B + 0.06) - box_h) / (len(flow_steps) - 1)

for i, (title, subtitle, color) in enumerate(flow_steps):
    by = top_y - i * (box_h + gap)
    # box
    ax_bg.add_patch(FancyBboxPatch(
        (box_x, by), box_w, box_h,
        boxstyle="round,pad=0.006,rounding_size=0.014",
        facecolor="#1c2128", edgecolor=color, lw=2.0, zorder=4))
    # left colour tab
    ax_bg.add_patch(Rectangle(
        (box_x + 0.004, by + 0.006), 0.005, box_h - 0.012,
        facecolor=color, edgecolor="none", alpha=0.9, zorder=5))
    # step number badge
    ax_bg.add_patch(plt.Circle(
        (box_x + 0.022, by + box_h - 0.018), 0.011,
        facecolor=color, edgecolor="none", alpha=0.25, zorder=5))
    ax_bg.text(box_x + 0.022, by + box_h - 0.018, str(i + 1),
               ha="center", va="center", fontsize=9, fontweight="bold",
               color=color, zorder=6)
    # title text
    ax_bg.text(box_x + 0.042, by + box_h - 0.022, title,
               ha="left", va="center", fontsize=12.5, fontweight="bold",
               color=TEXT, zorder=6)
    # subtitle text
    ax_bg.text(box_x + 0.042, by + 0.020, subtitle,
               ha="left", va="center", fontsize=9.5, color=color,
               zorder=6, alpha=0.92)

    # downward arrow to next box
    if i < len(flow_steps) - 1:
        arrow = FancyArrowPatch(
            (box_x + box_w / 2, by - 0.003),
            (box_x + box_w / 2, by - gap + 0.003),
            arrowstyle="-|>", mutation_scale=22,
            color=MUTED, lw=2.0, alpha=0.7, zorder=3)
        ax_bg.add_patch(arrow)

# ──────────────────────────────────────────────────────────────────────
# 8. FOOTER
# ──────────────────────────────────────────────────────────────────────
ax_bg.add_patch(Rectangle((0, 0), 1, 0.055, facecolor="#010409",
                          edgecolor="none", zorder=2))
ax_bg.add_patch(Rectangle((0, 0.055), 1, 0.002, facecolor=CYAN,
                          edgecolor="none", alpha=0.5, zorder=2))

ax_bg.text(0.5, 0.028,
           "Repository:  github.com/Magozcab/CyberLaws-AI   ·   "
           "85 / 85 Test Vectors Passed  (100%)",
           ha="center", va="center", fontsize=13, fontweight="bold",
           color=TEXT, zorder=5)
ax_bg.text(0.5, 0.010,
           "Dual-Layer Safety  ·  Probabilistic Alignment + Deterministic Z3 Solver  ·  "
           "Docker + Seccomp Containment",
           ha="center", va="center", fontsize=9.5, color=MUTED, zorder=5)

# ──────────────────────────────────────────────────────────────────────
# 9. SAVE
# ──────────────────────────────────────────────────────────────────────
out_dir = os.path.expanduser("~/cyberlaws")
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, "cyberlaws_infographic.png")

fig.savefig(out_path, dpi=300, facecolor=BG, edgecolor="none",
            bbox_inches="tight", pad_inches=0.05)
plt.close(fig)

size_kb = os.path.getsize(out_path) / 1024
print(f"[OK] Infographic saved -> {out_path}")
print(f"     Size: {size_kb:,.1f} KB")
print(f"     Resolution: {int(FIG_W*300)} x {int(FIG_H*300)} px @ 300 DPI")
