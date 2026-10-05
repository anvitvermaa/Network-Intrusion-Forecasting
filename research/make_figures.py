
#!/usr/bin/env python3

"""Paper figures from artifacts/forecast_audit.json.

 

Figure 1: the same forecasters scored two ways on DAPT2020 (every flow vs only real stage changes).

Figure 2: which stage changes actually occur in each sequence source (transition grids).

"""

import json

import os

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

import numpy as np

 

HERE = os.path.dirname(os.path.abspath(__file__))

ROOT = os.path.join(HERE, "..") if os.path.basename(HERE) == "research" else HERE

FIG = os.path.join(ROOT, "paper", "figures")

os.makedirs(FIG, exist_ok=True)

A = json.load(open(os.path.join(ROOT, "artifacts", "forecast_audit.json")))

 

INK, GREY, LIGHT, BLUE = "#1E1E1E", "#9A9A9A", "#E9E9E9", "#23466B"

plt.rcParams.update({

    "font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 9,

    "axes.edgecolor": INK, "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK,

    "axes.spines.top": False, "axes.spines.right": False,

    "savefig.dpi": 300, "savefig.bbox": "tight", "savefig.pad_inches": 0.05,

})

 

 

def save(fig, name):

    for ext in ("png", "pdf"):

        fig.savefig(os.path.join(FIG, f"{name}.{ext}"))

    plt.close(fig)

 

 

# ---------------- Figure 1 ----------------

F = A["dapt2020"]["flows_k1_loo"]

methods = [("persistence", "Persistence"), ("markov1", "Markov, fitted on data"),

           ("project_method_refit", "HMM recipe, refitted"), ("majority_next", "Majority next stage"),

           ("advance_one", "Advance one stage"), ("project_hmm", "Deployed HMM (prior)")]

methods = [(k, n) for k, n in methods if k in F]

labels = [n for _, n in methods]

y = np.arange(len(methods))[::-1]

n_all = F[methods[0][0]]["n_all"]

n_chg = F[methods[0][0]]["n_changes"]

 

fig, axes = plt.subplots(1, 2, figsize=(6.6, 2.7), sharey=True, gridspec_kw={"wspace": 0.16})

panels = [("acc_all", f"(a) Every flow counted ({n_all:,} steps)", GREY),

          ("acc_changes", f"(b) Only real stage changes ({n_chg} steps)", BLUE)]

for ax, (key, title, color) in zip(axes, panels):

    vals = [100 * (F[k][key] or 0.0) for k, _ in methods]

    ax.barh(y, vals, height=0.62, color=color, zorder=2)

    for yi, v, (k, _) in zip(y, vals, methods):

        if 0 < v < 1:

            txt = "<1%"

        elif 99 < v < 100:

            txt = ">99%"

        else:

            txt = f"{v:.0f}%"

        if key == "acc_changes":

            lo, hi = F[k].get("acc_changes_exact95", [None, None])

            if lo is not None:

                txt += f"  [{100 * lo:.0f}–{100 * hi:.0f}]"

        inside = v > 62

        ax.text(v - 2 if inside else v + 2, yi, txt, va="center", ha="right" if inside else "left",

                color="white" if inside else INK, fontsize=8, zorder=3)

    ax.set_xlim(0, 100)

    ax.set_xticks([0, 25, 50, 75, 100])

    ax.set_xticklabels(["0", "25", "50", "75", "100"])

    ax.grid(axis="x", color=LIGHT, lw=0.8, zorder=0)

    ax.set_title(title, fontsize=9, loc="left", pad=6)

    ax.tick_params(axis="y", length=0)

    ax.spines["left"].set_visible(False)

axes[0].set_yticks(y)

axes[0].set_yticklabels(labels)

fig.text(0.58, -0.05, "Next-stage accuracy (%) on DAPT2020, leave-one-attacker-out", ha="center", fontsize=9)

save(fig, "fig1_counting_flips_ranking")

 

# ---------------- Figure 2 ----------------

LAB = ["Recon", "Compromise", "Lateral", "Exfil./Impact"]

src = [("(a) Synthetic episodes\n(old evaluation)", A["synthetic"]["diagnostics"]),

       ("(b) CIC-IDS2017\nweekly schedule", A["cic_schedule"]["diagnostics_runs"])]

if "dapt2020" in A:

    src.append(("(c) DAPT2020\nreal attackers", A["dapt2020"]["diagnostics_runs"]))

 

fig, axes = plt.subplots(1, len(src), figsize=(2.25 * len(src), 2.55), gridspec_kw={"wspace": 0.12})

for ax, (title, dg) in zip(np.atleast_1d(axes), src):

    C = np.array(dg["transition_counts"])[1:, 1:].astype(float)  # drop NONE row/col

    np.fill_diagonal(C, 0)  # stage changes only

    total = C.sum()

    share = C / total if total else C

    cmap = plt.get_cmap("Blues")

    vmax = share.max() if share.max() > 0 else 1.0

    for i in range(4):

        for j in range(4):

            if i == j:

                face = LIGHT

            elif C[i, j] > 0:

                face = cmap(0.25 + 0.7 * share[i, j] / vmax)

            else:

                face = "white"

            ax.add_patch(plt.Rectangle((j - 0.5, i - 0.5), 1, 1, facecolor=face, edgecolor="white", lw=1.5))

            if i != j and C[i, j] > 0:

                dark = share[i, j] / vmax > 0.45

                ax.text(j, i, f"{int(C[i, j])}", ha="center", va="center", fontsize=8.5,

                        color="white" if dark else INK)

    ax.add_patch(plt.Rectangle((-0.5, -0.5), 4, 4, fill=False, edgecolor="#C8C8C8", lw=0.8, zorder=4))

    ax.set_xlim(-0.55, 3.55)

    ax.set_ylim(3.55, -0.55)

    ax.set_aspect("equal")

    for i in range(3):  # outline the 'advance one stage' cells

        ax.add_patch(plt.Rectangle((i + 0.5, i - 0.5), 1, 1, fill=False, edgecolor=INK, lw=1.2, clip_on=False, zorder=5))

    ax.set_xticks(range(4))

    ax.set_xticklabels(LAB, rotation=40, ha="right", fontsize=7.5)

    ax.set_yticks(range(4))

    ax.set_yticklabels(LAB if ax is np.atleast_1d(axes)[0] else [], fontsize=7.5)

    ax.tick_params(length=0, pad=2)

    for s in ax.spines.values():

        s.set_visible(False)

    ax.set_title(f"{title}\n{int(total)} stage changes", fontsize=8.5, pad=5)

np.atleast_1d(axes)[0].set_ylabel("From stage", fontsize=8.5)

fig.text(0.5, -0.11, "To stage", ha="center", fontsize=8.5)

fig.text(0.5, -0.19, "Outlined cells: the next stage in kill-chain order (what \u201cadvance one stage\u201d predicts).   Numbers: how often that stage change occurs.", ha="center", fontsize=7.5, color="#555555")

save(fig, "fig2_transitions")

 

print("[saved]", os.path.join(FIG, "fig1_counting_flips_ranking.png"), os.path.join(FIG, "fig2_transitions.png"))

