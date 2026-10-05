


#!/usr/bin/env python3

"""Build the paper's tables (LaTeX + CSV), figures (PNG + PDF) and a numbers summary from artifacts/forecast_audit.json."""

import json

import os

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

import numpy as np

import pandas as pd

 

HERE = os.path.dirname(os.path.abspath(__file__))

ROOT = os.path.join(HERE, "..")

OUT = os.path.join(ROOT, "paper")

TAB = os.path.join(OUT, "tables")

FIG = os.path.join(OUT, "figures")

os.makedirs(TAB, exist_ok=True)

os.makedirs(FIG, exist_ok=True)

 

A = json.load(open(os.path.join(ROOT, "artifacts", "forecast_audit.json")))

 

NAMES = {"persistence": "Persistence (next = current)", "advance_one": "Advance one stage",

         "majority_next": "Majority next stage", "markov1": "First-order Markov (fitted)",

         "project_hmm": "Deployed HMM (prior-based)", "project_method_refit": "HMM recipe refitted on data"}

SHORT = {"persistence": "Persistence", "advance_one": "Advance\none stage", "majority_next": "Majority\nnext",

         "markov1": "Markov\n(fitted)", "project_hmm": "Deployed\nHMM", "project_method_refit": "HMM\nrefitted"}

ORDER = ["persistence", "advance_one", "majority_next", "markov1", "project_hmm", "project_method_refit"]

STAGE_SHORT = {"NONE": "None", "RECON": "Recon", "INITIAL_COMPROMISE": "Compromise",

               "LATERAL_MOVEMENT": "Lateral", "EXFILTRATION": "Exfil/Impact"}

 

plt.rcParams.update({"font.family": "serif", "font.size": 10, "axes.spines.top": False,

                     "axes.spines.right": False, "savefig.dpi": 300, "savefig.bbox": "tight"})

GREY, BLUE, RED = "#8C8C8C", "#23466B", "#A5243B"

 

 

def pct(x, d=1):

    return "--" if x is None else f"{100 * x:.{d}f}"

 

 

def ci(pair):

    if not pair or pair[0] is None:

        return ""

    return f"[{100 * pair[0]:.0f}, {100 * pair[1]:.0f}]"

 

 

def latex(df, path, caption, label, colfmt):

    body = df.to_latex(index=False, escape=False, column_format=colfmt)

    with open(path, "w") as f:

        f.write("\\begin{table}[t]\n\\centering\n\\small\n" + body + f"\\caption{{{caption}}}\n\\label{{{label}}}\n\\end{{table}}\n")

 

 

def save(fig, name):

    fig.savefig(os.path.join(FIG, name + ".png"))

    fig.savefig(os.path.join(FIG, name + ".pdf"))

    plt.close(fig)

 

 

# ---------- Table 1: forecastability diagnostics ----------

rows = []

def drow(label, dg):

    rows.append({"Sequences": label, "Episodes": dg["n_episodes"], "Steps": f"{dg['n_pairs']:,}",

                 "Stage changes": f"{dg['n_stage_changes']:,} ({pct(dg['share_changes'])}\\%)",

                 "Distinct trans.": dg["distinct_transitions"],

                 "$H(S_{t+1}\\mid S_t)$ (bits)": f"{dg['cond_entropy_bits']:.3f}",

                 "Ceiling (\\%)": pct(dg["ceiling_first_order"])})

drow("Synthetic (prior evaluation)", A["synthetic"]["diagnostics"])

drow("CIC-IDS2017 schedule, events", A["cic_schedule"]["diagnostics_events"])

drow("CIC-IDS2017 schedule, changes only", A["cic_schedule"]["diagnostics_runs"])

has_dapt = "dapt2020" in A

if has_dapt:

    drow("DAPT2020, per flow", A["dapt2020"]["diagnostics_flows"])

    drow("DAPT2020, changes only", A["dapt2020"]["diagnostics_runs"])

t1 = pd.DataFrame(rows)

t1.to_csv(os.path.join(TAB, "table1_forecastability.csv"), index=False)

latex(t1, os.path.join(TAB, "table1_forecastability.tex"),

      "Forecastability of each sequence source. Ceiling is the best accuracy any rule that sees only the current stage could reach on that data (in-sample). Distinct transitions count stage changes $a\\to b$ with $a\\neq b$.",

      "tab:forecastability", "lrrrrrr")

 

# ---------- Table 2: DAPT2020 results ----------

if has_dapt:

    D = A["dapt2020"]

    rows = []

    for m in ORDER:

        f, r1 = D["flows_k1_loo"].get(m), D["runs_k"].get("1", {}).get(m)

        r2 = D["runs_k"].get("2", {}).get(m)

        rows.append({"Method": NAMES[m],

                     "Per flow: all steps": pct(f["acc_all"]) if f else "--",

                     "Per flow: at changes": (pct(f["acc_changes"]) + " " + ci(f.get("acc_changes_exact95"))) if f else "--",

                     "Changes only, $k{=}1$": (pct(r1["acc_changes"]) + " " + ci(r1.get("acc_changes_exact95"))) if r1 else "--",

                     "Changes only, $k{=}2$": (pct(r2["acc_all"]) + " " + ci(r2.get("acc_all_exact95"))) if r2 else "--"})

    t2 = pd.DataFrame(rows)

    t2.to_csv(os.path.join(TAB, "table2_dapt2020.csv"), index=False)

    n_f = D["flows_k1_loo"]["persistence"]["n_all"]

    n_c = D["flows_k1_loo"]["persistence"]["n_changes"]

    latex(t2, os.path.join(TAB, "table2_dapt2020.tex"),

          f"Next-stage accuracy (\\%) on DAPT2020 real attacker sequences, leave-one-attacker-out, with exact 95\\% Clopper--Pearson intervals. Per-flow evaluation has {n_f:,} steps but only {n_c} stage changes.",

          "tab:dapt", "lrrrr")

 

# ---------- Table 3: synthetic vs CIC ----------

rows = []

S1 = A["synthetic"]["k"]["1"]

C1 = A["cic_schedule"]["k1_runs_fixed_rules"]

for m in ["persistence", "advance_one", "project_hmm"]:

    rows.append({"Method": NAMES[m],

                 "Synthetic: all steps": pct(S1[m]["acc_all"]),

                 "Synthetic: at changes": pct(S1[m]["acc_changes"]) + " " + ci(S1[m].get("acc_changes_exact95")),

                 "CIC-IDS2017 schedule: at changes": pct(C1[m]["acc_changes"]) + " " + ci(C1[m].get("acc_changes_exact95"))})

t3 = pd.DataFrame(rows)

t3.to_csv(os.path.join(TAB, "table3_synthetic_cic.csv"), index=False)

latex(t3, os.path.join(TAB, "table3_synthetic_cic.tex"),

      f"The original synthetic evaluation versus the real CIC-IDS2017 attack schedule ({C1['persistence']['n_changes']} stage changes). Exact 95\\% intervals in brackets.",

      "tab:synthetic_cic", "lrrr")

 

# ---------- Figure 1: same models, two ways of counting (DAPT2020 per flow) ----------

if has_dapt:

    F1 = A["dapt2020"]["flows_k1_loo"]

    ms = [m for m in ORDER if m in F1]

    x = np.arange(len(ms))

    w = 0.38

    fig, ax = plt.subplots(figsize=(7.0, 3.0))

    a_all = [100 * (F1[m]["acc_all"] or 0) for m in ms]

    a_chg = [100 * (F1[m]["acc_changes"] or 0) for m in ms]

    ax.bar(x - w / 2, a_all, w, color=GREY, label="Counting every flow")

    ax.bar(x + w / 2, a_chg, w, color=BLUE, label="Counting only stage changes")

    for i, m in enumerate(ms):

        lo, hi = F1[m].get("acc_changes_exact95", [None, None])

        if lo is not None:

            ax.errorbar(x[i] + w / 2, a_chg[i], yerr=[[a_chg[i] - 100 * lo], [100 * hi - a_chg[i]]], fmt="none", ecolor="black", elinewidth=0.8, capsize=2)

    ax.set_xticks(x)

    ax.set_xticklabels([SHORT[m] for m in ms], rotation=0)

    ax.set_ylabel("Next-stage accuracy (%)")

    ax.set_ylim(0, 108)

    ax.legend(frameon=False, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.15))

    save(fig, "fig1_counting_flips_ranking")

 

# ---------- Figure 2: real attacker paths ----------

stages_axis = ["RECON", "INITIAL_COMPROMISE", "LATERAL_MOVEMENT", "EXFILTRATION"]

ypos = {s: i for i, s in enumerate(stages_axis)}

fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.0), sharey=True, gridspec_kw={"width_ratios": [1.15, 1], "wspace": 0.12})

ax = axes[0]

if has_dapt:

    paths = sorted(A["dapt2020"]["attacker_paths"].items(), key=lambda kv: -kv[1]["flows"])

    for j, (ip, p) in enumerate(paths):

        ys = [ypos[s] for s in p["path"] if s in ypos]

        xs = np.arange(len(ys))

        off = (j - len(paths) / 2) * 0.03

        ax.plot(xs, np.array(ys) + off, "-o", color=BLUE, alpha=0.65, ms=3.5, lw=1)

    ax.set_title(f"DAPT2020: {len(paths)} attacker sources", fontsize=10)

ax.set_yticks(range(len(stages_axis)))

ax.set_yticklabels([STAGE_SHORT[s] for s in stages_axis])

ax.set_xlabel("Order of stage within attacker path")

ax.set_xticks(range(4))

ax.set_xticklabels(["1st", "2nd", "3rd", "4th"])

ax = axes[1]

cp = [s for s in A["cic_schedule"]["collapsed_path"] if s in ypos]

ax.plot(range(1, len(cp) + 1), [ypos[s] for s in cp], "-o", color=RED, ms=4, lw=1.2)

for i, s in enumerate(cp):

    if s == "RECON":

        ax.annotate("port scan (Friday)", (i + 1, ypos[s]), textcoords="offset points", xytext=(-30, 10), fontsize=8)

ax.tick_params(axis="y", labelleft=False)

ax.set_title("CIC-IDS2017: weekly attack schedule", fontsize=10)

ax.set_xlabel("Position in schedule (repeats collapsed)")

ax.set_xticks(range(1, len(cp) + 1))

save(fig, "fig2_real_attack_paths")

 

# ---------- Figure 3: forecastability map ----------

pts = [("Synthetic", A["synthetic"]["diagnostics"]), ("CIC schedule", A["cic_schedule"]["diagnostics_runs"])]

if has_dapt:

    pts += [("DAPT2020 changes", A["dapt2020"]["diagnostics_runs"]), ("DAPT2020 flows", A["dapt2020"]["diagnostics_flows"])]

fig, ax = plt.subplots(figsize=(4.6, 3.0))

for lab, dg in pts:

    ax.scatter(dg["n_stage_changes"], dg["cond_entropy_bits"], s=40, color=BLUE)

    ax.annotate(lab, (dg["n_stage_changes"], dg["cond_entropy_bits"]), textcoords="offset points", xytext=(5, 4), fontsize=8)

ax.set_xscale("log")

ax.set_xlabel("Real stage changes available (log scale)")

ax.set_ylabel("$H(S_{t+1}\\mid S_t)$, bits")

ax.set_ylim(-0.05, max(1.1, max(dg["cond_entropy_bits"] for _, dg in pts) + 0.15))

save(fig, "fig3_forecastability_map")

 

# ---------- numbers summary for writing ----------

L = ["# Key numbers (auto-generated from artifacts/forecast_audit.json)", ""]

s = A["synthetic"]

L.append(f"- Synthetic: HMM {pct(s['k']['1']['project_hmm']['acc_all'])}% vs advance-one {pct(s['k']['1']['advance_one']['acc_all'])}% on all steps; at stage changes both {pct(s['k']['1']['project_hmm']['acc_changes'])}% and {pct(s['k']['1']['advance_one']['acc_changes'])}%.")

c = A["cic_schedule"]

L.append(f"- CIC-IDS2017 schedule path: {' -> '.join(c['collapsed_path'])}; {c['diagnostics_runs']['n_stage_changes']} stage changes; advance-one {pct(c['k1_runs_fixed_rules']['advance_one']['acc_changes'])}%, deployed HMM {pct(c['k1_runs_fixed_rules']['project_hmm']['acc_changes'])}%.")

if has_dapt:

    d = A["dapt2020"]

    f1 = d["flows_k1_loo"]

    L.append(f"- DAPT2020: {d['rows']:,} flows, {len(d['attacker_paths'])} attacker sources, {d['diagnostics_flows']['n_stage_changes']} stage changes out of {d['diagnostics_flows']['n_pairs']:,} flow steps ({pct(d['diagnostics_flows']['share_changes'], 2)}%).")

    L.append(f"- DAPT2020 distinct transitions: {d['diagnostics_runs']['distinct_transitions']}; H(next|current) at changes = {d['diagnostics_runs']['cond_entropy_bits']:.3f} bits.")

    for m in ORDER:

        if m in f1:

            L.append(f"  - {NAMES[m]}: per-flow all steps {pct(f1[m]['acc_all'])}%, at changes {pct(f1[m]['acc_changes'])}% {ci(f1[m].get('acc_changes_exact95'))}")

with open(os.path.join(OUT, "key_numbers.md"), "w") as f:

    f.write("\n".join(L) + "\n")

 

print("[saved]")

for root, _, files in os.walk(OUT):

    for fn in sorted(files):

        print("  ", os.path.relpath(os.path.join(root, fn), ROOT))


