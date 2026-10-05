

#!/usr/bin/env python3

"""Forecasting audit: do kill-chain stage forecasters beat trivial rules on REAL attacker sequences?

 

Three sources of stage sequences, evaluated with the same methods and metrics:

  1. SYNTHETIC : the 200 simulated episodes used by research/forecast_eval.py (reproduces the old numbers)

  2. CIC-IDS2017: the real attack schedule across the week (one sequence; no per-attacker data in our version)

  3. DAPT2020  : real per-attacker sequences (Src IP, time-ordered), leave-one-attacker-out evaluation

 

Methods: persistence, advance_one, majority_next, markov1 (fitted on training attackers),

project_hmm (the deployed transition matrix), project_method_refit (same Bayesian recipe:

training counts + prior pseudo-counts, prior_strength=15).

Output: artifacts/forecast_audit.json and a printed summary.

"""

import glob

import json

import os

import sys

import numpy as np

import pandas as pd

 

HERE = os.path.dirname(os.path.abspath(__file__))

ROOT = os.path.join(HERE, "..")

sys.path.insert(0, HERE)

import forecastability as F

 

STAGES = ["NONE", "RECON", "INITIAL_COMPROMISE", "LATERAL_MOVEMENT", "EXFILTRATION"]

ORDER = ["RECON", "INITIAL_COMPROMISE", "LATERAL_MOVEMENT", "EXFILTRATION"]

DAPT_MAP = {"benign": "NONE", "reconnaissance": "RECON", "establish foothold": "INITIAL_COMPROMISE",

            "lateral movement": "LATERAL_MOVEMENT", "data exfiltration": "EXFILTRATION"}

PRIOR_STRENGTH = 15.0

N_BOOT = 2000

 

 

def load_project_transmat():

    npz = np.load(os.path.join(ROOT, "artifacts", "models", "hmm_forecaster.npz"), allow_pickle=True)

    T = np.asarray(npz["transmat"], dtype=float)

    st = [str(s) for s in npz["stages"]]

    assert st == STAGES, f"unexpected stage order {st}"

    return T

 

 

def methods_for(train_seqs, k, T_project):

    m = F.make_methods(train_seqs, STAGES, ORDER, k=k)

    m["project_hmm"] = F.kstep_predictor_from_matrix(T_project, STAGES, k)

    C = F.transition_counts(train_seqs, STAGES)

    m["project_method_refit"] = F.kstep_predictor_from_matrix(F.row_normalise(C + PRIOR_STRENGTH * T_project), STAGES, k)

    return m

 

 

FIXED = ["persistence", "advance_one", "project_hmm"]  # need no training data

 

 

def score(methods, seqs, k):

    """Per-episode hit arrays at all steps and at real stage changes."""

    out = {}

    for name, f in methods.items():

        a_eps, c_eps = [], []

        for s in seqs:

            ha, hc = [], []

            for t in range(len(s) - k):

                hit = float(f(s[t]) == s[t + k])

                ha.append(hit)

                if s[t + 1] != s[t]:

                    hc.append(hit)

            a_eps.append(np.array(ha))

            c_eps.append(np.array(hc))

        out[name] = (a_eps, c_eps)

    return out

 

 

def summarise(hits):

    res = {}

    for name, (a_eps, c_eps) in hits.items():

        a = np.concatenate(a_eps) if a_eps and any(len(x) for x in a_eps) else np.array([])

        c = np.concatenate(c_eps) if c_eps and any(len(x) for x in c_eps) else np.array([])

        res[name] = {"acc_all": float(a.mean()) if len(a) else None, "n_all": int(len(a)),

                     "acc_all_ci95": F._bootstrap_ci(a_eps, N_BOOT),

                     "acc_changes": float(c.mean()) if len(c) else None, "n_changes": int(len(c)),

                     "acc_changes_ci95": F._bootstrap_ci(c_eps, N_BOOT),
                     "acc_all_exact95": F.exact_ci(int(a.sum()), int(len(a))),
                     "acc_changes_exact95": F.exact_ci(int(c.sum()), int(len(c)))}

    return res

 

 

def leave_one_out(seqs, k, T_project):

    """Train on all other attackers, test on the held-out one; pool the per-episode hits."""

    pooled = {}

    for i in range(len(seqs)):

        train = seqs[:i] + seqs[i + 1:]

        m = methods_for(train, k, T_project)

        h = score(m, [seqs[i]], k)

        for name, (a, c) in h.items():

            pooled.setdefault(name, ([], []))

            pooled[name][0].extend(a)

            pooled[name][1].extend(c)

    return summarise(pooled)

 

 

# ---------------- data sources ----------------

def synthetic_sequences():

    from forecast_eval import make_kill_chain_episodes

    return [[STAGES[i] for i in ep] for ep in make_kill_chain_episodes()]

 

 

def cic_sequence():

    p = os.path.join(ROOT, "artifacts", "attack_timeline.csv")

    t = pd.read_csv(p)

    if "onset_ts" in t.columns:

        t = t.assign(_ts=pd.to_datetime(t["onset_ts"], utc=True, errors="coerce")).sort_values("_ts", kind="stable")

    return [t["kill_chain_stage"].astype(str).tolist()], t[["day", "label", "kill_chain_stage"]].to_dict(orient="records")

 

 

def _norm(c):

    return " ".join(str(c).strip().lower().replace("_", " ").split())

 

 

def load_dapt():

    files = sorted(glob.glob(os.path.join(ROOT, "data", "raw", "dapt2020", "*.csv")))

    if not files:

        return None

    header = None

    for p in files:

        cols = list(pd.read_csv(p, nrows=0).columns)

        if any(_norm(c) == "stage" for c in cols):

            header = cols

            break

    frames = []

    for p in files:

        cols = list(pd.read_csv(p, nrows=0).columns)

        if any(_norm(c) == "stage" for c in cols):

            d = pd.read_csv(p, low_memory=False)

        else:  # header-less file: reuse the header of the others

            d = pd.read_csv(p, header=None, names=header, low_memory=False)

        d.columns = [_norm(c) for c in d.columns]

        d["file"] = os.path.basename(p)

        frames.append(d[["file", "timestamp", "src ip", "dst ip", "activity", "stage"]])

    d = pd.concat(frames, ignore_index=True)

    d["stage_n"] = d["stage"].astype(str).str.strip().str.lower().map(DAPT_MAP)

    unknown = d.loc[d["stage_n"].isna(), "stage"].unique().tolist()

    d["ts"] = pd.to_datetime(d["timestamp"], format="%d/%m/%Y %I:%M:%S %p", errors="coerce")

    return d, unknown

 

 

def dapt_sequences(d):

    atk = d[d["stage_n"].notna() & (d["stage_n"] != "NONE") & d["ts"].notna()].copy()

    atk = atk.sort_values(["src ip", "ts"], kind="stable")

    seqs, paths = [], {}

    for ip, g in atk.groupby("src ip", sort=False):

        s = g["stage_n"].tolist()

        paths[str(ip)] = {"flows": len(s), "path": F.collapse_runs(s)}

        if len(s) >= 2:

            seqs.append(s)

    return seqs, paths

 

 

# ---------------- report ----------------

def table(title, res, order):

    print(f"\n  {title}")

    print(f"    {'method':<22} {'acc all steps':>16} {'n':>7}   {'acc at stage changes [exact 95% CI]':>36} {'n':>5}")

    for name in order:

        if name not in res:

            continue

        r = res[name]

        aa = "n/a" if r["acc_all"] is None else f"{r['acc_all']:.1%}"

        ac = "n/a" if r["acc_changes"] is None else f"{r['acc_changes']:.1%}"

        lo, hi = r["acc_changes_exact95"]

        ci = "" if lo is None else f" [{lo:.0%}-{hi:.0%}]"

        print(f"    {name:<22} {aa:>16} {r['n_all']:>7}   {ac + ci:>36} {r['n_changes']:>5}")

 

 

def diag_line(name, dg):

    print(f"    {name:<26} episodes={dg['n_episodes']:>4}  steps={dg['n_pairs']:>7}  stage changes={dg['n_stage_changes']:>5} "

          f"({dg['share_changes']:.1%})  distinct transitions={dg['distinct_transitions']:>2}  "

          f"H(next|cur)={dg['cond_entropy_bits']:.3f} bits  ceiling={dg['ceiling_first_order']:.1%}")

 

 

def main():

    T = load_project_transmat()

    all_methods = ["persistence", "advance_one", "majority_next", "markov1", "project_hmm", "project_method_refit"]

    out = {"stages": STAGES, "order": ORDER, "prior_strength": PRIOR_STRENGTH, "n_boot": N_BOOT}

 

    print("=" * 100)

    print("FORECASTING AUDIT: learned forecasters vs trivial rules, on synthetic and real stage sequences")

    print("=" * 100)

 

    # 1. synthetic (reproduces research/forecast_eval.py)

    syn = synthetic_sequences()

    out["synthetic"] = {"diagnostics": F.diagnostics(syn, STAGES), "k": {}}

    for k in (1, 2, 3):

        out["synthetic"]["k"][str(k)] = summarise(score({n: f for n, f in methods_for(syn, k, T).items() if n in FIXED}, syn, k))

    table("SYNTHETIC episodes (the old evaluation), 1 step ahead", out["synthetic"]["k"]["1"], FIXED)

 

    # 2. CIC-IDS2017 real schedule

    cic, cic_rows = cic_sequence()

    cic_runs = [F.collapse_runs(cic[0])]

    out["cic_schedule"] = {"events": cic_rows, "collapsed_path": cic_runs[0],

                           "diagnostics_events": F.diagnostics(cic, STAGES),

                           "diagnostics_runs": F.diagnostics(cic_runs, STAGES),

                           "k1_runs_fixed_rules": summarise(score({n: f for n, f in methods_for(cic_runs, 1, T).items() if n in FIXED}, cic_runs, 1))}

    print("\n  CIC-IDS2017 real attack schedule, collapsed:", " -> ".join(cic_runs[0]))

    table("CIC-IDS2017 schedule, each step is a real stage change (fixed rules only; one sequence, nothing to train on)", out["cic_schedule"]["k1_runs_fixed_rules"], FIXED)

 

    # 3. DAPT2020 real attackers

    loaded = load_dapt()

    if loaded is None:

        print("\n  DAPT2020: no files found in data/raw/dapt2020/ -- skipped")

    else:

        d, unknown = loaded

        seqs, paths = dapt_sequences(d)

        runs = [F.collapse_runs(s) for s in seqs]

        runs2 = [r for r in runs if len(r) >= 2]

        out["dapt2020"] = {"rows": int(len(d)), "unparsed_timestamps": int(d["ts"].isna().sum()),

                           "unknown_stage_labels": [str(u) for u in unknown], "attacker_paths": paths,

                           "diagnostics_flows": F.diagnostics(seqs, STAGES), "diagnostics_runs": F.diagnostics(runs2, STAGES),

                           "flows_k1_loo": leave_one_out(seqs, 1, T), "runs_k": {}}

        for k in (1, 2):

            usable = [r for r in runs2 if len(r) > k]

            out["dapt2020"]["runs_k"][str(k)] = leave_one_out(usable, k, T) if len(usable) >= 2 else {}

        print(f"\n  DAPT2020: {len(d):,} flows, {len(paths)} attacker IPs, {len(seqs)} with 2+ attack flows; "

              f"unparsed timestamps={out['dapt2020']['unparsed_timestamps']}, unknown stage labels={unknown}")

        for ip, p in sorted(paths.items(), key=lambda x: -x[1]["flows"]):

            print(f"    {ip:<18} flows={p['flows']:>6,}  path={' -> '.join(p['path'])}")

        table("DAPT2020, every flow is a step (leave-one-attacker-out)", out["dapt2020"]["flows_k1_loo"], all_methods)

        table("DAPT2020, only stage changes (consecutive repeats collapsed), 1 step ahead (leave-one-attacker-out)", out["dapt2020"]["runs_k"]["1"], all_methods)

 

    print("\n  FORECASTABILITY DIAGNOSTICS (how predictable is the next stage at all?)")

    diag_line("synthetic episodes", out["synthetic"]["diagnostics"])

    diag_line("CIC-IDS2017 schedule events", out["cic_schedule"]["diagnostics_events"])

    diag_line("CIC-IDS2017 schedule, runs", out["cic_schedule"]["diagnostics_runs"])

    if "dapt2020" in out:

        diag_line("DAPT2020 flows", out["dapt2020"]["diagnostics_flows"])

        diag_line("DAPT2020 runs", out["dapt2020"]["diagnostics_runs"])

 

    p = os.path.join(ROOT, "artifacts", "forecast_audit.json")

    with open(p, "w") as f:

        json.dump(out, f, indent=2, default=str)

    print(f"\n[saved] {p}")

 

 

if __name__ == "__main__":

    main()
