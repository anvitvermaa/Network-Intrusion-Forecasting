
#!/usr/bin/env python3
"""Forecastability audit of the public synthetic APT alert dataset released by Ghafir et al.

Dataset: "Dataset of Advanced Persistent Threat (APT) alerts", Loughborough University repository
(Figshare article 7577750; 3,676 APT alerts, 1,000 campaigns, step labels S1-S6). It is the public
release of the APT alerts used to evaluate the HMM forecaster of Ghafir et al., IEEE Access 2019.

What this script does
  1. Downloads the SQLite file (280 kB) if it is not already present.
  2. Groups alerts into campaigns by infected host, ordered by timestamp (an idealised, error-free
     correlation step; S6 alerts carry no infected host and cannot be attributed).
  3. Forecastability diagnostic on step-change sequences.
  4. First-order trivial baselines (persistence, advance-one, majority, Markov), 5-fold CV over campaigns.
  5. A prefix lookup table (most frequent continuation of the exact observed prefix), top-1 and top-2,
     after 2, 3 and 4 observed alerts, under 5-fold CV and under 20 repeated 50/50 splits
     (the published paper used a single 50/50 split).
Output: artifacts/ghafir_audit.json
"""
import collections
import json
import os
import sqlite3
import sys
import urllib.request
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, HERE)
import forecastability as F

URL = 'https://ndownloader.figshare.com/files/14075042'
DB = os.path.join(ROOT, "data", "raw", "ghafir", "APT_alerts_dataset.db")
STEPS = ["S1", "S2", "S3", "S4", "S5", "S6"]
SEED = 42
PUBLISHED = {  # Ghafir et al., IEEE Access 2019, test set of the larger synthetic dataset
    "top1": {2: 0.436, 4: 0.9331},
    "top2": {2: 0.665, 3: 0.927, 4: 1.0},
}


def load():
    if not os.path.exists(DB):
        os.makedirs(os.path.dirname(DB), exist_ok=True)
        print(f"[download] {URL}")
        urllib.request.urlretrieve(URL, DB)
    d = pd.read_sql("select * from alerts_dataset", sqlite3.connect(DB))
    return d


def campaigns(d):
    g = d.dropna(subset=["infected_host"]).sort_values(["infected_host", "timestamp", "alert_id"], kind="stable")
    return [list(s) for _, s in g.groupby("infected_host", sort=True)["step"]]


def first_order_cv(runs, k):
    rng = np.random.default_rng(SEED)
    idx = rng.permutation(len(runs))
    folds = np.array_split(idx, 5)
    tot = {}
    for f in folds:
        fs = set(f.tolist())
        tr = [runs[i] for i in idx if i not in fs]
        te = [runs[i] for i in f if len(runs[i]) > k]
        for name, fn in F.make_methods(tr, STEPS, STEPS, k=k).items():
            h = [fn(s[t]) == s[t + k] for s in te for t in range(len(s) - k)]
            a = tot.setdefault(name, [0, 0])
            a[0] += int(sum(h))
            a[1] += len(h)
    return {n: {"hits": h, "n": N, "acc": h / N, "ci95": F.exact_ci(h, N)} for n, (h, N) in tot.items()}


def prefix_table(seqs, plans):
    out = {}
    for n in (2, 3, 4):
        t1 = t2 = tot = 0
        for tr_i, te_i in plans:
            table = collections.defaultdict(collections.Counter)
            for i in tr_i:
                s = seqs[i]
                if len(s) > n:
                    table[tuple(s[:n])][s[n]] += 1
            for i in te_i:
                s = seqs[i]
                if len(s) > n:
                    top = [k for k, _ in table[tuple(s[:n])].most_common(2)] or [s[n - 1]]
                    tot += 1
                    t1 += int(top[0] == s[n])
                    t2 += int(s[n] in top)
        out[str(n)] = {"n": tot, "top1": t1 / tot, "top1_ci95": F.exact_ci(t1, tot),
                       "top2": t2 / tot, "top2_ci95": F.exact_ci(t2, tot)}
    return out


def main():
    d = load()
    seqs = campaigns(d)
    runs = [r for r in (F.collapse_runs(s) for s in seqs) if len(r) >= 2]
    print(f"[data] {len(d):,} alerts; {len(seqs)} campaigns with an infected host ({sum(map(len, seqs)):,} alerts); "
          f"{int(d['infected_host'].isna().sum())} alerts without host (all {sorted(d[d['infected_host'].isna()]['step'].unique())})")

    dg = F.diagnostics(runs, STEPS)
    print(f"[diagnostic] step changes={dg['n_stage_changes']:,} in {dg['n_episodes']} campaigns; distinct transitions={dg['distinct_transitions']}; "
          f"H(next|current)={dg['cond_entropy_bits']:.3f} bits; first-order ceiling={dg['ceiling_first_order']:.1%}")

    fo = {str(k): first_order_cv(runs, k) for k in (1, 2)}
    print("[first-order baselines, step changes, 5-fold CV]")
    for k, res in fo.items():
        for name, r in res.items():
            print(f"   k={k} {name:<14} {r['hits']:>5}/{r['n']:<5} = {r['acc']:.1%}  [{r['ci95'][0]:.1%}-{r['ci95'][1]:.1%}]")

    rng = np.random.default_rng(SEED)
    idx = rng.permutation(len(seqs))
    cv_plans = [([i for i in idx if i not in set(f.tolist())], f.tolist()) for f in np.array_split(idx, 5)]
    rng = np.random.default_rng(SEED)
    half_plans = []
    for _ in range(20):
        p = rng.permutation(len(seqs))
        h = len(p) // 2
        half_plans.append((p[:h].tolist(), p[h:].tolist()))
    pt = {"cv5": prefix_table(seqs, cv_plans), "split50_x20": prefix_table(seqs, half_plans)}
    print("[prefix lookup table vs published HMM]")
    for proto, res in pt.items():
        for n, r in res.items():
            pub1 = PUBLISHED["top1"].get(int(n))
            pub2 = PUBLISHED["top2"].get(int(n))
            p1 = f"{pub1:.1%}" if pub1 is not None else "n/a"
            p2 = f"{pub2:.1%}" if pub2 is not None else "n/a"
            print(f"   {proto:<12} after {n} alerts (n={r['n']:>5}): top-1 {r['top1']:.1%} (HMM {p1})   top-2 {r['top2']:.1%} (HMM {p2})")

    out = {"source": URL, "alerts": int(len(d)), "campaigns_with_host": len(seqs),
           "alerts_without_host": int(d["infected_host"].isna().sum()),
           "diagnostics_step_changes": {k: v for k, v in dg.items() if k != "transition_counts"},
           "transition_counts": dg["transition_counts"], "first_order_cv5": fo, "prefix_table": pt,
           "published_hmm": PUBLISHED,
           "caveats": ["public release lacks the 2,300 uncorrelated alerts used in the paper",
                       "campaigns grouped by infected host (idealised correlation)",
                       "S6 alerts have no infected host and are excluded"]}
    p = os.path.join(ROOT, "artifacts", "ghafir_audit.json")
    with open(p, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[saved] {p}")


if __name__ == "__main__":
    main()
