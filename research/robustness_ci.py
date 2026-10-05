
#!/usr/bin/env python3
"""Honest uncertainty for the paper's threshold-free (AUROC) results.

Part A, block bootstrap: resample groups of related flows instead of single flows.
  - CIC-IDS2017 Friday (no timestamps in our release): consecutive blocks of 5,000 rows, assuming
    the file is in approximate time order. Uses artifacts/rc_friday.parquet (deployed detector scores).
  - DAPT2020 Tuesday-Friday: attack flows are resampled by attacker source address, normal flows by
    one-hour blocks. Uses artifacts/rc_dapt.parquet (deployed detector scores, E1).
Part B, seeds: refit Isolation Forests with 5 random seeds and report the spread of AUROC for
  (i) the recipe trained on CIC Mon-Wed normal traffic, scored on CIC Friday (all model features),
  (ii) E2: same recipe on the 77 shared features, scored on DAPT2020 Tue-Fri,
  (iii) E3: refitted on DAPT2020 Monday normal traffic, scored on DAPT2020 Tue-Fri.
Output: artifacts/robustness_ci.json
"""
import json
import os
import sys
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dapt_transfer as T

N_BOOT = 300
SEEDS = [0, 1, 2, 3, 4]
FRIDAY_BLOCK = 5000


def block_auc(y, s, groups, n_boot=N_BOOT, seed=42):
    """AUROC with a 95% interval from resampling whole groups (attack and normal groups resampled separately)."""
    y = np.asarray(y, bool)
    s = np.asarray(s, float)
    groups = np.char.add(np.asarray(groups).astype(str), np.where(y, "|attack", "|normal"))
    point = float(roc_auc_score(y, s))
    att_g = pd.unique(groups[y])
    ben_g = pd.unique(groups[~y])
    idx_by_g = pd.Series(np.arange(len(y))).groupby(groups).apply(lambda x: x.values).to_dict()
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n_boot):
        pick = np.concatenate([np.concatenate([idx_by_g[g] for g in rng.choice(att_g, len(att_g))]),
                               np.concatenate([idx_by_g[g] for g in rng.choice(ben_g, len(ben_g))])])
        yy = y[pick]
        if yy.all() or (~yy).all():
            continue
        vals.append(roc_auc_score(yy, s[pick]))
    return {"auroc": point, "ci95": [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))],
            "n_groups_attack": int(len(att_g)), "n_groups_normal": int(len(ben_g)), "n_boot": len(vals)}


def per_type(y_all, s, lab, groups, types):
    out = {}
    benign = ~np.asarray(y_all, bool)
    for t in types:
        m = np.asarray(lab) == t
        sel = benign | m
        if m.sum() == 0:
            continue
        out[t] = block_auc(m[sel], np.asarray(s)[sel], np.asarray(groups)[sel])
    return out


def fmt(r):
    return f"{r['auroc']:.3f} [{r['ci95'][0]:.3f}-{r['ci95'][1]:.3f}] ({r['n_groups_attack']} attack groups)"


def main():
    t0 = time.time()
    out = {"n_boot": N_BOOT, "friday_block_rows": FRIDAY_BLOCK, "block_bootstrap": {}, "seeds": {}}

    # ---------------- Part A: block bootstrap ----------------
    print("[A] block bootstrap of the deployed detector's AUROC")
    fr = pd.read_parquet(os.path.join(T.ART, "rc_friday.parquet")).reset_index(drop=True)
    y_fr = ~fr["label"].isin(T.BENIGN_CIC).values
    g_fr = np.arange(len(fr)) // FRIDAY_BLOCK
    out["block_bootstrap"]["cic_friday_overall"] = r = block_auc(y_fr, fr["score"].values, g_fr)
    print(f"    CIC Friday overall: {fmt(r)}")
    types = [t for t in fr.loc[y_fr, "label"].value_counts().index]
    out["block_bootstrap"]["cic_friday_per_type"] = pt = per_type(y_fr, fr["score"].values, fr["label"].values, g_fr, types)
    for t, r in pt.items():
        print(f"      {t:<12} {fmt(r)}")

    dp = T.load_dapt()
    test = dp[dp["day"].isin(["tuesday", "wednesday", "thursday", "friday"])].reset_index(drop=True)
    rcd = pd.read_parquet(os.path.join(T.ART, "rc_dapt.parquet")).reset_index(drop=True)
    assert len(rcd) == len(test), "rc_dapt.parquet does not match the DAPT2020 test set; rerun export_predictions.py"
    y_d = test["is_attack"].values
    hour = pd.to_datetime(test["ts"]).dt.floor("h").astype(str).values
    g_d = np.where(y_d, "atk_" + test["Src IP"].astype(str).values, "hour_" + hour)
    out["block_bootstrap"]["dapt_E1_overall"] = r = block_auc(y_d, rcd["score"].values, g_d)
    print(f"    DAPT2020 E1 (deployed) overall: {fmt(r)}")

    # ---------------- Part B: seeds ----------------
    print("[B] Isolation Forest refitted with 5 seeds")
    tr = pd.read_parquet(os.path.join(T.PROC, "train.parquet"))
    te = pd.read_parquet(os.path.join(T.PROC, "test.parquet")).reset_index(drop=True)
    from pipeline_consumer import Pipeline
    feats_all = list(Pipeline().anom_features)
    shared = [f for f in feats_all if f in dp.columns]
    ben = tr[tr["label"].isin(T.BENIGN_CIC)]
    med = ben[feats_all].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).median()
    Xb_all = T.clean(ben[feats_all], med).values
    Xb_sh = T.clean(ben[shared], med[shared]).values
    Xfr = T.clean(te[feats_all], med).values
    y_fr2 = ~te["label"].isin(T.BENIGN_CIC).values
    Xd = T.clean(test[shared], med[shared]).values
    mon = dp[(dp["day"] == "monday") & ~dp["is_attack"]].sort_values("ts", kind="stable")
    Xm = T.clean(mon.iloc[: int(0.7 * len(mon))][shared], med[shared]).values
    act = test["activity_n"].values
    res = {"cic_friday_recipe": [], "dapt_E2": [], "dapt_E3": [], "dapt_E3_account_discovery": []}
    for sd in SEEDS:
        f = lambda X: IsolationForest(n_estimators=200, random_state=sd, n_jobs=-1).fit(X)
        m1, m2, m3 = f(Xb_all), f(Xb_sh), f(Xm)
        a1 = roc_auc_score(y_fr2, -m1.score_samples(Xfr))
        a2 = roc_auc_score(y_d, -m2.score_samples(Xd))
        s3 = -m3.score_samples(Xd)
        a3 = roc_auc_score(y_d, s3)
        sel = (~y_d) | (act == "Account Discovery")
        a4 = roc_auc_score((act == "Account Discovery")[sel], s3[sel]) if (act == "Account Discovery").any() else float("nan")
        for k, v in zip(res, [a1, a2, a3, a4]):
            res[k].append(float(v))
        print(f"    seed {sd}: CIC Friday {a1:.3f}  DAPT E2 {a2:.3f}  DAPT E3 {a3:.3f}  E3 account discovery {a4:.3f}")
    for k, v in res.items():
        out["seeds"][k] = {"values": v, "mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1)), "min": float(min(v)), "max": float(max(v))}
        print(f"    {k:<28} mean {np.mean(v):.3f}  sd {np.std(v, ddof=1):.3f}  range {min(v):.3f}-{max(v):.3f}")

    with open(os.path.join(T.ART, "robustness_ci.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"[saved] artifacts/robustness_ci.json  ({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
