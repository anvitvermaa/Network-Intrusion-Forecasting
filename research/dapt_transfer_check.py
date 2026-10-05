
#!/usr/bin/env python3

"""Follow-up to dapt_transfer.py.

 

Check 1 (threshold-free): AUROC of every detector on DAPT2020 Tue-Fri, overall and per attack activity.

         AUROC 0.5 = the detector's score cannot rank attacks above normal traffic at all; 1.0 = perfect ranking.

Check 2: rerun E2 and E3 without the 3 features that look completely different between the two datasets'

         benign traffic (KS = 1.0), which are likely CICFlowMeter-version artefacts:

         init_fwd_win_bytes (0 vs -1 sentinel), subflow_bwd_packets, fwd_seg_size_min.

"""

import contextlib

import io

import json

import os

import sys

import time

import numpy as np

import pandas as pd

from sklearn.metrics import roc_auc_score

from sklearn.utils.class_weight import compute_sample_weight

from xgboost import XGBClassifier

 

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

import dapt_transfer as T

 

ARTEFACTS = ["init_fwd_win_bytes", "subflow_bwd_packets", "fwd_seg_size_min"]

N_BOOT = 300

 

 

def auc_ci(y, s, n_boot=N_BOOT, seed=T.SEED):

    y = np.asarray(y, bool)

    s = np.asarray(s, float)

    if y.all() or (~y).all():

        return None, [None, None]

    auc = float(roc_auc_score(y, s))

    rng = np.random.default_rng(seed)

    idx_p, idx_n = np.where(y)[0], np.where(~y)[0]

    boots = []

    for _ in range(n_boot):

        bp = rng.choice(idx_p, len(idx_p))

        bn = rng.choice(idx_n, len(idx_n))

        b = np.concatenate([bp, bn])

        boots.append(roc_auc_score(y[b], s[b]))

    return auc, [float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))]

 

 

def auc_report(name, y, s, activity, min_n=50):

    auc, ci = auc_ci(y, s)

    out = {"auroc": auc, "auroc_ci95": ci, "per_activity": {}}

    benign = ~np.asarray(y, bool)

    for a in sorted(set(np.asarray(activity)[np.asarray(y, bool)])):

        m = np.asarray(activity) == a

        if m.sum() < min_n:

            continue

        sel = benign | m

        out["per_activity"][a] = {"n": int(m.sum()), "auroc": float(roc_auc_score(m[sel], np.asarray(s)[sel]))}

    print(f"    {name:<48} AUROC = {auc:.3f}  [{ci[0]:.3f}-{ci[1]:.3f}]")

    for a, e in sorted(out["per_activity"].items(), key=lambda x: -x[1]["n"]):

        print(f"        {a:<26} n={e['n']:>6,}  AUROC = {e['auroc']:.3f}")

    return out

 

 

def deployed_scores(pipe, df):

    with contextlib.redirect_stdout(io.StringIO()):

        Xa = pipe.to_matrix.transform(df[pipe.anom_features])

    return -pipe.iso.decision_function(Xa)

 

 

def choose_tau(clf, classes, Xv, yv, av):

    best_tau, best = 0.0, (-1.0, 1.0)

    for tau in [0.0, 0.9, 0.95, 0.99, 0.995, 0.999, 0.9999]:

        _, pu = T.classify(clf, classes, Xv, av, tau)

        flag = ~np.isin(pu, list(T.BENIGN_CIC))

        far = float((flag & ~yv).sum() / max((~yv).sum(), 1))

        rec = float((flag & yv).sum() / max(yv.sum(), 1))

        if far <= 0.01 and rec > best[0]:

            best_tau, best = tau, (rec, far)

    return best_tau

 

 

def main():

    t0 = time.time()

    tr = pd.read_parquet(os.path.join(T.PROC, "train.parquet"))

    va = pd.read_parquet(os.path.join(T.PROC, "val.parquet"))

    dp = T.load_dapt()

    from pipeline_consumer import Pipeline

    os.environ["NIF_TAU"] = "0.999"

    pipe = Pipeline()

    cic_feats = list(pipe.anom_features)

    shared = [f for f in cic_feats if f in dp.columns]

    missing = [f for f in cic_feats if f not in dp.columns]

    no_art = [f for f in shared if f not in ARTEFACTS]

 

    cic_benign = tr[tr["label"].isin(T.BENIGN_CIC)]

    med = cic_benign[cic_feats].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).median()

    vb = va[va["label"].isin(T.BENIGN_CIC)]

    dmon = dp[(dp["day"] == "monday") & ~dp["is_attack"]].sort_values("ts", kind="stable")

    test = dp[dp["day"].isin(["tuesday", "wednesday", "thursday", "friday"])].reset_index(drop=True)

    y, act, stg = test["is_attack"].values, test["activity_n"].values, test["Stage"].astype(str).str.strip().values

    out = {"artefact_features_dropped": ARTEFACTS, "check1_auroc": {}, "check2_without_artefacts": {}}

 

    # ---------------- Check 1: AUROC ----------------

    print("\n=== CHECK 1: can each detector's score rank DAPT2020 attacks above DAPT2020 normal traffic? (0.5 = chance) ===")

    t1 = test.copy()

    for f in missing:

        t1[f] = med[f]

    t1[cic_feats] = T.clean(t1[cic_feats], med)

    out["check1_auroc"]["E1_deployed_detector"] = auc_report("E1 deployed detector (CIC, 82 features)", y, deployed_scores(pipe, t1), act)

 

    thursday_far = float(np.mean(deployed_scores(pipe, T.clean(vb[cic_feats], med)) >= pipe.threshold))

    cut = int(0.7 * len(dmon))

    models = {}

    for tag, feats in (("shared", shared), ("no_artefacts", no_art)):

        Xb = T.clean(cic_benign[feats], med[feats]).values

        iso2 = T.fit_iforest(Xb)

        thr2 = float(np.quantile(T.iscore(iso2, T.clean(vb[feats], med[feats]).values), 1 - thursday_far))

        iso3 = T.fit_iforest(T.clean(dmon.iloc[:cut][feats], med[feats]).values)

        thr3 = float(np.quantile(T.iscore(iso3, T.clean(dmon.iloc[cut:][feats], med[feats]).values), 1 - thursday_far))

        Xt = T.clean(test[feats], med[feats]).values

        models[tag] = (feats, iso2, thr2, iso3, thr3, Xt)

        out["check1_auroc"][f"E2_detector_{tag}"] = auc_report(f"E2 detector trained on CIC benign ({len(feats)} features)", y, T.iscore(iso2, Xt), act)

        out["check1_auroc"][f"E3_detector_{tag}"] = auc_report(f"E3 detector trained on DAPT Monday benign ({len(feats)} features)", y, T.iscore(iso3, Xt), act)

 

    # ---------------- Check 2: full pipeline without the artefact features ----------------

    print(f"\n=== CHECK 2: E2 and E3 rerun without {ARTEFACTS} ===")

    feats, iso2, thr2, iso3, thr3, Xt = models["no_artefacts"]

    trd = T.near_dedup(tr, feats)

    classes = sorted(trd["label"].unique())

    yy = trd["label"].map({c: i for i, c in enumerate(classes)}).astype(int)

    clf = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, random_state=T.SEED, n_jobs=4, verbosity=0, tree_method="hist")

    clf.fit(T.clean(trd[feats], med[feats]).values, yy, sample_weight=compute_sample_weight("balanced", yy))

    Xv = T.clean(va[feats], med[feats]).values

    yv = ~va["label"].isin(T.BENIGN_CIC).values

    tau = choose_tau(clf, classes, Xv, yv, T.iscore(iso2, Xv) >= thr2)

    print(f"    classifier retrained on {len(trd):,} rows with {len(feats)} features; UNKNOWN threshold from Thursday: tau={tau}")

    out["check2_without_artefacts"]["tau"] = tau

    for name, anom in (("E2_shared_feature_retrain", T.iscore(iso2, Xt) >= thr2), ("E3_local_benign_refit", T.iscore(iso3, Xt) >= thr3)):

        pc, _ = T.classify(clf, classes, Xt, anom, 0.0)

        _, pu = T.classify(clf, classes, Xt, anom, tau)

        res = T.levels(y, anom, pc, pu, act, stg)

        out["check2_without_artefacts"][name] = res

        T.show(f"{name} (without artefact features)", res)

 

    with open(os.path.join(T.ART, "dapt_transfer_check.json"), "w") as f:

        json.dump(out, f, indent=2, default=str)

    print(f"\n[saved] artifacts/dapt_transfer_check.json   ({time.time() - t0:.0f}s)")

 

 

if __name__ == "__main__":

    main()

