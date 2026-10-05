
#!/usr/bin/env python3

"""Cross-network test: does the CIC-IDS2017-trained Detect -> Classify pipeline work on DAPT2020?

 

E1  deployed system, zero-shot : the frozen production models (temporal XGB + UNKNOWN, tau=0.999).

                                  DAPT2020 lacks 5 of the 82 features; they are filled with CIC benign medians.

E2  shared-feature retrain     : same recipe retrained on CIC Mon-Wed using only features both datasets have.

                                  Detector threshold matched to the deployed detector's Thursday benign false-alarm rate;

                                  UNKNOWN threshold chosen on Thursday (max unseen-attack recall with Thursday FAR <= 1%).

E3  local benign refit         : E2's classifier, but the detector is refitted on DAPT2020 Monday (all benign):

                                  70% of Monday (by time) to fit, 30% to set the threshold at the same false-alarm rate.

Test set for all three: DAPT2020 Tuesday-Friday (Monday is used only by E3, and only its benign traffic).

 

Run:  python research/dapt_transfer.py                 (all features both datasets share)

      python research/dapt_transfer.py --robust-subset (also drop features the two CICFlowMeter versions compute differently)

"""

import argparse

import glob

import json

import os

import sys

import time

import warnings

import numpy as np

import pandas as pd

from scipy.stats import beta, ks_2samp

from sklearn.ensemble import IsolationForest

from sklearn.utils.class_weight import compute_sample_weight

from xgboost import XGBClassifier

 

warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))

ROOT = os.path.join(HERE, "..")

PROC = os.path.join(ROOT, "data", "processed")

DAPT_DIR = os.path.join(ROOT, "data", "raw", "dapt2020")

ART = os.path.join(ROOT, "artifacts")

sys.path.insert(0, os.path.join(ROOT, "streaming"))

 

BENIGN_CIC = {"Benign", "Attempted-relabel-as-Benign"}

UNK = "UNKNOWN_ATTACK"

SEED = 42

 

# DAPT2020 raw CICFlowMeter header -> project canonical feature name

RAW2CANON = {

    "Protocol": "protocol", "Flow Duration": "duration", "Total Fwd Packet": "tot_fwd_pkts", "Total Bwd packets": "tot_bwd_pkts",

    "Total Length of Fwd Packet": "orig_bytes", "Total Length of Bwd Packet": "resp_bytes",

    "Fwd Packet Length Max": "fwd_packet_length_max", "Fwd Packet Length Min": "fwd_packet_length_min",

    "Fwd Packet Length Mean": "fwd_packet_length_mean", "Fwd Packet Length Std": "fwd_packet_length_std",

    "Bwd Packet Length Max": "bwd_packet_length_max", "Bwd Packet Length Min": "bwd_packet_length_min",

    "Bwd Packet Length Mean": "bwd_packet_length_mean", "Bwd Packet Length Std": "bwd_packet_length_std",

    "Flow Bytes/s": "flow_bytes_per_s", "Flow Packets/s": "flow_pkts_per_s",

    "Flow IAT Mean": "flow_iat_mean", "Flow IAT Std": "flow_iat_std", "Flow IAT Max": "flow_iat_max", "Flow IAT Min": "flow_iat_min",

    "Fwd IAT Total": "fwd_iat_total", "Fwd IAT Mean": "fwd_iat_mean", "Fwd IAT Std": "fwd_iat_std", "Fwd IAT Max": "fwd_iat_max", "Fwd IAT Min": "fwd_iat_min",

    "Bwd IAT Total": "bwd_iat_total", "Bwd IAT Mean": "bwd_iat_mean", "Bwd IAT Std": "bwd_iat_std", "Bwd IAT Max": "bwd_iat_max", "Bwd IAT Min": "bwd_iat_min",

    "Fwd PSH Flags": "fwd_psh_flags", "Bwd PSH Flags": "bwd_psh_flags", "Fwd URG Flags": "fwd_urg_flags", "Bwd URG Flags": "bwd_urg_flags",

    "Fwd Header Length": "fwd_header_length", "Bwd Header Length": "bwd_header_length",

    "Fwd Packets/s": "fwd_packets_per_s", "Bwd Packets/s": "bwd_packets_per_s",

    "Packet Length Min": "packet_length_min", "Packet Length Max": "packet_length_max", "Packet Length Mean": "packet_length_mean",

    "Packet Length Std": "packet_length_std", "Packet Length Variance": "packet_length_variance",

    "FIN Flag Count": "fin_flag_count", "SYN Flag Count": "syn_flag_count", "RST Flag Count": "rst_flag_count", "PSH Flag Count": "psh_flag_count",

    "ACK Flag Count": "ack_flag_count", "URG Flag Count": "urg_flag_count", "CWR Flag Count": "cwr_flag_count", "ECE Flag Count": "ece_flag_count",

    "Down/Up Ratio": "down_per_up_ratio", "Average Packet Size": "avg_packet_size",

    "Fwd Segment Size Avg": "avg_fwd_segment_size", "Bwd Segment Size Avg": "avg_bwd_segment_size",

    "Fwd Bytes/Bulk Avg": "fwd_avg_bytes_per_bulk", "Fwd Packet/Bulk Avg": "fwd_avg_packets_per_bulk", "Fwd Bulk Rate Avg": "fwd_avg_bulk_rate",

    "Bwd Bytes/Bulk Avg": "bwd_avg_bytes_per_bulk", "Bwd Packet/Bulk Avg": "bwd_avg_packets_per_bulk", "Bwd Bulk Rate Avg": "bwd_avg_bulk_rate",

    "Subflow Fwd Packets": "subflow_fwd_packets", "Subflow Fwd Bytes": "subflow_fwd_bytes",

    "Subflow Bwd Packets": "subflow_bwd_packets", "Subflow Bwd Bytes": "subflow_bwd_bytes",

    "FWD Init Win Bytes": "init_fwd_win_bytes", "Bwd Init Win Bytes": "init_bwd_win_bytes",

    "Fwd Act Data Pkts": "fwd_act_data_packets", "Fwd Seg Size Min": "fwd_seg_size_min",

    "Active Mean": "active_mean", "Active Std": "active_std", "Active Max": "active_max", "Active Min": "active_min",

    "Idle Mean": "idle_mean", "Idle Std": "idle_std", "Idle Max": "idle_max", "Idle Min": "idle_min",

}

# Features the fixed (Distrinet) and original CICFlowMeter compute differently (Engelen et al. 2021)

VERSION_SENSITIVE = ["active_mean", "active_std", "active_max", "active_min", "idle_mean", "idle_std", "idle_max", "idle_min",

                     "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags", "down_per_up_ratio"]

 

 

def cp(k, n, alpha=0.05):

    if n == 0:

        return [None, None]

    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))

    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))

    return [lo, hi]

 

 

def clean(X, med):

    X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)

    return X.fillna(med)

 

 

# ---------------- data ----------------

def load_dapt():

    files = sorted(glob.glob(os.path.join(DAPT_DIR, "*.csv")))

    if not files:

        sys.exit("No DAPT2020 CSVs in data/raw/dapt2020/")

    header = None

    for p in files:

        cols = list(pd.read_csv(p, nrows=0).columns)

        if any(str(c).strip().lower() == "stage" for c in cols):

            header = [str(c).strip() for c in cols]

            break

    frames = []

    for p in files:

        cols = [str(c).strip() for c in pd.read_csv(p, nrows=0).columns]

        if "Stage" in cols:

            d = pd.read_csv(p, low_memory=False)

            d.columns = [str(c).strip() for c in d.columns]

        else:

            d = pd.read_csv(p, header=None, names=header, low_memory=False)

        name = os.path.basename(p).lower()

        d["day"] = next((x for x in ["monday", "tuesday", "wednesday", "thursday", "friday"] if x in name), "unknown")

        d["file"] = os.path.basename(p)

        frames.append(d)

    d = pd.concat(frames, ignore_index=True)

    d["stage_n"] = d["Stage"].astype(str).str.strip().str.lower()

    d["is_attack"] = d["stage_n"] != "benign"

    d["activity_n"] = d["Activity"].astype(str).str.strip()

    d.loc[~d["is_attack"], "activity_n"] = "Benign"

    d["ts"] = pd.to_datetime(d["Timestamp"], format="%d/%m/%Y %I:%M:%S %p", errors="coerce")

    d = d.rename(columns=RAW2CANON)

    return d

 

 

# ---------------- metrics ----------------

def evaluate(is_attack, flagged, activity, stage, pred=None):

    is_attack = np.asarray(is_attack, bool)

    flagged = np.asarray(flagged, bool)

    nb, na = int((~is_attack).sum()), int(is_attack.sum())

    fp, tp = int((flagged & ~is_attack).sum()), int((flagged & is_attack).sum())

    out = {"benign_flows": nb, "attack_flows": na, "false_alarms": fp, "far": fp / nb if nb else None, "far_ci95": cp(fp, nb),

           "detected": tp, "recall": tp / na if na else None, "recall_ci95": cp(tp, na),

           "precision": tp / (tp + fp) if (tp + fp) else None, "per_stage": {}, "per_activity": {}}

    for key, col in (("per_stage", stage), ("per_activity", activity)):

        col = np.asarray(col)

        for v in sorted(set(col[is_attack])):

            m = is_attack & (col == v)

            k, n = int(flagged[m].sum()), int(m.sum())

            entry = {"n": n, "detected": k, "rate": k / n, "ci95": cp(k, n)}

            if pred is not None:

                vc = pd.Series(np.asarray(pred)[m]).value_counts().head(3)

                entry["labelled_as"] = {str(a): int(b) for a, b in vc.items()}

            out[key][str(v)] = entry

    return out

 

 

def levels(is_attack, anom, pred_closed, pred_unk, activity, stage):

    benign_names = BENIGN_CIC

    return {

        "detector_only": evaluate(is_attack, anom, activity, stage),

        "detector_plus_classifier": evaluate(is_attack, ~np.isin(pred_closed, list(benign_names)), activity, stage, pred_closed),

        "detector_plus_classifier_plus_unknown": evaluate(is_attack, ~np.isin(pred_unk, list(benign_names)), activity, stage, pred_unk),

    }

 

 

# ---------------- models ----------------

def near_dedup(df, feats):

    d = df[feats + ["label"]].copy()

    d[feats] = d[feats].round(1)

    return df.loc[d.drop_duplicates(subset=feats + ["label"]).index]

 

 

def fit_iforest(X):

    return IsolationForest(n_estimators=200, random_state=SEED, n_jobs=-1).fit(X)

 

 

def iscore(model, X):

    return -model.score_samples(X)

 

 

def classify(clf, classes, X, anom, tau):

    n = len(X)

    pred = np.array(["Benign"] * n, dtype=object)

    conf = np.ones(n)

    idx = np.where(anom)[0]

    if len(idx):

        P = clf.predict_proba(X[idx])

        pred[idx] = np.array(classes, dtype=object)[P.argmax(axis=1)]

        conf[idx] = P.max(axis=1)

    unk = pred.copy()

    if tau > 0:

        unk[anom & (conf < tau)] = UNK

    return pred, unk

 

 

# ---------------- printing ----------------

def show(title, res):

    print(f"\n  {title}")

    print(f"    {'pipeline':<40} {'false alarms on DAPT benign':>30} {'attacks caught':>26}")

    for lvl, r in res.items():

        far = f"{100 * r['far']:.1f}% [{100 * r['far_ci95'][0]:.1f}-{100 * r['far_ci95'][1]:.1f}]"

        rec = f"{100 * r['recall']:.1f}% [{100 * r['recall_ci95'][0]:.1f}-{100 * r['recall_ci95'][1]:.1f}]"

        print(f"    {lvl:<40} {far:>30} {rec:>26}")

    last = res["detector_plus_classifier_plus_unknown"]

    print(f"    per activity (full pipeline incl. UNKNOWN):")

    for a, e in sorted(last["per_activity"].items(), key=lambda x: -x[1]["n"]):

        print(f"      {a:<26} n={e['n']:>6,}  caught={100 * e['rate']:5.1f}% [{100 * e['ci95'][0]:.0f}-{100 * e['ci95'][1]:.0f}]  labelled as {e.get('labelled_as', {})}")

 

 

def main():

    ap = argparse.ArgumentParser()

    ap.add_argument("--robust-subset", action="store_true", help="also drop CICFlowMeter-version-sensitive features")

    args = ap.parse_args()

    t0 = time.time()

 

    print("[load] CIC-IDS2017 train (Mon-Wed) and validation (Thu)...")

    tr = pd.read_parquet(os.path.join(PROC, "train.parquet"))

    va = pd.read_parquet(os.path.join(PROC, "val.parquet"))

    print("[load] DAPT2020 ...")

    dp = load_dapt()

    print(f"       {len(dp):,} flows; days: {dp['day'].value_counts().to_dict()}; unparsed timestamps: {int(dp['ts'].isna().sum())}")

 

    from pipeline_consumer import Pipeline

    os.environ["NIF_TAU"] = "0.999"

    pipe = Pipeline()

    cic_feats = list(pipe.anom_features)

    shared = [f for f in cic_feats if f in dp.columns]

    missing = [f for f in cic_feats if f not in dp.columns]

    feats = [f for f in shared if not (args.robust_subset and f in VERSION_SENSITIVE)]

    print(f"[features] model uses {len(cic_feats)}; DAPT2020 has {len(shared)}; missing in DAPT2020: {missing}")

    print(f"[features] E2/E3 use {len(feats)} features" + (" (version-sensitive ones dropped)" if args.robust_subset else ""))

 

    cic_benign = tr[tr["label"].isin(BENIGN_CIC)]

    med = cic_benign[cic_feats].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).median()

 

    # unit sanity check: medians on benign traffic in both datasets

    dmon = dp[(dp["day"] == "monday") & ~dp["is_attack"]]

    print("[sanity] benign medians, CIC vs DAPT2020 (big ratios suggest unit or semantic mismatch):")

    for f in ["duration", "tot_fwd_pkts", "orig_bytes", "flow_bytes_per_s", "flow_iat_mean", "init_fwd_win_bytes"]:

        a = float(med.get(f, np.nan))

        b = float(pd.to_numeric(dmon[f], errors="coerce").replace([np.inf, -np.inf], np.nan).median()) if f in dmon else np.nan

        print(f"    {f:<22} CIC={a:>14.1f}   DAPT={b:>14.1f}")

 

    test = dp[dp["day"].isin(["tuesday", "wednesday", "thursday", "friday"])].reset_index(drop=True)

    y_test, act_test, stg_test = test["is_attack"].values, test["activity_n"].values, test["Stage"].astype(str).str.strip().values

    print(f"[test] DAPT2020 Tue-Fri: {len(test):,} flows, {int(y_test.sum()):,} attack, {int((~y_test).sum()):,} benign")

 

    out = {"features_model": cic_feats, "features_missing_in_dapt": missing, "features_used_e2_e3": feats,

           "robust_subset": args.robust_subset, "test_flows": int(len(test)), "experiments": {}}

 

    # ---------- E1: deployed system, zero-shot ----------

    print("\n[E1] deployed system on DAPT2020 (missing features filled with CIC benign medians)...")

    t1 = test.copy()

    for f in missing:

        t1[f] = med[f]

    t1[cic_feats] = clean(t1[cic_feats], med)

    recs = t1[cic_feats].to_dict(orient="records")

    r_unk = pipe.score_batch(recs)

    os.environ["NIF_TAU"] = "0"

    r_closed = Pipeline().score_batch(recs)

    os.environ["NIF_TAU"] = "0.999"

    anom = np.array([r["is_anomaly"] for r in r_unk])

    e1 = levels(y_test, anom, np.array([r["pred_class"] for r in r_closed], dtype=object),

                np.array([r["pred_class"] for r in r_unk], dtype=object), act_test, stg_test)

    out["experiments"]["E1_deployed_zero_shot"] = e1

    show("E1  deployed system, zero-shot", e1)

 

    # deployed detector's false-alarm rate on Thursday benign = the operating point for E2/E3

    vb = va[va["label"].isin(BENIGN_CIC)]

    vb_recs = clean(vb[cic_feats], med).to_dict(orient="records")

    thursday_far = float(np.mean([r["is_anomaly"] for r in pipe.score_batch(vb_recs)]))

    print(f"\n[operating point] deployed detector flags {100 * thursday_far:.1f}% of CIC Thursday benign; E2/E3 thresholds match this rate")

    out["operating_point_thursday_benign_far"] = thursday_far

 

    # ---------- E2: shared-feature retrain ----------

    print("\n[E2] retraining detector + classifier on CIC Mon-Wed with the shared features...")

    Xb = clean(cic_benign[feats], med[feats]).values

    iso2 = fit_iforest(Xb)

    s_vb = iscore(iso2, clean(vb[feats], med[feats]).values)

    thr2 = float(np.quantile(s_vb, 1 - thursday_far))

 

    trd = near_dedup(tr, feats)

    classes = sorted(trd["label"].unique())

    y = trd["label"].map({c: i for i, c in enumerate(classes)}).astype(int)

    clf = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, random_state=SEED, n_jobs=4, verbosity=0, tree_method="hist")

    clf.fit(clean(trd[feats], med[feats]).values, y, sample_weight=compute_sample_weight("balanced", y))

    print(f"     classifier trained on {len(trd):,} rows, classes={classes}")

 

    Xv = clean(va[feats], med[feats]).values

    yv = ~va["label"].isin(BENIGN_CIC).values

    av = iscore(iso2, Xv) >= thr2

    best_tau, best = 0.0, (-1, 1)

    for tau in [0.0, 0.9, 0.95, 0.99, 0.995, 0.999, 0.9999]:

        _, pu = classify(clf, classes, Xv, av, tau)

        flag = ~np.isin(pu, list(BENIGN_CIC))

        far = float((flag & ~yv).sum() / max((~yv).sum(), 1))

        rec = float((flag & yv).sum() / max(yv.sum(), 1))

        if far <= 0.01 and rec > best[0]:

            best_tau, best = tau, (rec, far)

    print(f"     UNKNOWN threshold chosen on Thursday: tau={best_tau} (Thursday recall {100 * max(best[0], 0):.1f}%, FAR {100 * best[1]:.2f}%)")

    out["e2_tau"] = best_tau

 

    Xt = clean(test[feats], med[feats]).values

    a2 = iscore(iso2, Xt) >= thr2

    pc2, pu2 = classify(clf, classes, Xt, a2, 0.0)[0], classify(clf, classes, Xt, a2, best_tau)[1]

    e2 = levels(y_test, a2, pc2, pu2, act_test, stg_test)

    out["experiments"]["E2_shared_feature_retrain"] = e2

    show("E2  shared-feature retrain, zero-shot", e2)

 

    # ---------- E3: local benign refit ----------

    print("\n[E3] refitting the detector on DAPT2020 Monday benign (70% fit / 30% threshold, by time)...")

    mon = dmon.sort_values("ts", kind="stable")

    cut = int(0.7 * len(mon))

    Xm_fit = clean(mon.iloc[:cut][feats], med[feats]).values

    Xm_cal = clean(mon.iloc[cut:][feats], med[feats]).values

    iso3 = fit_iforest(Xm_fit)

    thr3 = float(np.quantile(iscore(iso3, Xm_cal), 1 - thursday_far))

    a3 = iscore(iso3, Xt) >= thr3

    pc3, pu3 = classify(clf, classes, Xt, a3, 0.0)[0], classify(clf, classes, Xt, a3, best_tau)[1]

    e3 = levels(y_test, a3, pc3, pu3, act_test, stg_test)

    out["experiments"]["E3_local_benign_refit"] = e3

    out["e3_monday_benign_fit_calibrate"] = [int(cut), int(len(mon) - cut)]

    show("E3  detector refitted on local normal traffic", e3)

 

    # ---------- diagnostics ----------

    print("\n[drift] features whose benign distribution differs most between CIC and DAPT2020 (KS statistic, 1 = completely different):")

    rng = np.random.default_rng(SEED)

    cb = cic_benign.sample(min(20000, len(cic_benign)), random_state=SEED)

    ks = []

    for f in feats:

        a = pd.to_numeric(cb[f], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna().values

        b = pd.to_numeric(dmon[f], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna().values

        if len(a) and len(b):

            ks.append((f, float(ks_2samp(a, b).statistic)))

    ks.sort(key=lambda x: -x[1])

    for f, k in ks[:10]:

        print(f"    {f:<26} KS={k:.3f}")

    out["drift_ks_top"] = ks[:20]

    out["drift_ks_median"] = float(np.median([k for _, k in ks])) if ks else None

    print(f"    median KS over {len(ks)} features: {out['drift_ks_median']:.3f}")

 

    ab = test[test["activity_n"].str.contains("Account Bruteforce", case=False, na=False)]

    if len(ab):

        ports = pd.to_numeric(ab["Dst Port"], errors="coerce").value_counts().head(5).to_dict()

        print(f"\n[check] DAPT2020 'Account Bruteforce' destination ports: {ports}  (22/21 would overlap the classifier's SSH/FTP-Patator classes)")

        out["account_bruteforce_dst_ports"] = {str(k): int(v) for k, v in ports.items()}

 

    name = "dapt_transfer_robust.json" if args.robust_subset else "dapt_transfer.json"

    with open(os.path.join(ART, name), "w") as f:

        json.dump(out, f, indent=2, default=str)

    print(f"\n[saved] artifacts/{name}   ({time.time() - t0:.0f}s)")

 

 

if __name__ == "__main__":

    main()
