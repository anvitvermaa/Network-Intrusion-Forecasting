

#!/usr/bin/env python3

"""Honest zero-day evaluation of the FULL pipeline: Stage A + temporal Stage B + UNKNOWN.

 

Fixes the leak in classify.py: the deployed classifier was trained on a stratified

pool of train+val+test, so evaluate.py scored Friday flows the classifier had seen.

Here Stage B is trained on Mon-Wed ONLY (train.parquet).

 

Regimes reported on Friday (test):

  A        : anomaly detector alone

  A+B      : anomaly gate + temporal closed-set classifier

  A+B+UNK  : as above, but anomalous flows with max class prob < tau -> UNKNOWN_ATTACK

tau is selected on Thursday (val) ONLY, whose attacks are also unseen by Stage B.

Friday sweep is reported for transparency but NOT used for selection.

"""

import argparse, json, os, sys, time, warnings

import numpy as np

import pandas as pd

from scipy.stats import beta

from sklearn.utils.class_weight import compute_sample_weight

from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

 

HERE = os.path.dirname(os.path.abspath(__file__))

ROOT = os.path.join(HERE, "..")

PROC = os.path.join(ROOT, "data", "processed")

ART = os.path.join(ROOT, "artifacts")

MODELS = os.path.join(ART, "models")

sys.path.insert(0, os.path.join(ROOT, "streaming"))

from pipeline_consumer import Pipeline

 

BENIGN = ["Benign", "Attempted-relabel-as-Benign"]

UNK = "UNKNOWN_ATTACK"

TAUS = [0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99, 0.995, 0.999, 0.9999]

 

 

def cp_interval(k, n, alpha=0.05):

    """Clopper-Pearson exact binomial 95% CI."""

    if n == 0:

        return [None, None]

    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))

    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))

    return [lo, hi]

 

 

def near_dedup(df, feats):

    """Same logic as classify.py / confirm.py."""

    d = df[feats + ["label"]].copy()

    d[feats] = d[feats].round(1)

    d = d.drop_duplicates(subset=feats + ["label"])

    return df.loc[d.index]

 

 

def train_temporal(feats, retrain):

    mpath = os.path.join(MODELS, "xgb_temporal.json")

    spath = os.path.join(MODELS, "xgb_temporal_spec.json")

    if os.path.exists(mpath) and os.path.exists(spath) and not retrain:

        clf = XGBClassifier()

        clf.load_model(mpath)

        spec = json.load(open(spath))

        print(f"[stage B] loaded existing temporal model ({len(spec['classes'])} classes)")

        return clf, spec["classes"]

    tr = pd.read_parquet(os.path.join(PROC, "train.parquet"))

    n0 = len(tr)

    tr = near_dedup(tr, feats)

    print(f"[stage B] train.parquet dedup {n0:,} -> {len(tr):,}")

    classes = sorted(tr["label"].unique())

    cls2id = {c: i for i, c in enumerate(classes)}

    y = tr["label"].map(cls2id).astype(int)

    sw = compute_sample_weight(class_weight="balanced", y=y)

    clf = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, random_state=42, n_jobs=4, verbosity=0, tree_method="hist")

    print(f"[stage B] training temporal XGBoost on {len(tr):,} rows, {len(classes)} classes: {classes}")

    print("[stage B] (this can take 10-30 min on a laptop)")

    t0 = time.time()

    clf.fit(tr[feats], y, sample_weight=sw)

    print(f"[stage B] trained in {time.time() - t0:.0f}s")

    clf.save_model(mpath)

    with open(spath, "w") as f:

        json.dump({"features": feats, "classes": classes, "class_to_id": cls2id, "split": "temporal_train_only_Mon_Tue_Wed", "note": "Same hyperparams/dedup/weights as classify.py. Trained on train.parquet ONLY. Use for zero-day evaluation."}, f, indent=2)

    print(f"[saved] {mpath}")

    return clf, classes

 

 

def stage_a(pipe, df):

    Xa = pipe.to_matrix.transform(df[pipe.anom_features])

    score = -pipe.iso.decision_function(Xa)

    return score >= pipe.threshold

 

 

def stage_b(clf, classes, df, feats, is_anom):

    n = len(df)

    pred = np.array(["Benign"] * n, dtype=object)

    maxp = np.ones(n)

    idx = np.where(is_anom)[0]

    if len(idx):

        P = clf.predict_proba(df.iloc[idx][feats])

        pred[idx] = np.array(classes, dtype=object)[P.argmax(axis=1)]

        maxp[idx] = P.max(axis=1)

    return pred, maxp

 

 

def apply_tau(pred, maxp, is_anom, tau):

    out = pred.copy()

    out[is_anom & (maxp < tau)] = UNK

    return out

 

 

def detect_metrics(labels, final):

    y_att = ~np.isin(labels, BENIGN)

    p_att = ~np.isin(final, BENIGN)

    tp = int((p_att & y_att).sum())

    fp = int((p_att & ~y_att).sum())

    fn = int((~p_att & y_att).sum())

    tn = int((~p_att & ~y_att).sum())

    prec = tp / (tp + fp) if (tp + fp) else 0.0

    rec = tp / (tp + fn) if (tp + fn) else 0.0

    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    far = fp / (fp + tn) if (fp + tn) else 0.0

    return {"precision": prec, "recall": rec, "f1": f1, "false_alarm_rate": far, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "far_ci95": cp_interval(fp, fp + tn), "recall_ci95": cp_interval(tp, tp + fn), "n_unknown": int((final == UNK).sum())}

 

 

def per_class(labels, final):

    out = {}

    for lbl in sorted(set(labels) - set(BENIGN)):

        m = labels == lbl

        n = int(m.sum())

        f = final[m]

        det = int((~np.isin(f, BENIGN)).sum())

        unk = int((f == UNK).sum())

        top = pd.Series(f).value_counts().head(4)

        out[lbl] = {"n": n, "detected": det, "detection_rate": det / n, "detection_ci95": cp_interval(det, n), "unknown": unk, "unknown_rate": unk / n, "assigned_as": {str(k): int(v) for k, v in top.items()}}

    return out

 

 

def show(name, m):

    lo, hi = m["far_ci95"]

    print(f"  {name:<28} P={m['precision']:.4f}  R={m['recall']:.4f}  F1={m['f1']:.4f}  FAR={m['false_alarm_rate']:.4%}  (FP={m['fp']:,}/{m['fp'] + m['tn']:,}, 95% CI {lo:.4%}-{hi:.4%})  UNK={m.get('n_unknown', 0):,}")

 

 

def show_pc(title, pc):

    print(f"\n  -- {title} --")

    for lbl, r in pc.items():

        lo, hi = r["detection_ci95"]

        print(f"    {lbl:<28} n={r['n']:>6,}  detected={r['detection_rate']:6.1%} (CI {lo:.1%}-{hi:.1%})  UNKNOWN={r['unknown_rate']:6.1%}  assigned_as={r['assigned_as']}")

 

 

def main():

    ap = argparse.ArgumentParser()

    ap.add_argument("--retrain", action="store_true", help="retrain temporal model even if saved")

    ap.add_argument("--far-budget", type=float, default=0.01, help="max val FAR when choosing tau")

    args = ap.parse_args()

 

    print("[load] Stage A (frozen) via Pipeline...")

    pipe = Pipeline()

    feats = pipe.clf_features

    clf, classes = train_temporal(feats, args.retrain)

 

    val = pd.read_parquet(os.path.join(PROC, "val.parquet")).reset_index(drop=True)

    test = pd.read_parquet(os.path.join(PROC, "test.parquet")).reset_index(drop=True)

    vl = val["label"].astype(str).values

    tl = test["label"].astype(str).values

    print(f"[data] val={len(val):,}  test={len(test):,}")

 

    print("[run] Stage A + B on val and test...")

    v_anom = stage_a(pipe, val)

    t_anom = stage_a(pipe, test)

    v_pred, v_maxp = stage_b(clf, classes, val, feats, v_anom)

    t_pred, t_maxp = stage_b(clf, classes, test, feats, t_anom)

 

    # ---- choose tau on VALIDATION only ----

    val_sweep = []

    for tau in TAUS:

        m = detect_metrics(vl, apply_tau(v_pred, v_maxp, v_anom, tau))

        val_sweep.append({"tau": tau, **m})

    feasible = [r for r in val_sweep if r["false_alarm_rate"] <= args.far_budget]

    if feasible:

        chosen = max(feasible, key=lambda r: (r["recall"], -r["false_alarm_rate"]))

    else:

        chosen = min(val_sweep, key=lambda r: r["false_alarm_rate"])

        print(f"[warn] no tau meets val FAR <= {args.far_budget:.2%}; using min-FAR tau")

    tau = chosen["tau"]

 

    print("\n" + "=" * 100)

    print(f"VALIDATION (Thu) SWEEP -- used to choose tau (FAR budget {args.far_budget:.2%})")

    print("=" * 100)

    for r in val_sweep:

        mark = "  <== CHOSEN" if r["tau"] == tau else ""

        print(f"  tau={r['tau']:<7} R={r['recall']:.4f}  FAR={r['false_alarm_rate']:.4%}  UNK={r['n_unknown']:,}{mark}")

 

    # ---- Friday regimes ----

    final_A = np.where(t_anom, "ANOMALY", "Benign").astype(object)

    final_AB = apply_tau(t_pred, t_maxp, t_anom, 0.0)

    final_ABU = apply_tau(t_pred, t_maxp, t_anom, tau)

    m_A = detect_metrics(tl, final_A)

    m_AB = detect_metrics(tl, final_AB)

    m_ABU = detect_metrics(tl, final_ABU)

 

    leaky = None

    ep = os.path.join(ART, "evaluation_results_leaky.json")

    if os.path.exists(ep):

        od = json.load(open(ep))["overall_detection"]

        leaky = dict(od)

        leaky["far_ci95"] = cp_interval(od["fp"], od["fp"] + od["tn"])

        leaky["recall_ci95"] = cp_interval(od["tp"], od["tp"] + od["fn"])

        leaky["n_unknown"] = 0

 

    print("\n" + "=" * 100)

    print("FRIDAY (test) -- FULL PIPELINE, overall attack detection")

    print("=" * 100)

    if leaky:

        show("OLD (leaky stratified B)", leaky)

    show("A only", m_A)

    show("A + temporal B", m_AB)

    show(f"A + temporal B + UNK(t={tau})", m_ABU)

 

    pc_A = per_class(tl, final_A)

    pc_AB = per_class(tl, final_AB)

    pc_ABU = per_class(tl, final_ABU)

    print("\n" + "=" * 100)

    print("FRIDAY per-class (all zero-day for Stage B)")

    print("=" * 100)

    show_pc("A only", pc_A)

    show_pc("A + temporal B", pc_AB)

    show_pc(f"A + temporal B + UNKNOWN (tau={tau})", pc_ABU)

 

    pc_val = per_class(vl, apply_tau(v_pred, v_maxp, v_anom, tau))

    show_pc(f"THURSDAY (val) at chosen tau={tau} -- calibration set", pc_val)

 

    test_sweep = []

    for t in TAUS:

        m = detect_metrics(tl, apply_tau(t_pred, t_maxp, t_anom, t))

        test_sweep.append({"tau": t, **m})

 

    out = {

        "note": "Stage B trained on Mon-Wed only. tau chosen on Thursday only. Friday sweep is report-only.",

        "temporal_classes": classes,

        "far_budget_val": args.far_budget,

        "chosen_tau": tau,

        "val_sweep": val_sweep,

        "test_sweep_REPORT_ONLY": test_sweep,

        "test_overall": {"old_leaky_stratified": leaky, "A_only": m_A, "A_plus_temporalB": m_AB, "A_plus_temporalB_plus_UNKNOWN": m_ABU},

        "test_per_class": {"A_only": pc_A, "A_plus_temporalB": pc_AB, "A_plus_temporalB_plus_UNKNOWN": pc_ABU},

        "val_per_class_at_tau": pc_val,

    }

    with open(os.path.join(ART, "temporal_eval.json"), "w") as f:

        json.dump(out, f, indent=2, default=str)

    print(f"\n[saved] artifacts/temporal_eval.json")

 

 

if __name__ == "__main__":

    main()
