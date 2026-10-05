
#!/usr/bin/env python3

"""PRODUCTION - Data Drift Monitoring (Evidently) + Model Registry (MLflow).

Drift detection is production ML's #1 requirement: detect when live traffic has

drifted from the training baseline so the model can be retrained before it rots.

MLflow provides governance: versioned models, metrics history, audit trail."""

import json, os, warnings

warnings.filterwarnings("ignore")

import numpy as np

import pandas as pd

from evidently import Report, Dataset, DataDefinition

from evidently.presets import DataDriftPreset

import mlflow

 

HERE = os.path.dirname(os.path.abspath(__file__))

PROC = os.path.join(HERE, "..", "data", "processed")

ART = os.path.join(HERE, "..", "artifacts")

MODELS = os.path.join(ART, "models")

MON = ["duration", "orig_bytes", "resp_bytes", "tot_fwd_pkts", "tot_bwd_pkts",

       "flow_bytes_per_s", "flow_pkts_per_s"]

 

 

def run_drift():

    print("="*64)

    print("PART 1 - DATA DRIFT MONITORING (Evidently, K-S test)")

    print("="*64)

    train = pd.read_parquet(os.path.join(PROC, "train.parquet"))

    test = pd.read_parquet(os.path.join(PROC, "test.parquet"))

    feats = [c for c in MON if c in train.columns]

    ref = train[train["label"] == "Benign"][feats].sample(

        n=min(10000, int((train["label"] == "Benign").sum())), random_state=42)

    cur = test[feats].sample(n=min(10000, len(test)), random_state=42)

    dd = DataDefinition(numerical_columns=feats)

    report = Report(metrics=[DataDriftPreset()])

    result = report.run(

        reference_data=Dataset.from_pandas(ref, data_definition=dd),

        current_data=Dataset.from_pandas(cur, data_definition=dd))

    d = result.dict()

    drifted_count = 0; drift_share = 0.0; per_col = {}

    for m in d["metrics"]:

        name = m.get("metric_name", "")

        if "DriftedColumnsCount" in name:

            drifted_count = int(m["value"]["count"]); drift_share = float(m["value"]["share"])

        elif "ValueDrift" in name:

            per_col[m["config"]["column"]] = float(m["value"])

    print(f"\n  Reference: {len(ref):,} benign training flows (baseline)")

    print(f"  Current:   {len(cur):,} live test flows")

    print(f"\n  {'Feature':<22} {'K-S p-value':>12} {'Drifted?':>10}")

    for col, p in per_col.items():

        print(f"  {col:<22} {p:>12.2e} {'YES' if p < 0.05 else 'no':>10}")

    print(f"\n  Drifted columns: {drifted_count}/{len(feats)} (share = {drift_share:.0%})")

    ALERT = drift_share > 0.5

    if ALERT:

        print(f"  >>> DRIFT ALERT: share {drift_share:.0%} > 50% threshold.")

        print(f"  >>> Production action: trigger model RETRAINING.")

    else:

        print(f"  >>> No significant drift (share {drift_share:.0%} <= 50%).")

    try:

        result.save_html(os.path.join(ART, "drift_report.html"))

        print(f"\n  [saved] artifacts/drift_report.html (open in browser)")

    except Exception as e:

        print(f"  [note] HTML save skipped: {e}")

    with open(os.path.join(ART, "drift_results.json"), "w") as f:

        json.dump({"drifted_count": drifted_count, "drift_share": drift_share,

                   "per_column_pvalue": per_col, "alert": ALERT, "threshold": 0.5,

                   "method": "Kolmogorov-Smirnov (Evidently)"}, f, indent=2)

    return drift_share, ALERT

 

 

def run_mlflow(drift_share, alert):

    print("\n" + "="*64)

    print("PART 2 - MODEL REGISTRY + GOVERNANCE (MLflow)")

    print("="*64)

    db = os.path.abspath(os.path.join(ART, "mlflow.db"))

    mlflow.set_tracking_uri(f"sqlite:///{db}")

    mlflow.set_experiment("network-intrusion-forecasting")

    with mlflow.start_run(run_name="production-eval"):

        mlflow.log_param("pipeline", "IsolationForest -> XGBoost -> HMM")

        mlflow.log_param("dataset", "corrected CIC-IDS2017 (Distrinet)")

        mlflow.log_param("split", "temporal (zero-day) + stratified")

        for fname in ["evaluation_results.json", "forecast_eval.json", "drift_results.json"]:

            p = os.path.join(ART, fname)

            if os.path.exists(p):

                mlflow.log_artifact(p)

        mlflow.log_metric("drift_share", drift_share)

        mlflow.log_metric("drift_alert", 1 if alert else 0)

        for mf in ["xgb_classifier.json", "isoforest.joblib", "hmm_forecaster.npz", "classifier_spec.json"]:

            p = os.path.join(MODELS, mf)

            if os.path.exists(p):

                mlflow.log_artifact(p, artifact_path="models")

        run_id = mlflow.active_run().info.run_id

        print(f"\n  MLflow run logged: {run_id}")

        print(f"  Backend: sqlite:///{db}")

        print(f"  Logged: pipeline config, eval + drift metrics, model artifacts.")

    print(f"\n  >>> Governance: versioned models, audit trail, metrics history.")

    print(f"  >>> View UI:  mlflow ui --backend-store-uri sqlite:///{db}")

 

 

def main():

    share, alert = run_drift()

    run_mlflow(share, alert)

    print("\n[done] Drift monitoring + MLflow registry complete.")

 

 

if __name__ == "__main__":

    main()

