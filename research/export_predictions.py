
#!/usr/bin/env python3

"""Export this project's own predictions in the format research/reality_check.py reads.

 

Writes to artifacts/:

  rc_friday.parquet      CIC-IDS2017 Friday (unseen attacks), deployed pipeline: label, flag, pred, score

  rc_dapt.parquet        DAPT2020 Tue-Fri, deployed pipeline as-is (E1): label, flag, pred, score, timestamp

  rc_dapt_stages.csv     DAPT2020 real attacker stage sequences: episode, order, stage

  rc_cic_stages.csv      CIC-IDS2017 weekly attack schedule as one stage sequence: episode, order, stage

"""

import contextlib

import io

import os

import sys

import numpy as np

import pandas as pd

 

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

import dapt_transfer as T

 

DAPT_STAGE = {"reconnaissance": "RECON", "establish foothold": "INITIAL_COMPROMISE",

              "lateral movement": "LATERAL_MOVEMENT", "data exfiltration": "EXFILTRATION"}

 

 

def score_frame(pipe, X):

    """Deployed pipeline outputs plus the detector's anomaly score, for a frame with the model's features."""

    with contextlib.redirect_stdout(io.StringIO()):

        Xa = pipe.to_matrix.transform(X[pipe.anom_features])

    score = -pipe.iso.decision_function(Xa)

    res = pipe.score_batch(X.to_dict(orient="records"))

    return (np.array([r["is_anomaly"] for r in res], dtype=int),

            np.array([r["pred_class"] for r in res], dtype=object), score)

 

 

def main():

    from pipeline_consumer import Pipeline

    os.environ["NIF_TAU"] = "0.999"

    pipe = Pipeline()

    feats = list(pipe.anom_features)

    tr = pd.read_parquet(os.path.join(T.PROC, "train.parquet"))

    med = tr[tr["label"].isin(T.BENIGN_CIC)][feats].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).median()

 

    # CIC-IDS2017 Friday

    te = pd.read_parquet(os.path.join(T.PROC, "test.parquet")).reset_index(drop=True)

    flag, pred, score = score_frame(pipe, T.clean(te[feats], med))

    pd.DataFrame({"label": te["label"].astype(str).values, "flag": flag, "pred": pred, "score": score}).to_parquet(os.path.join(T.ART, "rc_friday.parquet"))

    print(f"[saved] artifacts/rc_friday.parquet  ({len(te):,} flows)")

 

    # DAPT2020 Tue-Fri, deployed as-is

    dp = T.load_dapt()

    test = dp[dp["day"].isin(["tuesday", "wednesday", "thursday", "friday"])].reset_index(drop=True)

    X = test.copy()

    for f in feats:

        if f not in X.columns:

            X[f] = med[f]

    X = T.clean(X[feats], med)

    flag, pred, score = score_frame(pipe, X)

    pd.DataFrame({"label": test["activity_n"].values, "flag": flag, "pred": pred, "score": score,

                  "timestamp": test["ts"].values}).to_parquet(os.path.join(T.ART, "rc_dapt.parquet"))

    print(f"[saved] artifacts/rc_dapt.parquet  ({len(test):,} flows)")

 

    # DAPT2020 real attacker stage sequences

    atk = dp[dp["is_attack"] & dp["ts"].notna()].copy()

    atk["stage"] = atk["Stage"].astype(str).str.strip().str.lower().map(DAPT_STAGE)

    atk = atk[atk["stage"].notna()].sort_values(["Src IP", "ts"], kind="stable")

    atk["order"] = atk.groupby("Src IP").cumcount()

    atk.rename(columns={"Src IP": "episode"})[["episode", "order", "stage"]].to_csv(os.path.join(T.ART, "rc_dapt_stages.csv"), index=False)

    print(f"[saved] artifacts/rc_dapt_stages.csv  ({atk['Src IP'].nunique()} attacker sources)")

 

    # CIC-IDS2017 weekly schedule

    tl = pd.read_csv(os.path.join(T.ART, "attack_timeline.csv"))

    if "onset_ts" in tl.columns:

        tl = tl.assign(_ts=pd.to_datetime(tl["onset_ts"], utc=True, errors="coerce")).sort_values("_ts", kind="stable")

    pd.DataFrame({"episode": "cic_week", "order": range(len(tl)), "stage": tl["kill_chain_stage"].astype(str).values}).to_csv(

        os.path.join(T.ART, "rc_cic_stages.csv"), index=False)

    print(f"[saved] artifacts/rc_cic_stages.csv  ({len(tl)} scheduled attacks)")

 

 

if __name__ == "__main__":

    main()



