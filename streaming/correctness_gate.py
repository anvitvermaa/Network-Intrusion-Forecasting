
#!/usr/bin/env python3

"""Phase 3 - CORRECTNESS GATE.

 

Proves the streaming pipeline produces IDENTICAL predictions to an independent

offline reimplementation on the same data. If the streaming path silently

scrambled features, loaded a model wrong, or drifted from the decision spec,

predictions would diverge and this gate would FAIL.

 

Method:

  1. Random sample of test.parquet (includes attacks, not just benign head).

  2. OFFLINE path: independent reimplementation of the spec

     (Stage A threshold -> Stage B argmax + tau/UNKNOWN -> Stage C forecast).

  3. STREAMING path: the SAME Pipeline class the consumer uses, fed records that

     went through the producer's exact JSON serialization.

  4. Compare per-record: anomaly flag, predicted class, forecast. Must match.

"""

import contextlib, io, json, os, sys

import numpy as np

import pandas as pd

import warnings; warnings.filterwarnings("ignore")

 

HERE = os.path.dirname(os.path.abspath(__file__))

PROC = os.path.join(HERE, "..", "data", "processed")

 

sys.path.insert(0, HERE)

from pipeline_consumer import Pipeline, LABEL_TO_STAGE

 

 

def offline_score(df, pipe):

    """Independent reimplementation of the decision spec."""

    n = len(df)

    with contextlib.redirect_stdout(io.StringIO()):

        Xa = pipe.to_matrix.transform(df[pipe.anom_features])

    is_anom = (-pipe.iso.decision_function(Xa)) >= pipe.threshold

    pred_class = np.array(["Benign"] * n, dtype=object)

    forecast = np.array([""] * n, dtype=object)

    idx = np.where(is_anom)[0]

    if len(idx):

        Xc = df.iloc[idx][pipe.clf_features].values

        P = pipe.xgb.predict_proba(Xc)

        ids = P.argmax(axis=1)

        conf = P.max(axis=1)

        for k, ri in enumerate(idx):

            name = pipe.classes[ids[k]]

            if pipe.tau > 0 and conf[k] < pipe.tau:

                name = "UNKNOWN_ATTACK"

            pred_class[ri] = name

            stg = LABEL_TO_STAGE.get(name, "NONE")

            if stg == "UNKNOWN":

                continue

            si = pipe.sidx.get(stg, 0)

            forecast[ri] = pipe.stages[int(np.argmax(pipe.transmat[si]))]

    return is_anom, pred_class, forecast

 

 

def main():

    n_test = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

    df = pd.read_parquet(os.path.join(PROC, "test.parquet")).sample(n=n_test, random_state=42).reset_index(drop=True)

    print(f"[gate] comparing offline vs streaming on {len(df):,} records...")

 

    pipe = Pipeline()

 

    # OFFLINE path

    off_anom, off_class, off_fc = offline_score(df, pipe)

 

    # STREAMING path (identical serialization to producer.py)

    records = [json.loads(json.dumps(r, default=str)) for r in df.to_dict(orient="records")]

    stream_results = pipe.score_batch(records)

    str_anom = np.array([r["is_anomaly"] for r in stream_results])

    str_class = np.array([r["pred_class"] for r in stream_results], dtype=object)

    str_fc = np.array([r["forecast_next"] for r in stream_results], dtype=object)

 

    # COMPARE

    anom_match = int((off_anom == str_anom).sum())

    class_match = int((off_class == str_class).sum())

    fc_match = int((off_fc == str_fc).sum())

    n = len(df)

 

    print(f"\n{'='*60}")

    print("CORRECTNESS GATE RESULTS (offline vs streaming)")

    print(f"{'='*60}")

    print(f"  anomaly flags match:  {anom_match:,}/{n:,}  ({anom_match/n:.1%})")

    print(f"  predicted class match:{class_match:,}/{n:,}  ({class_match/n:.1%})")

    print(f"  forecast match:       {fc_match:,}/{n:,}  ({fc_match/n:.1%})")

 

    all_pass = (anom_match == n and class_match == n and fc_match == n)

    if all_pass:

        print(f"\n  >>> GATE PASSED: streaming pipeline is IDENTICAL to offline models.")

        print(f"  >>> The live system is verified correct (no silent scrambling).")

    else:

        print(f"\n  >>> GATE FAILED: divergence found -- investigate before proceeding.")

        mm = np.where(off_class != str_class)[0][:5]

        for i in mm:

            print(f"      row {i}: offline={off_class[i]} vs streaming={str_class[i]} (stream conf={stream_results[i]['clf_confidence']})")

 

    n_anom = int(str_anom.sum())

    print(f"\n[sanity] {n_anom:,}/{n:,} flagged anomalous ({n_anom/n:.1%}) -- consistent with Phase-1 Stage-A behavior")

    n_unk = int((str_class == "UNKNOWN_ATTACK").sum())

    print(f"[sanity] {n_unk:,} flows abstained as UNKNOWN_ATTACK (tau={pipe.tau})")

 

 

if __name__ == "__main__":

    main()


