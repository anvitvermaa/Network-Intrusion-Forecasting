#!/usr/bin/env python3

"""Generate forecasts.jsonl by running the full pipeline on test.parquet.

Simple, robust, no Kafka needed — feeds the Phase 4 dashboard."""

import json, os

import pandas as pd

from pipeline_consumer import Pipeline

 

HERE = os.path.dirname(os.path.abspath(__file__))

PROC = os.path.join(HERE, "..", "data", "processed")

OUT = os.path.join(HERE, "forecasts.jsonl")

 

N = 20000  # how many flows to score for the dashboard (raise/lower as you like)

 

print("[load] loading models + test data...")

pipe = Pipeline()


_full = pd.read_parquet(os.path.join(PROC, "test.parquet"))

df = _full.sample(n=min(N, len(_full)), random_state=42).reset_index(drop=True)

records = df.to_dict(orient="records")

 

print(f"[run] scoring {len(records):,} flows through Detect->Classify->Forecast...")

results = pipe.score_batch(records)

 

with open(OUT, "w") as f:

    for res in results:

        clean = {k: (v.item() if hasattr(v, "item") else v) for k, v in res.items()}



        f.write(json.dumps(clean) + "\n")

 

n_anom = sum(r["is_anomaly"] for r in results)

n_atk = sum(r["pred_class"] != "Benign" for r in results)

print(f"[done] wrote {len(results):,} forecasts to forecasts.jsonl")

print(f"       {n_anom:,} anomalies, {n_atk:,} classified attacks")
