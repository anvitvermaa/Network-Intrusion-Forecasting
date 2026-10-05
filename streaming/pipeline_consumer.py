#!/usr/bin/env python3
"""Phase 3 (Path B) - Python Streaming Consumer running Stage A -> B -> C.

Reads flow messages from Kafka, applies the FROZEN Phase-1 models per record:
  Stage A: IsolationForest anomaly gate (+ ZAT DataFrameToMatrix + threshold)
  Stage B: XGBoost classifier (only on anomalous flows)
  Stage C: HMM kill-chain forecast (next stage from current)
Measures end-to-end latency (now - _produced_at) per record; reports p50/p95/p99.

CRITICAL: each model gets features in ITS OWN order (anomaly and classifier use
the same 82 features but in different order -- feeding a fixed order would
scramble one model). We build inputs from each spec's own 'features' list.
"""
import argparse, contextlib, io, json, os, time
import numpy as np
import pandas as pd
import joblib
import warnings; warnings.filterwarnings("ignore")
from confluent_kafka import Consumer, KafkaError
from xgboost import XGBClassifier
from zat.dataframe_to_matrix import DataFrameToMatrix

HERE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(HERE, "..", "artifacts", "models")
TOPIC = "network-flow-data"
BOOTSTRAP = "localhost:9092"
DEFAULT_TAU = 0.999  # chosen on VAL (Thursday) in research/temporal_pipeline.py
UNKNOWN_LABEL = "UNKNOWN_ATTACK"

# label -> kill-chain stage (same mapping used in Phase 0/C)
LABEL_TO_STAGE = {
    "Benign": "NONE", "Attempted-relabel-as-Benign": "NONE",
    "FTP-Patator": "INITIAL_COMPROMISE", "SSH-Patator": "INITIAL_COMPROMISE",
    "DoS Hulk": "EXFILTRATION", "DoS GoldenEye": "EXFILTRATION",
    "DoS Slowloris": "EXFILTRATION", "DoS Slowhttptest": "EXFILTRATION",
    "DDoS": "EXFILTRATION", "Heartbleed": "INITIAL_COMPROMISE",
    "Web Attack - Brute Force": "INITIAL_COMPROMISE",
    "Web Attack - XSS": "INITIAL_COMPROMISE",
    "Web Attack - SQL Injection": "INITIAL_COMPROMISE",
    "Infiltration": "LATERAL_MOVEMENT", "Infiltration - Portscan": "LATERAL_MOVEMENT",
    "Botnet": "LATERAL_MOVEMENT", "Portscan": "RECON",
    "UNKNOWN_ATTACK": "UNKNOWN",
}


class Pipeline:
    """Loads all three frozen models once; scores a batch of flow dicts."""
    def __init__(self, model=None):
        self.model = model or os.environ.get("NIF_MODEL", "temporal")
        self.tau = 0.0
        # Stage A
        self.iso = joblib.load(os.path.join(MODELS, "isoforest.joblib"))
        self.to_matrix = joblib.load(os.path.join(MODELS, "dataframe_to_matrix.joblib"))
        acfg = json.load(open(os.path.join(MODELS, "anomaly_config.json")))
        self.anom_features = acfg["features"]          # anomaly's OWN order
        self.threshold = acfg["threshold"]
        # Stage B
        self.xgb = XGBClassifier()
        self.xgb.load_model(os.path.join(MODELS, "xgb_classifier.json"))
        cspec = json.load(open(os.path.join(MODELS, "classifier_spec.json")))
        self.clf_features = cspec["features"]          # classifier's OWN order
        self.classes = cspec["classes"]
        if self.model == "temporal":
            self.xgb = XGBClassifier()
            self.xgb.load_model(os.path.join(MODELS, "xgb_temporal.json"))
            tspec = json.load(open(os.path.join(MODELS, "xgb_temporal_spec.json")))
            self.clf_features = tspec["features"]
            self.classes = tspec["classes"]
            self.tau = float(os.environ.get("NIF_TAU", DEFAULT_TAU))
        print(f"[pipeline] Stage B model={self.model} classes={len(self.classes)} tau={self.tau}")
        # Stage C
        npz = np.load(os.path.join(MODELS, "hmm_forecaster.npz"), allow_pickle=True)
        self.transmat = npz["transmat"]
        self.stages = list(npz["stages"])
        self.sidx = {s: i for i, s in enumerate(self.stages)}

    def score_batch(self, records):
        """records: list of flow dicts. Returns list of result dicts."""
        df = pd.DataFrame(records)
        n = len(df)

        # --- Stage A: anomaly (features in ANOMALY order) ---
        with contextlib.redirect_stdout(io.StringIO()):
            Xa = self.to_matrix.transform(df[self.anom_features])
        anom_score = -self.iso.decision_function(Xa)
        is_anom = anom_score >= self.threshold

        # defaults: non-anomalous -> Benign, stage NONE, no forecast
        pred_class = np.array(["Benign"] * n, dtype=object)
        cur_stage = np.array(["NONE"] * n, dtype=object)
        forecast = np.array([""] * n, dtype=object)
        fc_prob = np.zeros(n)
        clf_conf = np.zeros(n)

        # --- Stage B: classify ONLY anomalous rows (features in CLF order) ---
        idx = np.where(is_anom)[0]
        if len(idx):
            Xc = df.iloc[idx][self.clf_features].values
            P = self.xgb.predict_proba(Xc)
            ids = P.argmax(axis=1)
            confs = P.max(axis=1)
            names = [self.classes[i] for i in ids]
            if self.tau > 0:
                names = [UNKNOWN_LABEL if confs[k] < self.tau else names[k] for k in range(len(names))]
            for k, row_i in enumerate(idx):
                clf_conf[row_i] = float(confs[k])
            for k, row_i in enumerate(idx):
                pred_class[row_i] = names[k]
                # --- Stage C: map class -> stage -> HMM next-stage forecast ---
                stg = LABEL_TO_STAGE.get(names[k], "NONE")
                cur_stage[row_i] = stg
                if stg == "UNKNOWN":
                    continue
                si = self.sidx.get(stg, 0)
                row = self.transmat[si]
                nxt = int(np.argmax(row))
                forecast[row_i] = self.stages[nxt]
                fc_prob[row_i] = float(row[nxt])

        # ground truth (from message, if present) for the correctness gate
        true_label = df["label"].values if "label" in df.columns else [None] * n
        results = []
        for i in range(n):
            results.append({
                "true_label": true_label[i],
                "is_anomaly": bool(is_anom[i]),
                "pred_class": pred_class[i],
                "current_stage": cur_stage[i],
                "forecast_next": forecast[i],
                "forecast_prob": round(fc_prob[i], 3),
                "clf_confidence": round(float(clf_conf[i]), 4),
            })
        return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=5000, help="records to process")
    ap.add_argument("--batch", type=int, default=100, help="batch size for scoring")
    ap.add_argument("--from-start", action="store_true")
    ap.add_argument("--group", default="nif-pipeline")
    ap.add_argument("--show", type=int, default=10, help="sample results to print")
    args = ap.parse_args()

    print("[load] loading frozen Phase-1 models (A+B+C)...")
    pipe = Pipeline()
    print(f"[load] anomaly feats={len(pipe.anom_features)}, "
          f"classifier feats={len(pipe.clf_features)}, stages={pipe.stages}")

    consumer = Consumer({
        "bootstrap.servers": BOOTSTRAP, "group.id": args.group,
        "auto.offset.reset": "earliest" if args.from_start else "latest",
        "enable.auto.commit": True,
    })
    consumer.subscribe([TOPIC])
    print(f"[consumer] processing up to {args.count} records "
          f"(batch={args.batch})...")

    latencies = []          # end-to-end ms per record
    processed = 0
    n_anom = 0
    printed = 0
    buf = []
    t_start = time.time()

    try:
        while processed < args.count:
            msg = consumer.poll(timeout=5.0)
            if msg is None:
                if buf:  # flush partial batch
                    pass
                else:
                    print("   (waiting... run producer in another terminal)")
                    continue
            elif msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    print(f"[err] {msg.error()}")
                continue
            else:
                rec = json.loads(msg.value().decode("utf-8"))
                buf.append(rec)

            # score a full batch (or flush if buffer big enough)
            if len(buf) >= args.batch:
                now_ms = time.time() * 1000.0
                results = pipe.score_batch(buf)
                fout = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "forecasts.jsonl"), "a")
                for rec, res in zip(buf, results):
                    fout.write(json.dumps({k: (float(v) if hasattr(v,"item") else v) for k,v in res.items()}) + "\n")
                    processed += 1
                    if res["is_anomaly"]:
                        n_anom += 1
                    # latency from produced timestamp
                    prod = rec.get("_produced_at")
                    if prod is not None:
                        latencies.append(now_ms - float(prod))
                    if printed < args.show and res["is_anomaly"]:
                        print(f"   [{processed}] true={res['true_label']} "
                              f"pred={res['pred_class']} stage={res['current_stage']} "
                              f"-> forecast={res['forecast_next']} "
                              f"({res['forecast_prob']:.0%})")
                        printed += 1
                buf = []
    finally:
        consumer.close()

    elapsed = time.time() - t_start
    print(f"\n[done] processed {processed:,} records in {elapsed:.1f}s "
          f"({processed/elapsed:.0f} rec/s), {n_anom:,} flagged anomalous")
    if latencies:
        lat = np.array(latencies)   
        print(f"\n[LATENCY end-to-end ms]  p50={np.percentile(lat,50):.1f}  "
              f"p95={np.percentile(lat,95):.1f}  p99={np.percentile(lat,99):.1f}  "
              f"max={lat.max():.1f}")
        print("(note: latency includes producer->kafka->consumer + inference)")
    else:
        print("[warn] no _produced_at timestamps found (use the timestamped producer)")


if __name__ == "__main__":
    main()
