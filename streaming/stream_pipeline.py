
#!/usr/bin/env python3

"""Phase 3 PRODUCTION - Streaming pipeline: consume flows, run A->B->C, produce forecasts."""

import json, os, time, signal

import numpy as np

import pandas as pd

import joblib

import warnings; warnings.filterwarnings("ignore")

from confluent_kafka import Consumer, Producer, KafkaError

from xgboost import XGBClassifier

from zat.dataframe_to_matrix import DataFrameToMatrix

 

HERE = os.path.dirname(os.path.abspath(__file__))

MODELS = os.path.join(HERE, "..", "artifacts", "models")

BOOTSTRAP = "localhost:9092"

IN_TOPIC = "network-flow-data"

OUT_TOPIC = "network-flow-forecasts"

 

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

}

 

 

class Pipeline:

    def __init__(self):

        self.iso = joblib.load(os.path.join(MODELS, "isoforest.joblib"))

        self.to_matrix = joblib.load(os.path.join(MODELS, "dataframe_to_matrix.joblib"))

        acfg = json.load(open(os.path.join(MODELS, "anomaly_config.json")))

        self.anom_features = acfg["features"]

        self.threshold = acfg["threshold"]

        self.xgb = XGBClassifier()

        self.xgb.load_model(os.path.join(MODELS, "xgb_classifier.json"))

        cspec = json.load(open(os.path.join(MODELS, "classifier_spec.json")))

        self.clf_features = cspec["features"]

        self.classes = cspec["classes"]

        npz = np.load(os.path.join(MODELS, "hmm_forecaster.npz"), allow_pickle=True)

        self.transmat = npz["transmat"]

        self.stages = list(npz["stages"])

        self.sidx = {s: i for i, s in enumerate(self.stages)}

 

    def score_batch(self, records):

        df = pd.DataFrame(records)

        n = len(df)

        Xa = self.to_matrix.transform(df[self.anom_features])

        is_anom = (-self.iso.decision_function(Xa)) >= self.threshold

        pred_class = np.array(["Benign"] * n, dtype=object)

        cur_stage = np.array(["NONE"] * n, dtype=object)

        forecast = np.array([""] * n, dtype=object)

        fc_prob = np.zeros(n)

        idx = np.where(is_anom)[0]

        if len(idx):

            Xc = df.iloc[idx][self.clf_features].values

            ids = self.xgb.predict(Xc)

            names = [self.classes[i] for i in ids]

            for k, ri in enumerate(idx):

                pred_class[ri] = names[k]

                stg = LABEL_TO_STAGE.get(names[k], "NONE")

                cur_stage[ri] = stg

                si = self.sidx.get(stg, 0)

                row = self.transmat[si]

                nxt = int(np.argmax(row))

                forecast[ri] = self.stages[nxt]

                fc_prob[ri] = float(row[nxt])

        tl = df["label"].values if "label" in df.columns else [None] * n

        out = []

        for i in range(n):

            out.append({

                "true_label": tl[i] if tl[i] is None else str(tl[i]),

                "is_anomaly": bool(is_anom[i]),

                "pred_class": str(pred_class[i]),

                "current_stage": str(cur_stage[i]),

                "forecast_next": str(forecast[i]),

                "forecast_prob": round(float(fc_prob[i]), 3),

            })

        return out

 

 

_run = True

def _stop(*a):

    global _run; _run = False

    print("\n[stopping] finishing current batch...")

 

 

def main():

    signal.signal(signal.SIGINT, _stop)

    print("[load] loading frozen Phase-1 models (A+B+C)...")

    pipe = Pipeline()

    print(f"[load] anomaly feats={len(pipe.anom_features)}, clf feats={len(pipe.clf_features)}")

 

    consumer = Consumer({

        "bootstrap.servers": BOOTSTRAP,

        "group.id": "nif-stream-pipeline",

        "auto.offset.reset": "earliest",

        "enable.auto.commit": False,

    })

    consumer.subscribe([IN_TOPIC])

 

    producer = Producer({

        "bootstrap.servers": BOOTSTRAP,

        "acks": "all",

        "enable.idempotence": True,

        "linger.ms": 5,

    })

 

    print(f"[stream] consuming '{IN_TOPIC}' -> scoring -> producing '{OUT_TOPIC}'")

    print("[stream] press Ctrl+C to stop.\n")

 

    processed = 0; n_anom = 0; n_attack = 0

    buf = []

    BATCH = 100

    t0 = time.time()

 

    def flush():

        nonlocal processed, n_anom, n_attack, buf

        if not buf: return

        results = pipe.score_batch(buf)

        for res in results:

            producer.produce(OUT_TOPIC, value=json.dumps(res).encode("utf-8"))

            processed += 1

            if res["is_anomaly"]: n_anom += 1

            if res["pred_class"] != "Benign": n_attack += 1

        producer.poll(0)

        consumer.commit(asynchronous=False)

        buf = []

 

    while _run:

        msg = consumer.poll(timeout=1.0)

        if msg is None:

            if buf: flush()

            continue

        if msg.error():

            if msg.error().code() != KafkaError._PARTITION_EOF:

                print(f"[err] {msg.error()}")

            continue

        try:

            rec = json.loads(msg.value().decode("utf-8"))

        except Exception:

            continue

        buf.append(rec)

        if len(buf) >= BATCH:

            flush()

            if processed % 2000 == 0:

                el = time.time() - t0

                print(f"   processed {processed:,} | {n_anom:,} anom | {n_attack:,} attacks | {processed/el:.0f} rec/s")

 

    flush()

    producer.flush(10)

    consumer.close()

    el = time.time() - t0

    print(f"\n[done] processed {processed:,} records in {el:.1f}s ({processed/max(el,0.1):.0f} rec/s); {n_anom:,} anomalies, {n_attack:,} attacks")

    print(f"[done] forecasts published to topic '{OUT_TOPIC}'")

 

 

if __name__ == "__main__":

    main()

