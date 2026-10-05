
#!/usr/bin/env python3

"""Phase 4 PRODUCTION - Live Streamlit dashboard consuming Kafka forecasts."""

import json, threading, time

from collections import deque

import pandas as pd

import streamlit as st

from confluent_kafka import Consumer, KafkaError

 

BOOTSTRAP = "localhost:9092"

TOPIC = "network-flow-forecasts"

MAXLEN = 20000

 

st.set_page_config(page_title="Network Intrusion Forecasting - LIVE", layout="wide")

 

@st.cache_resource

def start_consumer():

    buf = deque(maxlen=MAXLEN)

    lock = threading.Lock()

    def run():

        c = Consumer({

            "bootstrap.servers": BOOTSTRAP,

            "group.id": "nif-dashboard",

            "auto.offset.reset": "latest",

            "enable.auto.commit": True,

        })

        c.subscribe([TOPIC])

        while True:

            msg = c.poll(timeout=1.0)

            if msg is None: continue

            if msg.error():

                continue

            try:

                rec = json.loads(msg.value().decode("utf-8"))

                with lock:

                    buf.append(rec)

            except Exception:

                continue

    t = threading.Thread(target=run, daemon=True)

    t.start()

    return buf, lock

 

buf, lock = start_consumer()

 

st.title("\U0001F6E1 Network Intrusion Forecasting - LIVE Stream")

st.caption("Detect -> Classify -> Forecast  |  consuming Kafka 'network-flow-forecasts' live")

 

st.sidebar.header("Controls")

st.sidebar.write("Start producer.py and stream_pipeline.py to see live data.")

st.sidebar.write(f"Buffer: last {MAXLEN:,} forecasts")

 

with lock:

    rows = list(buf)

df = pd.DataFrame(rows)

 

if df.empty:

    st.warning("Waiting for live forecasts... Start:  (1) producer.py  (2) stream_pipeline.py")

else:

    total = len(df)

    n_anom = int(df["is_anomaly"].sum()) if "is_anomaly" in df else 0

    n_attack = int((df["pred_class"] != "Benign").sum()) if "pred_class" in df else 0

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Flows (live buffer)", f"{total:,}")

    c2.metric("Anomalies flagged", f"{n_anom:,}")

    c3.metric("Attacks classified", f"{n_attack:,}")

    c4.metric("Benign", f"{total - n_attack:,}")

    colA, colB = st.columns(2)

    with colA:

        st.subheader("Attack types (live)")

        if n_attack:

            st.bar_chart(df[df["pred_class"] != "Benign"]["pred_class"].value_counts())

        else:

            st.info("No attacks yet.")

    with colB:

        st.subheader("Kill-chain forecasts (live)")

        if "forecast_next" in df:

            fc = df[df["forecast_next"] != ""]["forecast_next"].value_counts()

            if len(fc): st.bar_chart(fc)

            else: st.info("No forecasts yet.")

    st.subheader("\U0001F6A8 Simulated Firewall Response Log")

    if "forecast_prob" in df:

        risky = df[(df["pred_class"] != "Benign") & (df["forecast_prob"].astype(float) >= 0.6)]

        if len(risky):

            log = risky.tail(15)[["pred_class", "current_stage", "forecast_next", "forecast_prob"]].copy()

            log["ACTION"] = "\U0001F534 BLOCK offending source (simulated)"

            st.dataframe(log, use_container_width=True)

            st.caption(f"{len(risky):,} high-risk forecasts would trigger an automated block.")

        else:

            st.success("No high-risk forecasts requiring a block.")

    st.subheader("Most recent forecasts")

    st.dataframe(df.tail(20), use_container_width=True)

 

time.sleep(2)

st.rerun()

