#!/usr/bin/env python3

"""Phase 4 - Live Forecast Dashboard (Streamlit, file-based). Run: streamlit run dashboard.py"""

import json, os, time

import pandas as pd

import streamlit as st

 

HERE = os.path.dirname(os.path.abspath(__file__))

FORECASTS = os.path.join(HERE, "forecasts.jsonl")

 

st.set_page_config(page_title="Network Intrusion Forecasting", layout="wide")

st.title("🛡 Network Intrusion Forecasting — Live Dashboard")

st.caption("Detect → Classify → Forecast   |   reading forecasts.jsonl")

 

refresh = st.sidebar.checkbox("Auto-refresh (2s)", value=True)

st.sidebar.write("Run the pipeline consumer to populate data.")

 

def load():

    if not os.path.exists(FORECASTS):

        return pd.DataFrame()

    rows = []

    with open(FORECASTS) as f:

        for line in f:

            line = line.strip()

            if line:

                try: rows.append(json.loads(line))

                except: pass

    return pd.DataFrame(rows)

 

df = load()

 

if df.empty:

    st.warning("No forecasts yet. Start the pipeline consumer (it appends to forecasts.jsonl).")

else:

    total = len(df)

    n_anom = int(df["is_anomaly"].sum()) if "is_anomaly" in df else 0

    n_attack = int((df["pred_class"] != "Benign").sum()) if "pred_class" in df else 0

 

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Flows processed", f"{total:,}")

    c2.metric("Anomalies flagged", f"{n_anom:,}")

    c3.metric("Attacks classified", f"{n_attack:,}")

    c4.metric("Benign", f"{total - n_attack:,}")

 

    st.subheader("Attack types detected")

    if n_attack:

        atk = df[df["pred_class"] != "Benign"]["pred_class"].value_counts()

        st.bar_chart(atk)

    else:

        st.info("No attacks classified yet.")

 

    st.subheader("Kill-chain stage forecasts")

    if "forecast_next" in df:

        fc = df[df["forecast_next"] != ""]["forecast_next"].value_counts()

        if len(fc): st.bar_chart(fc)

        else: st.info("No forecasts yet.")

 

    st.subheader("🚨 Simulated Firewall Response Log")

    if "forecast_prob" in df:

        risky = df[(df["pred_class"] != "Benign") & (df["forecast_prob"].astype(float) >= 0.6)]

        if len(risky):

            log = risky.tail(15)[["pred_class","current_stage","forecast_next","forecast_prob"]].copy()

            log["ACTION"] = "🔴 BLOCK offending source (simulated)"

            st.dataframe(log, use_container_width=True)

            st.caption(f"{len(risky):,} high-risk forecasts would trigger an automated block.")

        else:

            st.success("No high-risk forecasts requiring a block.")

 

    st.subheader("Recent forecasts")

    st.dataframe(df.tail(20), use_container_width=True)

 

if refresh:

    time.sleep(2)

    st.rerun()
