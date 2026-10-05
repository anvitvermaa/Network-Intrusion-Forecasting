

#!/usr/bin/env python3

"""Inspect DAPT2020 flow CSVs: column names per file, stage labels, timestamps, attacker IPs."""

import glob

import os

import pandas as pd

 

FILES = sorted(glob.glob(os.path.join("data", "raw", "dapt2020", "*.csv")))

WANT = {"timestamp": "Timestamp", "src ip": "Src IP", "dst ip": "Dst IP", "activity": "Activity", "stage": "Stage"}

 

 

def norm(c):

    return " ".join(str(c).strip().lower().replace("_", " ").split())

 

 

frames = []

for p in FILES:

    d = pd.read_csv(p, low_memory=False)

    name = os.path.basename(p)

    found = {}

    for c in d.columns:

        if norm(c) in WANT:

            found[WANT[norm(c)]] = c

    missing = [v for v in WANT.values() if v not in found]

    print(f"{name:<42} rows={len(d):>7,}  missing={missing}")

    if missing:

        print("    raw header:", list(d.columns)[:8], "...", list(d.columns)[-6:])

        continue

    d = d.rename(columns={v: k for k, v in found.items()})

    d["file"] = name

    frames.append(d[["file", "Timestamp", "Src IP", "Dst IP", "Activity", "Stage"]])

 

d = pd.concat(frames, ignore_index=True)

print("\nTOTAL rows:", f"{len(d):,}")

print("\nStage values:\n", d["Stage"].value_counts(dropna=False).to_string())

print("\nStage per file:\n", d.groupby("file")["Stage"].value_counts().to_string())

print("\nActivity values (top 30):\n", d["Activity"].value_counts(dropna=False).head(30).to_string())

print("\nTimestamp samples:", d["Timestamp"].astype(str).head(3).tolist(), d["Timestamp"].astype(str).tail(3).tolist())

ts = pd.to_datetime(d["Timestamp"], errors="coerce")

print("Timestamp parse failures:", int(ts.isna().sum()), "of", len(d))

print("Timestamp range:", ts.min(), "to", ts.max())

 

atk = d[d["Stage"].astype(str).str.strip().str.lower() != "benign"].copy()

print("\nAttack flows:", f"{len(atk):,}")

print("Attack source IPs (top 15):\n", atk["Src IP"].value_counts().head(15).to_string())

print("Attack destination IPs (top 10):\n", atk["Dst IP"].value_counts().head(10).to_string())

 

atk["ts"] = pd.to_datetime(atk["Timestamp"], errors="coerce")

print("\nPer attacker IP: stage sequence over time (consecutive repeats collapsed), top 10 IPs")

for ip in atk["Src IP"].value_counts().head(10).index:

    s = atk[atk["Src IP"] == ip].sort_values("ts")["Stage"].astype(str).str.strip().tolist()

    runs = [x for i, x in enumerate(s) if i == 0 or x != s[i - 1]]

    print(f"  {ip:<18} flows={len(s):>6,}  changes={len(runs) - 1:>4}  path={runs[:12]}{' ...' if len(runs) > 12 else ''}")
