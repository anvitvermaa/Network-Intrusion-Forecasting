

#!/usr/bin/env python3
"""Forecastability audit of the Unraveled APT campaign (run research/unraveled_extract.py first).

Steps
  1. Load the extracted attack flows; remove flows captured twice (gateway and subnet interface).
  2. Describe each attacker group (Signature): flows, hosts, stages, time span.
  3. For the APT campaign, at 1-hour, 6-hour and 1-day windows:
       - concurrency: share of active windows containing two or more stages at once
       - dominant-stage sequence (most flows per window), collapsed to stage changes
       - forecastability diagnostic on that sequence
       - trivial baselines fitted on the first half of the windows, scored at stage changes in the second half
Output: artifacts/unraveled_audit.json
"""
import json
import os
import sys
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, HERE)
import forecastability as F

IN = os.path.join(ROOT, "data", "processed", "unraveled_attacks.parquet")
MAP = {"Reconnaissance": "RECON", "Establish Foothold": "INITIAL_COMPROMISE", "Lateral Movement": "LATERAL_MOVEMENT",
       "Data Exfiltration": "EXFILTRATION", "Cover up": "COVER_UP"}
ORDER = ["RECON", "INITIAL_COMPROMISE", "LATERAL_MOVEMENT", "EXFILTRATION", "COVER_UP"]


def main():
    d = pd.read_parquet(IN)
    u = d.drop_duplicates(subset=["src_ip", "dst_ip", "ts_ms", "Stage", "Activity"]).copy()
    u["t"] = pd.to_datetime(u["ts_ms"], unit="ms")
    out = {"attack_flows_raw": int(len(d)), "attack_flows_dedup": int(len(u)), "groups": {}, "apt_windows": {}}
    print(f"[data] {len(d):,} attack flows; {len(u):,} after removing gateway/subnet duplicates")

    for g, x in u.groupby("Signature", dropna=False):
        info = {"flows": int(len(x)), "first": str(x["t"].min()), "last": str(x["t"].max()),
                "stages": {k: int(v) for k, v in x["Stage"].value_counts().items()},
                "top_src": {k: int(v) for k, v in x["src_ip"].value_counts().head(5).items()}}
        out["groups"][str(g)] = info
        print(f"[group {g}] {info['flows']:,} flows, {info['first'][:10]} to {info['last'][:10]}, stages {info['stages']}")

    a = u[u["Signature"] == "APT"].copy()
    a["stage"] = a["Stage"].map(MAP)
    lab = a[["Stage", "Activity"]].value_counts()
    out["apt_stage_activity_pairs"] = [[s, act, int(n)] for (s, act), n in lab.items()]

    for res in ["1h", "6h", "1D"]:
        w = a.groupby([pd.Grouper(key="t", freq=res), "stage"]).size().unstack(fill_value=0)
        w = w[w.sum(axis=1) > 0]
        concurrency = float((w.gt(0).sum(axis=1) >= 2).mean())
        dom = w.idxmax(axis=1).tolist()
        runs = F.collapse_runs(dom)
        dg = F.diagnostics([runs], ORDER)
        half = len(dom) // 2
        tr, te = F.collapse_runs(dom[:half]), F.collapse_runs(dom[half:])
        methods = F.make_methods([tr], ORDER, ORDER)
        scores = {}
        for name, fn in methods.items():
            k = sum(fn(te[i]) == te[i + 1] for i in range(len(te) - 1))
            n = len(te) - 1
            scores[name] = {"hits": int(k), "n": int(n), "ci95": F.exact_ci(k, n)}
        out["apt_windows"][res] = {"active_windows": int(len(w)), "share_windows_multi_stage": concurrency,
                                   "dominant_stage_changes": int(len(runs) - 1),
                                   "distinct_transitions": dg["distinct_transitions"],
                                   "cond_entropy_bits": dg["cond_entropy_bits"],
                                   "ceiling_first_order": dg["ceiling_first_order"],
                                   "dominant_path": runs, "second_half_at_changes": scores}
        print(f"[APT, {res} windows] {len(w)} active; {concurrency:.0%} with 2+ stages at once; "
              f"{len(runs) - 1} dominant-stage changes; distinct={dg['distinct_transitions']}; H={dg['cond_entropy_bits']:.3f} bits")
        print("      second half, at changes: " + ", ".join(f"{n} {s['hits']}/{s['n']}" for n, s in scores.items()))

    p = os.path.join(ROOT, "artifacts", "unraveled_audit.json")
    with open(p, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"[saved] {p}")


if __name__ == "__main__":
    main()

