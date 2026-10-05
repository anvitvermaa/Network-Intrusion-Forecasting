
#!/usr/bin/env python3
"""Fair comparison for the DAPT2020 forecasting result: does the fitted Markov model fail because of the
model, or because of what it was trained on?

Leave-one-attacker-out on artifacts/rc_dapt_stages.csv (written by research/export_predictions.py):
  markov_flows    first-order Markov fitted on every flow step of the other attackers (the paper's original setup)
  markov_changes  the same model fitted only on the stage changes of the other attackers
  advance_one     the textbook rule, for reference
Each is scored over every flow step and at real stage changes, with exact 95% intervals.
Output: artifacts/dapt_markov_changes.json
"""
import json
import os
import sys
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, HERE)
import forecastability as F

IN = os.path.join(ROOT, "artifacts", "rc_dapt_stages.csv")
ORDER = ["RECON", "INITIAL_COMPROMISE", "LATERAL_MOVEMENT", "EXFILTRATION"]
EXPECTED_IN_PAPER = {"markov_flows": {"changes": (0, 11)}, "advance_one": {"changes": (11, 11)}}


def main():
    st = pd.read_csv(IN)
    eps = {e: g.sort_values("order", kind="stable")["stage"].astype(str).tolist() for e, g in st.groupby("episode", sort=True)}
    stages = sorted(set(ORDER) | set(st["stage"].astype(str)))
    names = sorted(eps)
    tot = {m: {"all": [0, 0], "chg": [0, 0]} for m in ["markov_flows", "markov_changes", "advance_one"]}
    for held in names:
        train_flows = [eps[e] for e in names if e != held]
        train_runs = [F.collapse_runs(s) for s in train_flows]
        m_flow = F.make_methods(train_flows, stages, ORDER)
        m_run = F.make_methods(train_runs, stages, ORDER)
        fns = {"markov_flows": m_flow["markov1"], "markov_changes": m_run["markov1"], "advance_one": m_flow["advance_one"]}
        s = eps[held]
        for t in range(len(s) - 1):
            change = s[t] != s[t + 1]
            for m, fn in fns.items():
                hit = fn(s[t]) == s[t + 1]
                tot[m]["all"][0] += int(hit)
                tot[m]["all"][1] += 1
                if change:
                    tot[m]["chg"][0] += int(hit)
                    tot[m]["chg"][1] += 1
    out = {"attackers": len(names), "results": {}}
    print(f"[data] {len(names)} attacker sources, {sum(len(s) for s in eps.values()):,} attack flows")
    for m, r in tot.items():
        a, n = r["all"]
        c, k = r["chg"]
        ci = F.exact_ci(c, k)
        out["results"][m] = {"every_flow": [a, n], "at_changes": [c, k], "at_changes_ci95": ci}
        print(f"   {m:<15} every flow {a:>6}/{n:<6} = {a / n:6.2%}   at changes {c}/{k}  [{ci[0]:.0%}-{ci[1]:.0%}]")
    ok = all(tuple(out["results"][m]["at_changes"]) == v["changes"] for m, v in EXPECTED_IN_PAPER.items())
    print("[check] original results reproduced:", "YES" if ok else "NO - paste this output before changing the paper")
    mc = out["results"]["markov_changes"]["at_changes"]
    ma, mn = out["results"]["markov_changes"]["every_flow"]
    paper_ok = tuple(mc) == (11, 11) and ma / mn < 0.01
    print(f"[result] Markov fitted on stage changes: {mc[0]}/{mc[1]} at changes, {ma / mn:.2%} over every flow")
    print("[result] updated paper says 11/11 and <1%:", "MATCHES" if paper_ok else "DIFFERS - paste this output before uploading the paper")
    with open(os.path.join(ROOT, "artifacts", "dapt_markov_changes.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("[saved] artifacts/dapt_markov_changes.json")


if __name__ == "__main__":
    main()
