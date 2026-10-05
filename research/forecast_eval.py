
#!/usr/bin/env python3

"""RESEARCH - Forecast Earliness Evaluation (n-step-ahead prediction accuracy).

WARNING: this script evaluates on SYNTHETIC episodes from make_kill_chain_episodes(), which are generated
to follow kill-chain order. Its numbers are not results on real data. See research/forecast_audit.py.

Framework: Ghafir et al. / E-HiDNet 2026 -- OSP (t+1), TSP (t+2), 3SP (t+3).

Measures FORECAST quality (not detection): how accurately & how far ahead the

HMM predicts the attacker's next kill-chain stage, vs a naive baseline."""

import json, os

import numpy as np

 

HERE = os.path.dirname(os.path.abspath(__file__))

MODELS = os.path.join(HERE, "..", "artifacts", "models")

STAGES = ["NONE", "RECON", "INITIAL_COMPROMISE", "LATERAL_MOVEMENT", "EXFILTRATION"]

 

 

def load_transmat():

    npz = np.load(os.path.join(MODELS, "hmm_forecaster.npz"), allow_pickle=True)

    return npz["transmat"], list(npz["stages"])

 

 

def predict_n_ahead(transmat, current_state, n):

    mat_n = np.linalg.matrix_power(transmat, n)

    return int(np.argmax(mat_n[current_state]))

 

 

def make_kill_chain_episodes(n_episodes=200, seed=42):

    rng = np.random.default_rng(seed)

    idx = {s: i for i, s in enumerate(STAGES)}

    canonical = [idx["RECON"], idx["INITIAL_COMPROMISE"],

                 idx["LATERAL_MOVEMENT"], idx["EXFILTRATION"]]

    episodes = []

    for _ in range(n_episodes):

        ep = []

        for stage in canonical:

            r = rng.random()

            if r < 0.15 and ep:

                continue

            ep.append(stage)

            if rng.random() < 0.2:

                ep.append(stage)

        if len(ep) >= 2:

            episodes.append(ep)

    return episodes

 

 

def evaluate(transmat, episodes, max_ahead=3):

    results = {n: {"correct": 0, "total": 0} for n in range(1, max_ahead + 1)}

    naive = {n: {"correct": 0, "total": 0} for n in range(1, max_ahead + 1)}

    for ep in episodes:

        for i in range(len(ep)):

            cur = ep[i]

            for n in range(1, max_ahead + 1):

                j = i + n

                if j >= len(ep):

                    continue

                truth = ep[j]

                pred = predict_n_ahead(transmat, cur, n)

                results[n]["total"] += 1

                if pred == truth:

                    results[n]["correct"] += 1

                naive_pred = min(cur + n, len(STAGES) - 1)

                naive[n]["total"] += 1

                if naive_pred == truth:

                    naive[n]["correct"] += 1

    return results, naive

 

 

def main():

    transmat, stages = load_transmat()

    print("[load] HMM transition matrix loaded")

    episodes = make_kill_chain_episodes()

    print(f"[data] {len(episodes)} attack episodes, "

          f"mean length {np.mean([len(e) for e in episodes]):.1f} stages")

    results, naive = evaluate(transmat, episodes, max_ahead=3)

    print("\n" + "="*66)

    print("FORECAST-EARLINESS EVALUATION (n-step-ahead prediction accuracy)")

    print("Framework: Ghafir et al. / E-HiDNet 2026 (OSP / TSP / 3SP)")

    print("="*66)

    print(f"  {'Horizon':<28} {'HMM Forecast':>14} {'Naive Baseline':>16}")

    names = {1: "OSP  (1 step ahead, t+1)", 2: "TSP  (2 steps ahead, t+2)",

             3: "3SP  (3 steps ahead, t+3)"}

    out = {}

    for n in [1, 2, 3]:

        h = results[n]["correct"] / results[n]["total"] if results[n]["total"] else 0

        nb = naive[n]["correct"] / naive[n]["total"] if naive[n]["total"] else 0

        out[f"{n}-step"] = {"hmm_accuracy": h, "naive_accuracy": nb,

                            "n_predictions": results[n]["total"]}

        print(f"  {names[n]:<28} {h:>13.1%} {nb:>15.1%}")

    print("\n  Interpretation:")

    print("  - OSP is the operationally critical metric (immediate early warning).")

    print("  - Accuracy DEGRADES with horizon as uncertainty compounds.")

    print(f"  - Literature: Ghafir HMM ~43.6% OSP; E-HiDNet ~70% (2 obs).")

    with open(os.path.join(HERE, "..", "artifacts", "forecast_eval.json"), "w") as f:

        json.dump({"n_episodes": len(episodes), "results": out,

                   "framework": "OSP/TSP/3SP n-step-ahead (Ghafir/E-HiDNet)",

                   "benchmark_note": "Ghafir HMM ~43.6% OSP baseline",
                   "warning": "SYNTHETIC episodes generated to follow kill-chain order; not a real-data result. See artifacts/forecast_audit.json."}, f, indent=2)

    print("\n[saved] artifacts/forecast_eval.json")

 

 

if __name__ == "__main__":

    main()

