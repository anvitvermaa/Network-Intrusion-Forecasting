

#!/usr/bin/env python3

"""reality_check: does an intrusion detector's headline result survive basic scrutiny?

 

It audits PREDICTIONS, not models, so it works for any detector. Give it a CSV or parquet file with:

  label      (required) ground truth per flow: a benign value or an attack type

  pred       (optional) the system's final output per flow (benign value, attack type, or "UNKNOWN_ATTACK")

  flag       (optional) 1 if the detector stage flagged the flow, else 0

  score      (optional) suspiciousness score; higher = more suspicious

  timestamp  (optional) used to estimate traffic volume per hour

 

Checks (each reports PASS / WARN / FAIL / NOT CHECKED with its numbers):

  1 headline vs per-attack-type results      5 ranking quality without a threshold (AUROC)

  2 false alarms as alerts per hour          6 identical rows shared by training and test data

  3 seen vs unseen attack types              7 whether stage sequences can test forecasting at all

  4 classifier veto of detector alarms

 

Example:

  python research/reality_check.py --predictions artifacts/rc_friday.parquet --name "CIC-IDS2017 Friday" \\

      --train-attacks "DoS Hulk,DoS GoldenEye,DoS Slowloris,DoS Slowhttptest,FTP-Patator,SSH-Patator,Heartbleed" --hours 8

The thresholds used for PASS/WARN are rules of thumb, printed with each check, not standards.

"""

import argparse

import hashlib

import json

import os

import sys

import numpy as np

import pandas as pd

from scipy.stats import beta

 

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

 

DEFAULT_BENIGN = "Benign,BENIGN,benign,Normal,Attempted-relabel-as-Benign"

UNK = "UNKNOWN_ATTACK"

MIN_N = 30

PATCHED_V2 = True  # per-type checks: weaknesses cannot hide in averages

 

 

def cp(k, n, alpha=0.05):

    if n == 0:

        return [None, None]

    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))

    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))

    return [lo, hi]

 

 

def pc(x, d=1):

    return "n/a" if x is None else f"{100 * x:.{d}f}%"

 

 

def load(path):

    if path.endswith(".parquet"):

        return pd.read_parquet(path)

    return pd.read_csv(path, low_memory=False)

 

 

class Report:

    def __init__(self, name):

        self.name, self.checks = name, []

 

    def add(self, num, title, status, summary, details=None, rule=None):

        self.checks.append({"check": num, "title": title, "status": status, "summary": summary,

                            "details": details or [], "rule": rule})

        print(f"\n[{status:<11}] {num}. {title}\n              {summary}")

        for d in details or []:

            print(f"              - {d}")

        if rule:

            print(f"              (rule of thumb: {rule})")

 

    def markdown(self):

        L = [f"# Reality check: {self.name}", "", "| # | Check | Status | Summary |", "|---|---|---|---|"]

        for c in self.checks:

            L.append(f"| {c['check']} | {c['title']} | **{c['status']}** | {c['summary']} |")

        for c in self.checks:

            L += ["", f"## {c['check']}. {c['title']}: {c['status']}", "", c["summary"], ""]

            L += [f"- {d}" for d in c["details"]]

            if c["rule"]:

                L += ["", f"_Rule of thumb: {c['rule']}_"]

        return "\n".join(L) + "\n"

 

 

def main():

    ap = argparse.ArgumentParser(description="Audit an intrusion detector's predictions.")

    ap.add_argument("--predictions", required=True, help="CSV or parquet with label [pred flag score timestamp]")

    ap.add_argument("--name", default="detector", help="name shown in the report")

    ap.add_argument("--benign", default=DEFAULT_BENIGN, help="comma-separated labels that mean normal traffic")

    ap.add_argument("--train-attacks", default=None, help="comma-separated attack types present in training data")

    ap.add_argument("--hours", type=float, default=None, help="hours of traffic covered (if no timestamp column)")

    ap.add_argument("--overlap-train", default=None, help="training data file, for the leakage check")

    ap.add_argument("--overlap-test", default=None, help="test data file with the same feature columns, for the leakage check")

    ap.add_argument("--stages", default=None, help="CSV with columns episode, order, stage (for the forecasting check)")

    ap.add_argument("--stage-order", default="RECON,INITIAL_COMPROMISE,LATERAL_MOVEMENT,EXFILTRATION",

                    help="kill-chain order used by the 'advance one stage' rule")

    ap.add_argument("--out", default=None, help="output path prefix (default: artifacts/reality_check_<name>)")

    a = ap.parse_args()

 

    df = load(a.predictions)

    if "label" not in df.columns:

        sys.exit("[error] the predictions file needs a 'label' column")

    benign = set(s.strip() for s in a.benign.split(",") if s.strip())

    lab = df["label"].astype(str).str.strip().values

    y = ~np.isin(lab, list(benign))

    has_pred, has_flag, has_score = "pred" in df.columns, "flag" in df.columns, "score" in df.columns

    if has_pred:

        pred = df["pred"].astype(str).str.strip().values

        alarm = ~np.isin(pred, list(benign))

    elif has_flag:

        alarm = df["flag"].astype(bool).values

    else:

        alarm = None

    R = Report(a.name)

    print(f"Reality check: {a.name}\n  {len(df):,} flows, {int(y.sum()):,} attack, {int((~y).sum()):,} normal; "

          f"columns found: {[c for c in ['pred', 'flag', 'score', 'timestamp'] if c in df.columns]}")

 

    # ---------- 1. headline vs per-type ----------

    if alarm is None:

        R.add(1, "Headline vs per-attack-type results", "NOT CHECKED", "Needs a 'pred' or 'flag' column.")

        per = {}

    else:

        tp, fp = int((alarm & y).sum()), int((alarm & ~y).sum())

        rec = tp / max(int(y.sum()), 1)

        far = fp / max(int((~y).sum()), 1)

        per = {}

        for t in sorted(set(lab[y])):

            m = lab == t

            k, n = int(alarm[m].sum()), int(m.sum())

            per[t] = {"n": n, "caught": k, "rate": k / n, "ci95": cp(k, n)}

        top_t, top = max(per.items(), key=lambda kv: kv[1]["n"]) if per else (None, {"n": 0})

        share = top["n"] / max(int(y.sum()), 1)

        weak = [t for t, e in per.items() if e["n"] >= MIN_N and e["rate"] < 0.5]

        small = [t for t, e in per.items() if e["n"] < MIN_N]

        status = "FAIL" if rec < 0.5 else ("WARN" if weak or share > 0.5 else "PASS")

        det = [f"overall: {pc(rec)} of attacks caught, {pc(far, 3)} of normal traffic flagged ({fp:,} false alarms)",

               f"largest attack type: {top_t} = {pc(share, 0)} of all attack flows"]

        det += [f"{t}: {pc(e['rate'])} caught of {e['n']:,} (95% CI {pc(e['ci95'][0], 0)}-{pc(e['ci95'][1], 0)})"

                for t, e in sorted(per.items(), key=lambda kv: -kv[1]["n"])]

        if small:

            det.append(f"too few examples to judge (n < {MIN_N}): {', '.join(small)}")

        summ = f"Overall {pc(rec)} caught at {pc(far, 3)} false alarms."

        if rec < 0.5:

            summ += " Most attacks are missed."

        if weak:

            summ += f" Weak types hidden by the average: {', '.join(weak)}."

        R.add(1, "Headline vs per-attack-type results", status, summ, det,

              "FAIL if under 50% of attacks are caught; WARN if one type is over half of all attacks or any type with 30+ examples is under 50%")

 

    # ---------- 2. alerts per hour ----------

    hours = a.hours

    hours_from_span = False

    if hours is None and "timestamp" in df.columns:

        ts = pd.to_datetime(df["timestamp"], errors="coerce")

        if ts.notna().sum() > 1:

            hours = max((ts.max() - ts.min()).total_seconds() / 3600.0, 1e-9)

            hours_from_span = True

    if alarm is None or hours is None:

        R.add(2, "False alarms as alerts per hour", "NOT CHECKED", "Needs predictions and either --hours or a timestamp column.")

    else:

        fp = int((alarm & ~y).sum())

        per_h = fp / hours

        prec = int((alarm & y).sum()) / max(int(alarm.sum()), 1)

        status = "PASS" if per_h <= 10 else ("WARN" if per_h <= 100 else "FAIL")

        R.add(2, "False alarms as alerts per hour", status,

              f"{per_h:,.1f} false alerts per hour over {hours:,.1f} hours; {pc(prec)} of all alerts are real attacks.",

              [f"{fp:,} false alarms in total", "an analyst can typically review tens of alerts per hour, not thousands"]

              + (["hours = first to last timestamp; if capture was not continuous (nights, gaps), the true busy-hour rate is higher"] if hours_from_span else []),

              "PASS up to 10 per hour, WARN up to 100, FAIL above; depends on team size")

 

    # ---------- 3. seen vs unseen ----------

    if alarm is None or not a.train_attacks:

        R.add(3, "Seen vs unseen attack types", "NOT CHECKED",

              "Pass --train-attacks to verify claims about new attacks. Without it, a high score may only mean the attacks were seen in training.")

    else:

        seen = set(s.strip() for s in a.train_attacks.split(",") if s.strip())

        ms, mu = y & np.isin(lab, list(seen)), y & ~np.isin(lab, list(seen))

        rs = alarm[ms].mean() if ms.any() else None

        ru = alarm[mu].mean() if mu.any() else None

        if rs is None:

            status = "INFO"

        else:

            status = "PASS" if (ru is not None and ru >= rs - 0.2) else "WARN"

        R.add(3, "Seen vs unseen attack types", status,

              f"Unseen types: {pc(ru)} caught ({int(mu.sum()):,} flows). Seen types: {pc(rs)} ({int(ms.sum()):,} flows).",

              [f"unseen types in this data: {', '.join(sorted(set(lab[mu]))) or 'none'}"]

              + (["every attack type here is unseen, so this is a genuine zero-day test; there is nothing seen to compare against"] if rs is None else []),

              "WARN if unseen types are caught 20+ points less often than seen ones")

 

    # ---------- 4. veto ----------

    if not (has_flag and has_pred):

        R.add(4, "Classifier veto of detector alarms", "NOT CHECKED", "Needs both 'flag' (detector) and 'pred' (final output).")

    else:

        fl = df["flag"].astype(bool).values

        caught = fl & y

        vetoed = caught & ~alarm

        rate = vetoed.sum() / max(caught.sum(), 1)

        rows = []

        for t in sorted(set(lab[y])):

            m = caught & (lab == t)

            if m.sum() >= MIN_N:

                rows.append((t, int(m.sum()), float((m & ~alarm).sum() / m.sum())))

        rows.sort(key=lambda r: -r[2])

        bad = [r for r in rows if r[2] > 0.2]

        status = "WARN" if rate > 0.2 or bad else "PASS"

        R.add(4, "Classifier veto of detector alarms", status,

              f"Of {int(caught.sum()):,} attacks the detector caught, the final output called {pc(rate)} normal."

              + (f" Worst: {bad[0][0]}, {pc(bad[0][2])} of its detector catches overruled." if bad else ""),

              [f"{t}: {pc(r)} of {n:,} detector catches overruled" for t, n, r in rows[:8]],

              "WARN if more than 20% of the detector's correct alarms are overruled, overall or for any type with 30+ catches")

 

    # ---------- 5. AUROC ----------

    if not has_score:

        R.add(5, "Ranking quality without a threshold (AUROC)", "NOT CHECKED", "Needs a 'score' column.")

    else:

        from sklearn.metrics import roc_auc_score

        s = pd.to_numeric(df["score"], errors="coerce").fillna(-np.inf).values

        if y.all() or (~y).all():

            R.add(5, "Ranking quality without a threshold (AUROC)", "NOT CHECKED", "Needs both attack and normal flows.")

        else:

            auc = float(roc_auc_score(y, s))

            det, weak_auc = [], []

            for t in sorted(set(lab[y]), key=lambda t: -(lab == t).sum()):

                m = lab == t

                if m.sum() >= MIN_N:

                    sel = ~y | m

                    v = roc_auc_score(m[sel], s[sel])

                    det.append(f"{t}: AUROC {v:.3f} (n={int(m.sum()):,})")

                    if v < 0.7:

                        weak_auc.append(f"{t} {v:.2f}")

            status = "FAIL" if auc < 0.7 else ("WARN" if auc < 0.9 or weak_auc else "PASS")

            R.add(5, "Ranking quality without a threshold (AUROC)", status,

                  f"AUROC {auc:.3f} (0.5 = chance, 1.0 = perfect ranking)." + (f" Weak types: {', '.join(weak_auc)}." if weak_auc else ""), det,

                  "PASS at 0.9+ with every type (30+ examples) at 0.7+; WARN at 0.7-0.9 or if any type is below 0.7; FAIL below 0.7 overall")

 

    # ---------- 6. leakage ----------

    if not (a.overlap_train and a.overlap_test):

        R.add(6, "Identical rows in training and test data", "NOT CHECKED", "Pass --overlap-train and --overlap-test.")

    else:

        tr, te = load(a.overlap_train), load(a.overlap_test)

        drop = {"label", "day", "kill_chain_stage", "attack_onset_ts", "timestamp", "pred", "flag", "score"}

        cols = [c for c in te.columns if c in tr.columns and c not in drop and pd.api.types.is_numeric_dtype(te[c])]

 

        def hashes(d):

            return set(hashlib.md5(r.tobytes()).hexdigest() for r in d[cols].round(6).to_numpy(dtype=float))

        ht = hashes(tr)

        hv = [hashlib.md5(r.tobytes()).hexdigest() for r in te[cols].round(6).to_numpy(dtype=float)]

        dup = np.array([h in ht for h in hv])

        share = float(dup.mean())

        te_att = ~np.isin(te["label"].astype(str).str.strip().values, list(benign)) if "label" in te.columns else np.zeros(len(te), bool)

        share_att = float(dup[te_att].mean()) if te_att.any() else 0.0

        share_ben = float(dup[~te_att].mean()) if (~te_att).any() else 0.0

        status = "PASS" if share <= 0.01 and share_att <= 0.01 else "WARN"

        R.add(6, "Identical rows in training and test data", status,

              f"{pc(share, 2)} of test rows also appear exactly in the training data ({len(cols)} feature columns compared).",

              [f"attack rows that also appear in training: {pc(share_att, 2)} of {int(te_att.sum()):,}",

               f"normal rows that also appear in training: {pc(share_ben, 2)} of {int((~te_att).sum()):,} (short, common normal flows repeat naturally)",

               "identical attack rows let a model memorise answers instead of learning patterns"],

              "WARN above 1% overall, or above 1% of attack rows")

 

    # ---------- 7. forecastability ----------

    if not a.stages:

        R.add(7, "Can these stage sequences test forecasting?", "NOT CHECKED", "Pass --stages (columns: episode, order, stage).")

    else:

        import forecastability as F

        st = load(a.stages)

        order = [s.strip() for s in a.stage_order.split(",")]

        seqs = [g.sort_values("order")["stage"].astype(str).tolist() for _, g in st.groupby("episode")]

        runs = [F.collapse_runs(s) for s in seqs]

        runs = [r for r in runs if len(r) >= 2]

        stages = sorted(set(order) | set(x for s in runs for x in s))

        if not runs:

            R.add(7, "Can these stage sequences test forecasting?", "FAIL", "No episode contains a stage change.")

        else:

            dg = F.diagnostics(runs, stages)

            adv = F.make_methods(runs, stages, order)["advance_one"]

            hits = sum(adv(s[t]) == s[t + 1] for s in runs for t in range(len(s) - 1))

            n = sum(len(s) - 1 for s in runs)

            lo, hi = F.exact_ci(hits, n)

            ceiling = dg["ceiling_first_order"]

            status = "FAIL" if hits / n >= ceiling - 1e-9 or n < MIN_N else "PASS"

            R.add(7, "Can these stage sequences test forecasting?", status,

                  f"{n} real stage changes in {len(runs)} episodes; the one-line rule 'advance one stage' gets {hits}/{n} "

                  f"({pc(hits / n, 0)}, 95% CI {pc(lo, 0)}-{pc(hi, 0)}); best possible for any rule using the current stage: {pc(ceiling, 0)}.",

                  [f"distinct transitions: {dg['distinct_transitions']}",

                   f"uncertainty about the next stage: {dg['cond_entropy_bits']:.3f} bits (0 = fully predictable)"],

                  f"FAIL if the trivial rule already reaches the ceiling, or there are fewer than {MIN_N} stage changes: no forecaster can then show an advantage")

 

    # ---------- write ----------

    counts = pd.Series([c["status"] for c in R.checks]).value_counts().to_dict()

    print(f"\nSummary: {counts}")

    slug = "".join(ch if ch.isalnum() else "_" for ch in a.name.lower()).strip("_")

    prefix = a.out or os.path.join(HERE, "..", "artifacts", f"reality_check_{slug}")

    os.makedirs(os.path.dirname(os.path.abspath(prefix)), exist_ok=True)

    with open(prefix + ".md", "w") as f:

        f.write(R.markdown())

    with open(prefix + ".json", "w") as f:

        json.dump({"name": a.name, "summary": counts, "checks": R.checks}, f, indent=2, default=str)

    print(f"[saved] {prefix}.md and {prefix}.json")

 

 

if __name__ == "__main__":

    main()

