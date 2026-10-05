import os
import sys
import tempfile
import pandas as pd
import streamlit as st
import _paper as P
import _runner as R
import _theme as T

sys.path.insert(0, R.path("research"))
T.setup("Run the checks")
T.masthead("Run the checks", "These buttons execute the project's real research scripts on this machine and compare every number with the paper.")
T.note("Each check runs only if its input data is on the machine serving this site. On the laptop with the full project, all of them run. "
       "On a public copy of the site, the ones that need large datasets show the paper's recorded values instead, and say so.")


def pct(x, d=1):
    return f"{100 * x:.{d}f}%"


# ---------------- comparisons: paper value vs this run ----------------
def cmp_ghafir():
    J = R.load_json("artifacts/ghafir_audit.json")
    G = P.GHAFIR_RECORD
    dg = J["diagnostics_step_changes"]
    fo = J["first_order_cv5"]["1"]
    pt = J["prefix_table"]["split50_x20"]
    rows = [("Stage changes", G["changes"], f"{dg['n_stage_changes']:,}"),
            ("Distinct transitions", G["distinct"], str(dg["distinct_transitions"])),
            ("Uncertainty of next stage (bits)", G["entropy"], f"{dg['cond_entropy_bits']:.3f}"),
            ("Advance one stage, 1 step ahead", G["advance_one"], pct(fo["advance_one"]["acc"])),
            ("Fitted Markov, 1 step ahead", G["markov1"], pct(fo["markov1"]["acc"]))]
    for n in ("2", "3", "4"):
        rows.append((f"Lookup table, one guess, {n} alerts", G["top1"][n], pct(pt[n]["top1"])))
    for n in ("2", "3", "4"):
        rows.append((f"Lookup table, two guesses, {n} alerts", G["top2"][n], pct(pt[n]["top2"])))
    return [(a, b, c, b == c) for a, b, c in rows]


def cmp_dapt():
    J = R.load_json("artifacts/dapt_markov_changes.json")["results"]

    def chg(m):
        c, k = J[m]["at_changes"]
        return f"{c} of {k}"

    def allf(m):
        a, n = J[m]["every_flow"]
        v = a / n
        return "&gt;99%" if v > 0.99 else ("&lt;1%" if v < 0.01 else pct(v))
    rows = [("Markov fitted on every flow, at stage changes", "0 of 11", chg("markov_flows")),
            ("Markov fitted on every flow, over every flow", "&gt;99%", allf("markov_flows")),
            ("Markov fitted on stage changes, at stage changes", "11 of 11", chg("markov_changes")),
            ("Markov fitted on stage changes, over every flow", "&lt;1%", allf("markov_changes")),
            ("Advance one stage, at stage changes", "11 of 11", chg("advance_one"))]
    return [(a, b, c, b == c) for a, b, c in rows]


def cmp_unraveled():
    J = R.load_json("artifacts/unraveled_audit.json")
    U = P.UNRAVELED_RECORD
    rows = [("Attack flows", U["attack_flows"], f"{J['attack_flows_raw']:,}"),
            ("After removing duplicate captures", U["dedup"], f"{J['attack_flows_dedup']:,}")]
    for key, label in (("1h", "1-hour"), ("6h", "6-hour"), ("1D", "1-day")):
        w = J["apt_windows"][key]
        multi, changes, distinct = U[key]
        rows.append((f"{label} windows with two or more stages", multi, f"{100 * w['share_windows_multi_stage']:.0f}%"))
        rows.append((f"{label} dominant-stage changes", changes, str(w["dominant_stage_changes"])))
        rows.append((f"{label} distinct transitions", distinct, str(w["distinct_transitions"])))
    return [(a, b, c, b == c) for a, b, c in rows]


def cmp_reality(out_prefix):
    J = R.load_json(out_prefix + ".json")
    got = {c["check"]: c["status"] for c in J["checks"]}
    rows = []
    for k in range(1, 8):
        paper, now = P.REALITY_CHECK_FRIDAY[k], got.get(k, "missing")
        ok = None if now == "NOT CHECKED" else (paper == now)
        rows.append((f"{k}. {P.CHECK_NAMES[k]}", paper, now, ok))
    return rows


def reality_args():
    out = os.path.join(tempfile.gettempdir(), "nif_reality_check_friday")
    args = ["research/reality_check.py", "--predictions", "artifacts/rc_friday.parquet", "--name", "CIC-IDS2017 Friday",
            "--train-attacks", P.CIC_TRAIN_ATTACKS, "--hours", "8", "--out", out]
    if R.exists("artifacts/rc_cic_stages.csv"):
        args += ["--stages", "artifacts/rc_cic_stages.csv"]
    return args, out


CHECKS = [
    {"key": "ghafir", "title": "The dataset behind a published forecaster",
     "what": "Downloads Ghafir et al.'s public alert dataset (280 KB) and compares a lookup table with their published HMM.",
     "needs": [], "internet": True, "args": lambda: (["research/ghafir_audit.py"], None), "compare": lambda o: cmp_ghafir()},
    {"key": "dapt", "title": "DAPT2020: fitted on flows versus fitted on stage changes",
     "what": "Leave-one-attacker-out on the 11 real attackers. Reproduces 0 of 11 and the fair 11 of 11.",
     "needs": ["artifacts/rc_dapt_stages.csv"], "args": lambda: (["research/dapt_markov_changes.py"], None), "compare": lambda o: cmp_dapt()},
    {"key": "unraveled", "title": "Unraveled: concurrent stages",
     "what": "Measures how often the APT is in several stages at once, at three window sizes.",
     "needs": ["data/processed/unraveled_attacks.parquet"], "args": lambda: (["research/unraveled_audit.py"], None),
     "compare": lambda o: cmp_unraveled()},
    {"key": "reality", "title": "The audit tool on our own detector",
     "what": "Runs the seven checks on the deployed pipeline's Friday predictions. Check 6 compares against 1.1 million training rows "
             "and is run from the terminal, so it is not compared here.",
     "needs": ["artifacts/rc_friday.parquet"], "args": reality_args, "compare": cmp_reality},
]


def render_result(c):
    res = st.session_state.get("res_" + c["key"])
    if not res:
        return
    if res["error"]:
        T.note(f"The script stopped with an error (exit code {res['code']}). The last lines of its output are below.", warn=True)
        st.code("\n".join(res["log"].splitlines()[-15:]), language=None)
        return
    rows = res["rows"]
    n_ok = sum(1 for r in rows if r[3] is True)
    n_cmp = sum(1 for r in rows if r[3] is not None)
    T.table(["Quantity", "Paper", "This run", ""], [[a, b, c, T.mark(ok)] for a, b, c, ok in rows], num_cols=(1, 2))
    T.caption(f"{n_ok} of {n_cmp} compared values match the paper.")
    with st.expander("Full script output"):
        st.code(res["log"], language=None)


def run_check(c):
    args, out = c["args"]()
    code, log = R.run(args)
    entry = {"code": code, "log": log, "error": code != 0, "rows": []}
    if code == 0:
        try:
            entry["rows"] = c["compare"](out)
        except Exception as e:
            entry["error"] = True
            entry["log"] = log + f"\n[website] could not read the results: {e}"
    st.session_state["res_" + c["key"]] = entry


T.section("Reproduce the paper", "Each check runs the script that produced the paper's numbers.")
available = [c for c in CHECKS if all(R.exists(n) for n in c["needs"])]
if st.button(f"Run all {len(available)} available checks", key="run_all"):
    for c in available:
        with st.status(f"Running: {c['title']}", expanded=True) as box:
            run_check(c)
            failed = st.session_state["res_" + c["key"]]["error"]
            box.update(label=("Stopped with an error: " if failed else "Finished: ") + c["title"],
                       state="error" if failed else "complete", expanded=False)

for c in CHECKS:
    T.sub(c["title"])
    T.prose(c["what"])
    missing = [n for n in c["needs"] if not R.exists(n)]
    if missing:
        T.note("Not available on this machine: needs <code>" + "</code>, <code>".join(missing) + "</code>. "
               "Run it on the laptop with the full project. The paper's values are on the Findings page.")
        continue
    if c.get("internet"):
        T.caption("Needs an internet connection to download the dataset on first run.")
    if st.button("Run this check", key="btn_" + c["key"]):
        run_check(c)
    render_result(c)

# ---------------- audit your own results ----------------
T.section("Audit your own detector", "Upload any intrusion detector's predictions. Nothing is stored after the page closes.")
T.prose("A CSV or parquet file with a <code>label</code> column (true class per flow) and, if you have them, <code>pred</code> "
        "(final output), <code>flag</code> (detector stage, 0 or 1), <code>score</code> (higher means more suspicious) and "
        "<code>timestamp</code>. Each check reports what it found and the rule of thumb it used.")
up = st.file_uploader("Predictions file", type=["csv", "parquet"], key="pred_upload")
c1, c2 = st.columns(2)
benign = c1.text_input("Labels that mean normal traffic", "Benign,BENIGN,benign,Normal")
hours = c2.text_input("Hours of traffic covered (optional)", "")
train_attacks = st.text_input("Attack types present in training (optional, comma-separated)", "")
if up is not None and st.button("Audit this file", key="audit_upload"):
    suffix = ".parquet" if up.name.endswith(".parquet") else ".csv"
    tmp = tempfile.mkdtemp()
    fpath = os.path.join(tmp, "upload" + suffix)
    with open(fpath, "wb") as f:
        f.write(up.getbuffer())
    out = os.path.join(tmp, "report")
    args = ["research/reality_check.py", "--predictions", fpath, "--name", up.name, "--benign", benign, "--out", out]
    if hours.strip():
        args += ["--hours", hours.strip()]
    if train_attacks.strip():
        args += ["--train-attacks", train_attacks.strip()]
    code, log = R.run(args)
    if code != 0 or not os.path.exists(out + ".json"):
        st.session_state["audit_result"] = {"error": True, "log": log, "name": up.name}
    else:
        J = R.load_json(out + ".json")
        st.session_state["audit_result"] = {"error": False, "name": up.name, "md": open(out + ".md").read(),
                                            "rows": [[f"{c['check']}. {c['title']}", c["status"], T.esc(c["summary"])] for c in J["checks"]]}
    st.rerun()
res = st.session_state.get("audit_result")
if res:
    T.sub(f"Audit of {T.esc(res['name'])}")
    if res["error"]:
        T.note("The audit could not read this file. The tool's message is below; most often the <code>label</code> column is missing.", warn=True)
        st.code("\n".join(res["log"].splitlines()[-10:]), language=None)
    else:
        T.table(["Check", "Result", "Summary"], res["rows"])
        with st.expander("Full report"):
            st.markdown(res["md"])

T.section("Check whether stage data can test forecasting", "Upload attack-stage sequences before you trust a forecasting result on them.")
T.prose("A CSV with columns <code>episode</code> (one attacker or campaign), <code>order</code> (time order) and <code>stage</code>.")
use_dapt = R.exists("artifacts/rc_dapt_stages.csv") and st.checkbox("Use the DAPT2020 attacker sequences from this project")
up2 = None if use_dapt else st.file_uploader("Stage sequences file", type=["csv"], key="stage_upload")
order_txt = st.text_input("Kill-chain order, earliest first", P.KILL_CHAIN)
if (use_dapt or up2 is not None) and st.button("Check forecastability", key="fc_run"):
    import forecastability as F
    out = {"tables": [], "notes": [], "name": "DAPT2020 attacker sequences" if use_dapt else up2.name}
    try:
        df = pd.read_csv(R.path("artifacts/rc_dapt_stages.csv") if use_dapt else up2)
        assert {"episode", "order", "stage"} <= set(df.columns), "the file needs the columns episode, order and stage"
        order = [s_.strip() for s_ in order_txt.split(",") if s_.strip()]
        seqs = {e: g.sort_values("order", kind="stable")["stage"].astype(str).tolist() for e, g in df.groupby("episode", sort=True)}
        stages = sorted(set(order) | set(df["stage"].astype(str)))
        runs = {e: F.collapse_runs(q) for e, q in seqs.items()}
        changing = [r for r in runs.values() if len(r) >= 2]
        steps = sum(len(q) - 1 for q in seqs.values())
        if not changing:
            out["notes"].append(("No episode contains a stage change, so this data cannot test forecasting at all.", True))
        else:
            dg = F.diagnostics(changing, stages)
            n_chg = dg["n_stage_changes"]
            out["tables"].append((["Measure", "Value"], [
                ["Episodes", f"{len(seqs):,}"], ["Steps", f"{steps:,}"],
                ["Stage changes", f"{n_chg:,} ({100 * n_chg / max(steps, 1):.2f}% of steps)"],
                ["Distinct transitions", str(dg["distinct_transitions"])],
                ["Uncertainty of the next stage", f"{dg['cond_entropy_bits']:.3f} bits"],
                ["Best possible for a rule using the current stage", pct(dg["ceiling_first_order"])]], (1,)))
            names = sorted(runs)
            tot = {}
            if len(names) >= 2:
                for held in names:
                    m = F.make_methods([runs[e] for e in names if e != held], stages, order)
                    r = runs[held]
                    for k, fn in m.items():
                        h = sum(fn(r[t]) == r[t + 1] for t in range(len(r) - 1))
                        a = tot.setdefault(k, [0, 0])
                        a[0] += h
                        a[1] += len(r) - 1
                label = {"persistence": "Persistence", "advance_one": "Advance one stage",
                         "majority_next": "Majority next stage", "markov1": "Markov fitted on stage changes"}
                out["tables"].append((["Baseline, leave one episode out", "Correct at stage changes", "95% CI"],
                                      [[label[k], f"{h} of {n}", f"{pct(F.exact_ci(h, n)[0], 0)}&ndash;{pct(F.exact_ci(h, n)[1], 0)}"]
                                       for k, (h, n) in tot.items() if n], (1, 2)))
            adv = tot.get("advance_one", [0, 0])
            if n_chg < 30:
                out["notes"].append((f"Only {n_chg} stage changes: too few for any forecaster to show an advantage over a trivial rule.", True))
            elif adv[1] and adv[0] / adv[1] >= dg["ceiling_first_order"] - 1e-9:
                out["notes"].append(("The one-line rule already reaches the best possible accuracy. No forecaster can show skill on this data.", True))
            else:
                out["notes"].append(("This data leaves room between trivial rules and the ceiling. Report these baselines next to any forecaster's accuracy.", False))
            if steps and n_chg / steps < 0.1:
                out["notes"].append((f"Only {100 * n_chg / steps:.2f}% of steps are stage changes. Accuracy counted over every step would reward "
                                     "predicting no change; report accuracy at stage changes.", True))
    except Exception as e:
        out["notes"].append((f"Could not check this file: {T.esc(e)}.", True))
    st.session_state["fc_result"] = out
    st.rerun()
fc = st.session_state.get("fc_result")
if fc:
    T.sub(f"Forecastability of {T.esc(fc['name'])}")
    for headers, rows, nums in fc["tables"]:
        T.table(headers, rows, num_cols=nums)
    for text, warn in fc["notes"]:
        T.note(text, warn=warn)
