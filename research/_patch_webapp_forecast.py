
#!/usr/bin/env python3

"""Replace the synthetic forecasting claims on the website with the real DAPT2020 / CIC-IDS2017 audit,

and label research/forecast_eval.py as synthetic. Every edit must match exactly once, or nothing is written."""

import sys

 

EDITS = {}

 

 

def edit(path, old, new):

    EDITS.setdefault(path, []).append((old, new))

 

 

# ---------------- webapp/_data.py ----------------

edit("webapp/_data.py",

     "def forecasts_source():",

     '''@st.cache_data

def forecast_audit():

    return _json("forecast_audit.json")

 

 

def figure_path(name):

    p = os.path.join(DATA, "figures", name)

    return p if os.path.exists(p) else None

 

 

def forecast_summary():

    """Key forecasting numbers from forecast_audit.json, or None if the file is missing."""

    fa = forecast_audit()

    if not fa or "dapt2020" not in fa:

        return None

    d = fa["dapt2020"]

    f = d["flows_k1_loo"]

    n = f["advance_one"]["n_changes"]

 

    def hits(m):

        return int(round((f[m]["acc_changes"] or 0) * n))

    cic = fa.get("cic_schedule", {})

    cic_adv = cic.get("k1_runs_fixed_rules", {}).get("advance_one", {})

    return {"n_changes": n, "n_steps": f["advance_one"]["n_all"], "n_attackers": len(d.get("attacker_paths", {})),

            "advance_hits": hits("advance_one"), "markov_hits": hits("markov1"), "hmm_hits": hits("project_hmm"),

            "persist_all": f["persistence"]["acc_all"], "markov_all": f["markov1"]["acc_all"],

            "entropy_runs": d.get("diagnostics_runs", {}).get("cond_entropy_bits"),

            "distinct": d.get("diagnostics_runs", {}).get("distinct_transitions"),

            "cic_path": cic.get("collapsed_path", []), "cic_adv": cic_adv.get("acc_changes"),

            "cic_changes": cic_adv.get("n_changes"),

            "syn": fa.get("synthetic", {}).get("k", {}).get("1", {})}

 

 

def forecasts_source():''')

 

# ---------------- webapp/_style.py ----------------

edit("webapp/_style.py",

     ".figure .cap, .tblcap { font-size: 15.5px; color: #5E5A52; line-height: 1.5; max-width: 44em; margin-top: 0.6rem; }",

     ".figure .cap, .tblcap { font-size: 15.5px; color: #5E5A52; line-height: 1.5; max-width: 44em; margin-top: 0.6rem; margin-bottom: 1.6rem; }\n[data-testid=\"stImage\"] img { border: 1px solid #CFC8B8; }")

 

# ---------------- webapp/Home.py ----------------

edit("webapp/Home.py",

     "lk = D.leaky()",

     "lk = D.leaky()\nfs = D.forecast_summary()")

edit("webapp/Home.py",

     '''          f"because its flows look statistically like normal traffic. And the stage forecaster is right {pct(D.FACTS['osp'])} of the time one step ahead, "

          f"less than the {pct(D.FACTS['naive_osp'])} achieved by simply assuming the attacker advances one stage.</p>")''',

     '''          f"because its flows look statistically like normal traffic. And the stage forecaster cannot be judged on public data: "

          + (f"on DAPT2020's {fs['n_attackers']} real attackers, every one of the {fs['n_changes']} stage changes follows textbook order, "

             f"so the one-line rule \\u201cthe attacker advances one stage\\u201d is right {fs['advance_hits']} of {fs['n_changes']} times, "

             f"while a model fitted to the data learns only that attackers stay put and gets {fs['markov_hits']} of {fs['n_changes']}. "

             f"The Results page explains why.</p>" if fs else "the public benchmarks contain too few real stage changes. The Results page explains why.</p>"))''')

edit("webapp/Home.py",

     '''            f'<span class="now">{ps("A_plus_temporalB_plus_UNKNOWN")}</span>. The live system on this site runs the corrected model.</p></div>')''',

     '''            f'<span class="now">{ps("A_plus_temporalB_plus_UNKNOWN")}</span>. The live system on this site runs the corrected model.</p></div>')

    if fs and fs.get("syn"):

        sy = fs["syn"]

        raw('<div class="erratum"><div class="head">Correction, 2 October 2026</div>'

            '<p>The stage forecaster was first evaluated on 200 simulated attack episodes, generated to follow kill-chain order. '

            f'That test reported <span class="was">{pct(sy["project_hmm"]["acc_all"])} for the forecaster against {pct(sy["advance_one"]["acc_all"])} for '

            '\\u201cadvance one stage\\u201d</span>. Because the episodes were built to advance one stage, the test was circular.</p>'

            f'<p>We re-ran it on real attacker sequences from DAPT2020. At the {fs["n_changes"]} real stage changes, the forecaster and the one-line rule are both '

            f'<span class="now">{fs["hmm_hits"]} of {fs["n_changes"]}</span> correct, and a model fitted to the data gets '

            f'<span class="now">{fs["markov_hits"]} of {fs["n_changes"]}</span>. The data cannot tell a good forecaster from a trivial rule.</p></div>')''')

 

# ---------------- webapp/pages/2_Results.py ----------------

edit("webapp/pages/2_Results.py",

     '''raw("<h2>Forecasting the next stage</h2>")

F = D.FACTS

table(["Method", "Next stage correct", "Source"], [

    ["This project, 1 step ahead", pct(F["osp"]), "Viterbi on held-out episodes"],

    ["This project, 2 steps ahead", pct(F["tsp"]), ""],

    ["This project, 3 steps ahead", pct(F["sp3"]), ""],

    ["Naive: always advance one stage", pct(F["naive_osp"]), "Baseline"],

    ["Ghafir et al., HMM", pct(F["ghafir_osp"]), "Published, different data"],

    ["E-HiDNet (2026)", pct(F["ehidnet_osp"], 0), "Published, different data"],

], num_cols=(1,))

caption("<b>Table 5.</b> The forecaster loses to the naive baseline. CIC-IDS2017 has one attack type per day and almost no real multi-stage campaigns, "

        "so the model has little to learn from and falls back on its prior. Published figures use other datasets and are not directly comparable.")''',

     '''raw("<h2>Forecasting the next stage</h2>")

F = D.FACTS

fa = D.forecast_audit()

if fa and "dapt2020" in fa:

    d = fa["dapt2020"]

    f1 = d["flows_k1_loo"]

    n_chg = f1["advance_one"]["n_changes"]

    n_steps = f1["advance_one"]["n_all"]

    prose("<p>Forecasting cannot be tested on CIC-IDS2017's flows, because our version has no attacker addresses or timestamps. "

          "An earlier version of this project therefore tested the forecaster on simulated episodes, which were generated to follow kill-chain order, "

          "so the test was circular. We replaced it with real attacker sequences from DAPT2020, a dataset built for this purpose: "

          f"{len(d.get('attacker_paths', {}))} attacker sources, each followed in time order. Each attacker is held out in turn while the "

          "methods are fitted on the others.</p>")

    names = {"persistence": "Persistence: next stage = current stage", "advance_one": "Advance one stage in kill-chain order",

             "majority_next": "Most common next stage", "markov1": "Markov model fitted on the data",

             "project_hmm": "Deployed HMM (its prior encodes kill-chain order)", "project_method_refit": "Same HMM recipe, refitted on the data"}

    rows = []

    for m in ["persistence", "markov1", "project_method_refit", "majority_next", "advance_one", "project_hmm"]:

        if m in f1:

            a = f1[m]

            v = a["acc_all"] or 0.0

            rows.append([names[m], "<1%" if 0 < v < 0.01 else (">99%" if 0.99 < v < 1 else pct(v, 1)),

                         f"{pct(a['acc_changes'], 0)}<br><span class='small'>{ci(a['acc_changes_exact95'], 0)}</span>"])

    table(["Method", f"Every flow counted ({n_steps:,} steps)", f"Only real stage changes ({n_chg} steps, 95% CI)"], rows, num_cols=(1, 2))

    caption("<b>Table 5.</b> Next-stage accuracy on DAPT2020 real attackers, leave-one-attacker-out. Intervals are exact (Clopper–Pearson), "

            "which matters when every answer is right or every answer is wrong.")

    p1 = D.figure_path("fig1_counting_flips_ranking.png")

    if p1:

        st.image(p1)

        caption("<b>Figure 6.</b> The same methods scored two ways. Counting every flow rewards predicting \\u201cno change\\u201d, because attackers stay in one stage "

                f"for thousands of flows; only {n_chg} of {n_steps:,} steps are real stage changes. Counted only at those changes, the ranking reverses.")

    prose("<p>Two things follow. First, accuracy depends on what is counted: the same model scores near 100% or 0%. "

          "Second, models fitted to the data learn that attackers stay put. The deployed HMM gets stage changes right only because "

          "its hand-written prior encodes the textbook order, which is the same thing the one-line rule does.</p>")

    p2 = D.figure_path("fig2_transitions.png")

    if p2:

        st.image(p2)

        dr = d.get("diagnostics_runs", {})

        caption(f"<b>Figure 7.</b> Which stage changes actually occur. In DAPT2020 every real change falls on the textbook path "

                f"({dr.get('distinct_transitions', '?')} distinct transitions, {dr.get('cond_entropy_bits', 0):.3f} bits of uncertainty about the next stage), "

                "so no method can beat \\u201cadvance one stage\\u201d. CIC-IDS2017's weekly schedule moves backwards and puts reconnaissance near the end.")

    cic = fa.get("cic_schedule", {})

    if cic.get("collapsed_path"):

        adv = cic.get("k1_runs_fixed_rules", {}).get("advance_one", {})

        prose("<p>CIC-IDS2017's real attack order across the week, with repeats removed, is "

              + " → ".join(D.stage(s) for s in cic["collapsed_path"])

              + f". \\u201cAdvance one stage\\u201d and the deployed HMM each get {pct(adv.get('acc_changes'), 0)} of its {adv.get('n_changes', '?')} changes right. "

              "The attacks were scheduled by day, not run as one campaign, so the benchmark cannot evaluate kill-chain forecasting.</p>")

    aside("The finding is about the benchmarks, not about HMMs: with this little and this regular data, no forecaster can be distinguished from a trivial rule. "

          "Published stage-forecasting results are rarely reported against such rules.")

else:

    D.missing("forecast_audit.json")''')

 

# ---------------- webapp/pages/4_Limitations.py ----------------

edit("webapp/pages/4_Limitations.py",

     '''raw("<h3>The stage forecaster does not beat a simple rule</h3>")

prose(f"<p>It predicts the next stage correctly {pct(F['osp'])} of the time, while “assume the attacker advances one stage” scores {pct(F['naive_osp'])}. "

      "The cause is the data: CIC-IDS2017 runs one attack type per day and contains only about two genuine stage-to-stage transitions. "

      "The model therefore relies on its prior, which encodes the same rule less directly. The forecasting machinery works end to end; "

      "it simply has no multi-stage campaigns to learn from.</p>")''',

     '''raw("<h3>The stage forecaster cannot be told apart from a simple rule</h3>")

fs = D.forecast_summary()

if fs:

    prose(f"<p>On DAPT2020's real attackers there are only {fs['n_changes']} stage changes, and every one follows textbook order. "

          f"\\u201cAdvance one stage\\u201d gets {fs['advance_hits']} of {fs['n_changes']} right, the deployed HMM {fs['hmm_hits']}, "

          f"and a model fitted to the data {fs['markov_hits']}. CIC-IDS2017 has only {fs.get('cic_changes') or 'a handful of'} stage changes in its weekly schedule, "

          "and they do not follow kill-chain order. With so few and such regular examples, a learned forecaster cannot show any advantage, "

          "and the HMM's correct answers come from its hand-written prior. The forecasting machinery works end to end; the public data cannot test it.</p>")

else:

    prose("<p>The public benchmarks contain too few real stage changes to evaluate a forecaster.</p>")''')

edit("webapp/pages/4_Limitations.py",

     '''prose("<p><b>Test the forecaster on data with real campaigns.</b> Datasets built for this already exist: DAPT2020 covers reconnaissance, foothold, "

      "lateral movement and exfiltration, and Unraveled (2023) spans six weeks of emulated attackers. Running the same forecaster on them would show "

      "whether it beats the naive rule when real transitions exist.</p>"''',

     '''prose("<p><b>Test forecasting on data with varied campaigns.</b> DAPT2020 turned out to be fully scripted. Datasets with more attackers and less regular paths, "

      "such as Unraveled (2023, six weeks of emulated attackers) or the AIT alert data set, would show whether learned forecasters add anything "

      "when the next stage is genuinely uncertain.</p>"''')

edit("webapp/pages/4_Limitations.py",

     "qa = [\n",

     '''qa = [

    ("Your forecaster loses to a naive rule. Isn't it broken?",

     "No. It ties the rule exactly where it matters. On DAPT2020's real attackers, every stage change follows textbook order, so the rule "

     "\\u201cadvance one stage\\u201d is already perfect and nothing can beat it. The earlier 69.4% against 74.7% came from simulated episodes and from counting "

     "steps where the stage does not change. We replaced that test and report the real one."),

''')

 

# ---------------- research/forecast_eval.py ----------------

edit("research/forecast_eval.py",

     '"""RESEARCH - Forecast Earliness Evaluation (n-step-ahead prediction accuracy).',

     '"""RESEARCH - Forecast Earliness Evaluation (n-step-ahead prediction accuracy).\n\nWARNING: this script evaluates on SYNTHETIC episodes from make_kill_chain_episodes(), which are generated\nto follow kill-chain order. Its numbers are not results on real data. See research/forecast_audit.py.')

edit("research/forecast_eval.py",

     '"benchmark_note": "Ghafir HMM ~43.6% OSP baseline"}, f, indent=2)',

     '"benchmark_note": "Ghafir HMM ~43.6% OSP baseline",\n                   "warning": "SYNTHETIC episodes generated to follow kill-chain order; not a real-data result. See artifacts/forecast_audit.json."}, f, indent=2)')

 

# ---------------- apply (all or nothing) ----------------

staged = {}

for path, pairs in EDITS.items():

    try:

        src = open(path).read()

    except FileNotFoundError:

        print(f"[FAIL] missing file {path}. Nothing written.")

        sys.exit(1)

    for old, new in pairs:

        c = src.count(old)

        if c != 1:

            print(f"[FAIL] {path}: expected 1 match, found {c} for:\n{old[:200]}\nNothing written.")

            sys.exit(1)

        src = src.replace(old, new)

    staged[path] = src

for path, src in staged.items():

    open(path, "w").write(src)

    print(f"[OK] {path}: {len(EDITS[path])} edit(s)")

