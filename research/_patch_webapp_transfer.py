

#!/usr/bin/env python3

"""Add the DAPT2020 cross-network results and a 'What survived honest testing' table to the website.

Requires the forecasting patch (_patch_webapp_forecast.py) to have been applied first.

All edits must match exactly once, or nothing is written."""

import sys

 

EDITS = {}

 

 

def edit(path, old, new):

    EDITS.setdefault(path, []).append((old, new))

 

 

# ---------------- prerequisite check ----------------

try:

    _d = open("webapp/_data.py").read()

except FileNotFoundError:

    sys.exit("[FAIL] webapp/_data.py not found. Run this from ~/network-intrusion-forecasting. Nothing written.")

if "def forecast_summary" not in _d:

    sys.exit("[FAIL] The forecasting patch has not been applied yet. Run research/_patch_webapp_forecast.py first. Nothing written.")

if "def dapt_transfer" in _d:

    sys.exit("[FAIL] This patch is already applied. Nothing written.")

 

# ---------------- webapp/_data.py ----------------

edit("webapp/_data.py",

     "def forecasts_source():",

     '''@st.cache_data

def dapt_transfer():

    return _json("dapt_transfer.json")

 

 

@st.cache_data

def dapt_check():

    return _json("dapt_transfer_check.json")

 

 

def auroc_range():

    """(min, max) AUROC over the detectors trained with all shared features, or None."""

    ck = dapt_check()

    if not ck:

        return None

    vals = [v.get("auroc") for k, v in ck.get("check1_auroc", {}).items() if not k.endswith("no_artefacts") and v.get("auroc") is not None]

    return (min(vals), max(vals)) if vals else None

 

 

def forecasts_source():''')

 

# ---------------- webapp/Home.py: 'What survived' table + transfer finding ----------------

edit("webapp/Home.py",

     "from _style import page, raw, prose, figure, aside, pct, INK, GRAPHITE, BLUE, PAPER",

     "from _style import page, raw, prose, figure, aside, pct, table, caption, INK, GRAPHITE, BLUE, PAPER")

edit("webapp/Home.py",

     '''      "gives defenders a chance to act before the later, costlier stages.</p>")''',

     '''      "gives defenders a chance to act before the later, costlier stages.</p>")

 

# ---- What survived honest testing ----

raw("<h2>What survived honest testing</h2>")

prose("<p>Every headline claim below was tested twice. The first result came from an evaluation with a flaw; the second from a corrected one. "

      "This site reports only the second.</p>")

_rows = []

if te and lk:

    _o, _od = te["test_overall"]["A_plus_temporalB_plus_UNKNOWN"], lk["overall_detection"]

    _rows.append(["Detects attacks it has never seen",

                  f"{pct(_od['recall'])} caught, {pct(_od['false_alarm_rate'], 4)} false alarms",

                  f"<b>{pct(_o['recall'])} caught, {pct(_o['false_alarm_rate'], 2)} false alarms</b>",

                  "The classifier had been trained on data that included the test day"])

    _old_ps = lk.get("two_stage_benefit", {}).get("Portscan", {}).get("with_classifier")

    _new_ps = te["test_per_class"]["A_plus_temporalB_plus_UNKNOWN"]["Portscan"]["detection_rate"]

    if _old_ps is not None:

        _rows.append(["Detects unseen port scans", pct(_old_ps), f"<b>{pct(_new_ps)}</b>",

                      "The classifier overrules the detector on attacks it does not recognise"])

if fs and fs.get("syn"):

    _sy = fs["syn"]

    _rows.append(["Forecasts the attacker's next stage",

                  f"{pct(_sy['project_hmm']['acc_all'])} vs {pct(_sy['advance_one']['acc_all'])} for a one-line rule",

                  f"<b>Ties the rule: {fs['hmm_hits']} of {fs['n_changes']} on real attackers</b>",

                  "The first test used simulated episodes; the real data is too predictable to tell them apart"])

_ar = D.auroc_range()

if _ar:

    _rows.append(["Works on a different network", "Not tested",

                  f"<b>Weak: ranking score {_ar[0]:.2f}–{_ar[1]:.2f} (0.5 = chance)</b>",

                  "Normal traffic differs between networks, and stealthy attacks look normal"])

if _rows:

    table(["Claim", "First result", "After honest testing", "Why it changed"], _rows)

    caption("<b>Summary.</b> The project's four main claims, before and after correction. Each correction is explained on the Results page.")

else:

    D.missing("temporal_eval.json")''')

edit("webapp/Home.py",

     '''    raw('<div class="pull">A classifier trained only on known attacks does not just fail to name new ones. It overrules the detector that found them.</div>')''',

     '''    _tr = D.dapt_transfer()

    if _tr and _ar:

        _e1 = _tr["experiments"]["E1_deployed_zero_shot"]

        prose(f"<p><b>It does not carry over to a different network.</b> Run on DAPT2020, a separate test network, the deployed detector "

              f"flags {pct(_e1['detector_only']['far'])} of normal traffic. Measured without any threshold, every detector we tried ranks that network's "

              f"attacks only weakly above its normal traffic (ranking score {_ar[0]:.2f}–{_ar[1]:.2f}, where 0.5 is chance), "

              "including one retrained on that network's own normal traffic.</p>")

    raw('<div class="pull">A classifier trained only on known attacks does not just fail to name new ones. It overrules the detector that found them.</div>')''')

 

# ---------------- webapp/pages/2_Results.py: cross-network section ----------------

edit("webapp/pages/2_Results.py",

     'raw("<h2>Engineering checks</h2>")',

     '''raw("<h2>Does it work on a different network?</h2>")

tr_ = D.dapt_transfer()

ck_ = D.dapt_check()

if tr_ and ck_:

    ex = tr_["experiments"]

    any_lvl = ex["E1_deployed_zero_shot"]["detector_only"]

    prose(f"<p>Everything above was measured on one network. We then ran the system on DAPT2020, a separate test network with its own normal traffic "

          f"and its own attacks: {any_lvl['benign_flows']:,} normal and {any_lvl['attack_flows']:,} attack flows from Tuesday to Friday. "

          f"DAPT2020 was recorded with an older version of the same flow tool, so {len(tr_.get('features_missing_in_dapt', []))} of the 82 features are missing. "

          "We tested three ways of moving the system across:</p>")

    names = [("E1_deployed_zero_shot", "As deployed", "The frozen models, missing features filled with typical values"),

             ("E2_shared_feature_retrain", "Retrained on shared features", "Same recipe, retrained on the original network using only features both have"),

             ("E3_local_benign_refit", "Detector relearns local normal", "The detector is refitted on the new network's Monday, which is all normal traffic")]

    rows = []

    for key, short, how in names:

        r_det, r_full = ex[key]["detector_only"], ex[key]["detector_plus_classifier_plus_unknown"]

        rows.append([f"<b>{short}</b><br><span class='small'>{how}</span>",

                     f"{pct(r_det['far'])}", f"{pct(r_det['recall'])}", f"{pct(r_full['far'])}", f"{pct(r_full['recall'])}"])

    table(["Approach", "Detector: false alarms", "Detector: attacks caught", "Full system: false alarms", "Full system: attacks caught"], rows, num_cols=(1, 2, 3, 4))

    caption("<b>Cross-network test.</b> DAPT2020, Tuesday to Friday. The detector's threshold was set to flag the same share of normal traffic as on the original network. "

            "Full system = detector, classifier and the unknown option.")

 

    c1 = ck_["check1_auroc"]

    prose("<p>A single threshold can hide or exaggerate a detector's ability. So we also measured how well each detector's score <i>ranks</i> attacks above "

          "normal traffic, regardless of threshold: 0.5 means no better than chance, 1.0 means every attack scores above every normal flow, "

          "and below 0.5 means attacks look more normal than normal traffic.</p>")

    label = {"E1_deployed_detector": "As deployed", "E2_detector_shared": "Retrained on shared features", "E3_detector_shared": "Relearns local normal"}

    recs = []

    for key, nm in label.items():

        for act, e in c1.get(key, {}).get("per_activity", {}).items():

            recs.append({"detector": nm, "activity": act, "auroc": e["auroc"], "n": e["n"]})

    if recs:

        dfa = pd.DataFrame(recs)

        order = dfa.groupby("activity")["n"].max().sort_values(ascending=False).index.tolist()

        cmap = {"As deployed": QUIET, "Retrained on shared features": BLUE, "Relearns local normal": OCHRE}

        legend(list(cmap.items()))

        pts = alt.Chart(dfa).mark_point(filled=True, size=90).encode(

            y=alt.Y("activity:N", sort=order, title=None, axis=alt.Axis(labelLimit=220)),

            x=alt.X("auroc:Q", scale=alt.Scale(domain=[0.25, 0.85], nice=False, zero=False), axis=alt.Axis(title="Ranking score (AUROC); 0.5 = chance", format=".1f", values=[0.3, 0.4, 0.5, 0.6, 0.7, 0.8])),

            color=alt.Color("detector:N", scale=alt.Scale(domain=list(cmap), range=list(cmap.values()))),

            tooltip=[alt.Tooltip("detector:N"), alt.Tooltip("activity:N"), alt.Tooltip("auroc:Q", format=".3f"), alt.Tooltip("n:Q", format=",")])

        chance = alt.Chart(pd.DataFrame({"x": [0.5]})).mark_rule(color=CARMINE, strokeDash=[4, 4]).encode(x="x:Q")

        show_chart(chart_style(alt.layer(chance, pts), height=46 * len(order) + 50))

        overall = ", ".join(f"{nm.lower()} {c1[k]['auroc']:.2f}" for k, nm in label.items() if k in c1)

        caption(f"<b>Figure 8.</b> Ranking score per attack type on DAPT2020 (dashed line = chance). Overall: {overall}. "

                "Account discovery falls below chance for the detector that learned the new network's normal traffic: its flows look more normal than normal traffic.")

 

    c2 = ck_.get("check2_without_artefacts", {})

    e2a = c2.get("E2_shared_feature_retrain", {}).get("detector_plus_classifier_plus_unknown")

    e2b = ex["E2_shared_feature_retrain"]["detector_plus_classifier_plus_unknown"]

    if e2a:

        top = ", ".join(f[0] for f in tr_.get("drift_ks_top", [])[:3])

        prose(f"<p><b>Is the older flow tool to blame?</b> Three features ({top}) look completely different between the two networks' normal traffic, "

              "which suggests the two tool versions compute them differently. Removing them barely changes anything: the retrained system catches "

              f"{pct(e2a['recall'])} of attacks at {pct(e2a['far'])} false alarms, against {pct(e2b['recall'])} at {pct(e2b['far'])} with them. "

              "The tool version is not why the system struggles.</p>")

    aside("The system does not transfer to a new network, and even local normal traffic does not fix it. This matches published cross-dataset studies "

          "of flow-based detectors. One caution: the ranking scores treat every flow as independent, so their true uncertainty is wider than a simple interval would suggest.")

else:

    D.missing("dapt_transfer.json and dapt_transfer_check.json")

 

raw("<h2>Engineering checks</h2>")''')

 

# ---------------- webapp/pages/4_Limitations.py ----------------

edit("webapp/pages/4_Limitations.py",

     '''raw("<h3>One dataset, recorded in 2017</h3>")

prose("<p>All results come from one network over five days. Drift monitoring already shows that "

      f"{F['drift_features']} monitored features change between training and test days. A second dataset would be needed to claim the results generalise.</p>")''',

     '''raw("<h3>It does not transfer to a different network</h3>")

ar_ = D.auroc_range()

tr_ = D.dapt_transfer()

if ar_ and tr_:

    e1_ = tr_["experiments"]["E1_deployed_zero_shot"]["detector_only"]

    prose(f"<p>Tested on DAPT2020, a second network, the deployed detector flags {pct(e1_['far'])} of normal traffic, and every detector we tried "

          f"ranks attacks only weakly above normal traffic (ranking score {ar_[0]:.2f}–{ar_[1]:.2f}, where 0.5 is chance), even after relearning "

          "that network's normal traffic. Some stealthy activity, such as account discovery, looks more normal than normal traffic. "

          "Flow statistics alone are not enough; host logs or behaviour over longer periods would be needed.</p>")

else:

    prose("<p>The detection results come from one network. A second network is needed to claim they generalise.</p>")''')

edit("webapp/pages/4_Limitations.py",

     "qa = [\n",

     '''qa = [

    ("Why does it fail on the second network?",

     "Normal traffic looks different on every network, so a model of one network's normal flags much of another's. We also retrained the detector on "

     "the new network's own normal traffic, and it still ranked attacks only weakly above normal. That points to the features: per-flow statistics "

     "cannot separate these attacks. We ruled out the obvious alternative, that the older flow tool caused it, by removing the affected features."),

''')

 

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
