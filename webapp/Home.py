import streamlit as st
import _paper as P
import _theme as T

T.setup("Counting Flows, Not Transitions")
T.masthead(P.TITLE, P.DEK, P.AUTHORS)

T.prose("Forecasters that predict an attacker's next kill-chain stage report accuracies of 90% and more. "
        "We asked whether those numbers can be trusted. On every public benchmark we could test, they cannot: "
        "the answer is decided by how steps are counted and by how the data was scripted, not by the model.")

T.table(["Same forecasters, same data", "Counted over every flow", "Counted at the 11 real stage changes"],
        [[r[0], r[1], r[2]] for r in P.DAPT if r[0] in (
            "Persistence (next = current)", "Markov, fitted on every flow", "Advance one stage", "Deployed HMM (hand-written prior)")],
        cap="DAPT2020, 11 real attackers, leave-one-attacker-out. Counting every flow makes &ldquo;nothing changes&rdquo; look perfect; "
            "counting only the moments an attacker actually moves reverses the ranking.",
        num_cols=(1, 2))

T.section("The problem")
T.prose("A kill-chain forecaster watches an intrusion and predicts the attacker's next stage: reconnaissance, initial compromise, "
        "lateral movement, exfiltration. If the prediction is right, defenders gain time. Published forecasters report high accuracy, "
        "but almost never say what a trivial rule would score on the same data, or how predictable the data is to begin with. "
        "Of the nine stage-forecasting papers we read in full, none compares with a trivial rule.")

T.section("What we did")
T.prose("We built a streaming intrusion pipeline that detects unusual network flows, names known attacks, and forecasts the next stage. "
        "Testing it honestly exposed two errors in our own evaluation, and led to the real question. We then audited stage forecasting "
        "on five sources of attack sequences with four one-line baselines and a forecastability check: how many distinct stage changes "
        "the data contains, how uncertain the next stage is, and the best accuracy any rule could reach.")

T.section("What we found")
T.bullets([
    "<b>DAPT2020, real attackers.</b> All 11 stage changes follow textbook order, with zero uncertainty. &ldquo;Advance one stage&rdquo; is "
    "right 11 of 11 times. A Markov model is right 0 of 11 times when fitted on every flow and 11 of 11 when fitted on stage changes: "
    "what the model is trained and scored on decides the result.",
    "<b>The dataset behind a published forecaster.</b> On Ghafir et al.'s public data (2,286 stage changes), a lookup table of observed "
    "paths matches or beats the published HMM: 45.6% against 43.6% after two alerts, 95.5% against 93.3% after four.",
    "<b>Unraveled, six weeks of an emulated APT.</b> Half of all time windows contain two or more stages at once, so &ldquo;the next "
    "stage&rdquo; is not well defined, and the best method changes with the window size.",
    "<b>The pipeline itself.</b> On attack types absent from training, the classifier overrules 70.9% of the detector's correct port-scan "
    "alarms. On a second network, every detector ranks attacks only slightly above normal traffic (AUROC 0.59&ndash;0.68)."])

T.section("What it means")
T.prose("Public benchmarks cannot currently tell a good stage forecaster from a one-line rule. Before reporting forecasting accuracy, "
        "report trivial baselines, count at stage changes, and check how predictable the data is. We release the checks as a tool, "
        "and the Run page executes them live.")
T.note("Two errors in our own first evaluation were caught by exactly these checks: a training split that leaked the test day, and a "
       "forecasting test on simulated episodes built to follow the kill chain. Both are documented on the Limitations page.")

st.page_link("pages/3_Run.py", label="Run the checks yourself")
st.page_link("pages/2_Findings.py", label="Read the full findings")
