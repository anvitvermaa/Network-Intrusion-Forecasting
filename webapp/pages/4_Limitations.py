import streamlit as st
import _theme as T

T.setup("Limitations")
T.masthead("Limitations and corrections", "What this work does not show, and every error we found in our own evaluation.")

T.section("What we do not claim")
T.bullets([
    "That kill-chain forecasting is impossible. Our findings concern what public benchmarks can and cannot show.",
    "A new detector or forecaster. The pipeline is the case study that led to the audit.",
    "Anything about real-world campaigns. All four datasets are laboratory or synthetic captures."])

T.section("Threats to validity")
T.table(["Threat", "What it means for the results"], [
    ["Small samples", "DAPT2020 has 11 stage changes and CIC-IDS2017 five. Intervals are wide (72&ndash;100% for 11 of 11), and we claim no differences between methods that tie."],
    ["One campaign", "Unraveled contains a single APT campaign, so its baselines are compared on at most 12 test changes."],
    ["Published result", "For Ghafir et al. we compare with their reported accuracies, not a re-implementation. Their HMM's states do not match the released step labels exactly, and the public data lacks their 2,300 uncorrelated alerts."],
    ["Stage labels", "Stages are assigned by attack type. In Unraveled, &ldquo;Maintain Access&rdquo; appears as an activity of lateral movement although its documentation lists it as a stage, and the skilled-hacker group it describes does not appear."],
    ["Dependence between flows", "Flows from one attacker are not independent. Ranking-score intervals therefore resample whole attackers and hours, and CIC-IDS2017 intervals assume its rows are in time order."],
    ["Survey coverage", "The survey was targeted, not systematic, and covers only the 11 papers we could read in full."],
])

T.section("Corrections log", "Each error was caught by a check that compared a result with something simpler.")
T.table(["What was wrong", "How it was found", "What changed"], [
    ["The classifier was trained on a random split that included the test day.", "A time-ordered split.", "Unseen-attack recall fell from an inflated 99.2% to the honest figures on the Findings page."],
    ["The forecaster was evaluated on simulated episodes generated to follow kill-chain order.", "The &ldquo;advance one stage&rdquo; baseline.", "Replaced with real attacker sequences from DAPT2020 and three further sources."],
    ["The audit tool averaged the classifier veto over attack types and passed our own system.", "Running the tool on our own predictions.", "Every attack type is now checked separately."],
    ["The paper first quoted Ghafir et al.'s two-guess accuracies as plain accuracy.", "Reading the original paper's results table.", "Single- and two-guess accuracies are now reported separately."],
    ["A cited preprint had been withdrawn by its authors.", "Checking every reference against its source.", "Removed and replaced with verified work."],
    ["The fitted Markov model on DAPT2020 was trained only on every flow.", "A review of our own claims.", "Added the same model fitted on stage changes (11 of 11), and reworded the claim."],
    ["Tied baselines were broken in an order that varied between runs.", "Two machines disagreeing on one score.", "Ties are now broken deterministically."],
])

T.section("Questions an examiner might ask")
QA = [
    ("Your forecaster ties a one-line rule. Isn't it broken?",
     "No. On DAPT2020 every real stage change follows textbook order, so the rule is already perfect and nothing can beat it. "
     "The forecaster ties it because its prior encodes the same order. That is a property of the benchmark, which the forecastability check measures."),
    ("Isn't the Markov model's 0 of 11 unfair?",
     "Yes, if it stood alone, which is why we report both versions. Fitted on every flow it learns that attackers stay put; fitted on stage "
     "changes it scores 11 of 11, exactly like the rule. Either way it shows no forecasting skill, and what it is trained on decides the result."),
    ("Why should anyone trust the comparison with a published paper?",
     "We say exactly where it is weaker: we use their reported numbers, our grouping of alerts is perfect, and part of their data is not public. "
     "Even with those caveats, a table that memorises paths reaches their accuracy, and the script that shows it runs on the Run page."),
    ("Is the detection result a zero-day result?",
     "Port scan and botnet are new families. DDoS is a variant of DoS attacks seen in training, which is why the classifier still catches it, "
     "and why the headline recall is dominated by it."),
    ("How do we know these numbers are real?",
     "Every number is produced by a script, reproduced on a second machine, and can be re-run from the Run page, which marks each value as matching the paper or not."),
]
for q, a in QA:
    with st.expander(q):
        T.prose(a)
