import streamlit as st
import _theme as T

T.setup("Method")
T.masthead("Method", "What we tested, on which data, and how we kept the tests honest.")

T.section("The case study: a streaming pipeline",
          "The system that led to the question. It is the setting, not the contribution.")
T.table(["Stage", "What it does", "Model"], [
    ["Detect", "Flags flows that look unlike normal traffic. Trained on normal traffic only.", "Isolation Forest"],
    ["Classify", "Names the attack type, or answers <i>unknown</i> when its top probability is below &tau; = 0.999.", "XGBoost"],
    ["Forecast", "Predicts the attacker's next kill-chain stage from a transition matrix with a textbook prior.", "Hidden Markov model"],
], cap="Flows are replayed through Apache Kafka and scored as they arrive. An independent re-implementation of the decision rules "
       "matched the live service on 20,000 sampled flows.")

T.section("Data", "Five sources of attack sequences, from fully scripted to the most realistic available.")
T.table(["Source", "What it is", "Used for"], [
    ["CIC-IDS2017 (corrected)", "Five days of lab traffic, 82 flow features. Trained Mon&ndash;Wed, calibrated Thu, tested Fri.", "Detection, schedule audit"],
    ["DAPT2020", "86,691 flows from 11 attacker sources across five days, labelled by stage.", "Forecasting audit, transfer test"],
    ["Ghafir et al. alerts", "3,676 synthetic alerts in 1,000 campaigns, released with a published HMM forecaster.", "Published-result audit"],
    ["Unraveled", "6.88 million flows over six weeks; one APT group and one amateur attacker.", "Concurrency audit"],
    ["Our first evaluation", "200 simulated episodes generated to follow kill-chain order.", "Showing why it was circular"],
])

T.section("The forecastability check", "Three numbers that say whether a dataset can tell forecasters apart at all.")
T.prose("Let C(a, b) count how often stage a is followed by stage b. We report the number of distinct stage changes, "
        "the uncertainty of the next stage given the current one, and the ceiling: the best accuracy any rule using only "
        "the current stage could reach on the data.")
st.latex(r"H(S_{t+1}\mid S_t) = -\sum_a \frac{C(a,\cdot)}{N}\sum_b \frac{C(a,b)}{C(a,\cdot)}\log_2\frac{C(a,b)}{C(a,\cdot)}"
         r"\qquad \pi^\star = \frac{1}{N}\sum_a \max_b C(a,b)")
T.prose("Zero bits of uncertainty means the next stage is fully determined: no forecaster can beat the trivial rule that encodes "
        "the order. Every quantity is computed twice, over every step and over stage changes only, because the two answer different questions.")

T.section("Baselines", "Every forecaster is compared with rules that need no learning.")
T.table(["Rule", "Prediction"], [
    ["Persistence", "The stage does not change."],
    ["Advance one stage", "The attacker moves to the next stage in kill-chain order."],
    ["Majority next stage", "The most common next stage in the training data."],
    ["First-order Markov", "The most likely next stage given the current one, fitted on training sequences, either on every flow or on stage changes only."],
    ["Prefix lookup table", "The most frequent continuation of the exact sequence seen so far (used for the published-forecaster audit)."],
])

T.section("Protocols")
T.bullets([
    "<b>Unseen attacks.</b> Every Friday attack label in CIC-IDS2017 is absent from training. Port scan and botnet are new families; "
    "DDoS is a variant of the DoS attacks seen on Wednesday.",
    "<b>Real attackers.</b> DAPT2020 uses leave-one-attacker-out: each attacker is held out while the rest are used for fitting.",
    "<b>Published result.</b> The Ghafir et al. data uses 20 repeated 50/50 splits, matching the paper's single 50/50 split.",
    "<b>Concurrent stages.</b> Unraveled is analysed in 1-hour, 6-hour and 1-day windows; baselines are fitted on the first half and scored on the second.",
    "<b>Uncertainty.</b> Exact Clopper&ndash;Pearson intervals for small counts, block bootstrap over attackers and hours for ranking scores, and five random seeds.",
    "<b>No peeking.</b> No threshold is chosen on test data, and predictions for the transfer experiment were written down before it ran."])
