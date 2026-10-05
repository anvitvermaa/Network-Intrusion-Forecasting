import streamlit as st
import _paper as P
import _theme as T

T.setup("Findings")
T.masthead("Findings", "Every number here is reproduced by a script; the Run page executes them.")

T.section("How predictable are the benchmarks?",
          "If the next stage is already determined, no forecaster can show skill.")
T.table(["Source", "Stage changes", "Distinct", "Uncertainty (bits)", "Best possible"],
        [list(r) for r in P.FORECASTABILITY], num_cols=(1, 2, 3, 4),
        cap="&ldquo;Best possible&rdquo; is the highest accuracy any rule using only the current stage can reach on that data.")
T.figure("paper/figures/fig2_transitions.png",
         "Which stage changes occur. Outlined cells are what &ldquo;advance one stage&rdquo; predicts. Every real change in DAPT2020 "
         "falls on an outlined cell; the CIC-IDS2017 schedule moves backwards.")

T.section("DAPT2020: what you count decides who wins")
T.table(["Forecaster", "Every flow", "At stage changes", "95% CI"], [list(r) for r in P.DAPT],
        num_cols=(1, 2, 3), highlight=(1, 3),
        cap="The highlighted rows are the same Markov model. Fitted on every flow, it learns that attackers stay put; "
            "fitted on stage changes, it rediscovers the textbook order. Neither shows forecasting skill.")
T.figure("paper/figures/fig1_counting_flips_ranking.png",
         "The same forecasters scored two ways. Only 11 of 22,968 steps are real stage changes.")

T.section("The dataset behind a published forecaster",
          "Ghafir et al. (IEEE Access 2019) released the alerts their HMM was evaluated on.")
T.table(["Alerts seen", "HMM, 1 guess", "Lookup, 1 guess", "HMM, 2 guesses", "Lookup, 2 guesses"],
        [list(r) for r in P.GHAFIR], num_cols=(0, 1, 2, 3, 4),
        cap="The published HMM against a table that memorises which path usually comes next (20 repeated 50/50 splits). "
            "The headline 66.5%, 92.7% and 100% in the original abstract are two-guess accuracies. We compare with the reported "
            "numbers and did not re-implement the HMM; our grouping of alerts is error-free, which makes our task easier.")

T.section("Unraveled: the attacker is in several stages at once")
T.table(["Window", "Active windows", "Two or more stages", "Stage changes", "Distinct", "Bits", "Best rule, second half"],
        [list(r) for r in P.UNRAVELED], num_cols=(1, 2, 3, 4, 5),
        cap="One APT campaign over six weeks. From 21 June to 2 July, foothold, lateral movement and exfiltration run every day. "
            "With at most 12 test changes, no difference between rules is meaningful; the window size decides the answer.")

T.section("How the field evaluates forecasters",
          "Eleven forecasting papers read in full: six peer-reviewed, five preprints.")
T.table(["Paper", "Predicts", "Evaluation data", "Data", "Trivial baseline"], [list(r) for r in P.SURVEY], small=True,
        cap="The two papers that compare with trivial rules forecast events or actions, not kill-chain stages. None of the 11 reports "
            "how predictable its data is. The search was targeted, not systematic; paywalled papers were not examined.")

T.section("Detection on unseen attacks", "CIC-IDS2017 Friday. No Friday attack label appears in training.")
T.table(["Pipeline", "Attacks caught", "False alarms", "False alarm count"], [list(r) for r in P.FRIDAY],
        num_cols=(1, 2, 3), highlight=(3,))
T.table(["Attack type", "Detector only", "+ classifier", "+ abstain", "AUROC"], [list(r) for r in P.PER_TYPE], num_cols=(1, 2, 3, 4),
        cap="DDoS is 97.5% of Friday's attacks and carries the headline. The classifier overrules 70.9% of the detector's correct "
            "port-scan alarms and all of its botnet alarms. Overall AUROC 0.908 (block-bootstrap 95% CI 0.897&ndash;0.917).")

T.section("Moving the pipeline to another network", "Trained on CIC-IDS2017, tested on DAPT2020 Tuesday to Friday.")
T.table(["Approach", "Detector false alarms", "Detector recall", "System false alarms", "System recall", "AUROC"],
        [list(r) for r in P.TRANSFER], num_cols=(1, 2, 3, 4, 5),
        cap="AUROC intervals resample whole attackers and hours of normal traffic; &plusmn; is the spread over five random seeds. "
            "Account discovery scores below chance (0.32&ndash;0.39) in every seed: its flows look more normal than normal traffic.")

T.section("The audit tool on our own system")
T.table(["Check", "CIC-IDS2017 Friday", "DAPT2020"],
        [[f"{k}. {P.CHECK_NAMES[k]}", P.REALITY_CHECK_FRIDAY[k], P.REALITY_CHECK_DAPT[k]] for k in range(1, 8)],
        cap="Its first version averaged the veto rate over attack types and passed Friday; the released version checks each type.")
