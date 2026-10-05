"""The paper's numbers of record. Every page reads from here, so the site cannot drift from the paper.
Edit AUTHORS once your names and guide are final."""

TITLE = "Counting Flows, Not Transitions"
DEK = "A forecastability audit of kill-chain stage prediction"
AUTHORS = "Author names, Department, Institution"

# DAPT2020, leave-one-attacker-out: (forecaster, every flow, at the 11 stage changes, 95% CI)
DAPT = [
    ("Persistence (next = current)", "&gt;99%", "0 of 11", "0&ndash;28%"),
    ("Markov, fitted on every flow", "&gt;99%", "0 of 11", "0&ndash;28%"),
    ("HMM recipe, refitted on every flow", "&gt;99%", "0 of 11", "0&ndash;28%"),
    ("Markov, fitted on stage changes", "&lt;1%", "11 of 11", "72&ndash;100%"),
    ("Majority next stage", "36.7%", "1 of 11", "0&ndash;41%"),
    ("Advance one stage", "&lt;1%", "11 of 11", "72&ndash;100%"),
    ("Deployed HMM (hand-written prior)", "&lt;1%", "11 of 11", "72&ndash;100%"),
]

FORECASTABILITY = [
    ("Synthetic episodes (our first evaluation)", "511", "6", "0.974", "74.7%"),
    ("CIC-IDS2017 weekly schedule", "5", "5", "0.400", "80.0%"),
    ("DAPT2020, stage changes only", "11", "3", "0.000", "100%"),
    ("Ghafir et al. published dataset", "2,286", "13", "0.679", "76.0%"),
    ("Unraveled APT, 1-hour dominant stage", "29", "8", "0.822", "75.9%"),
]

GHAFIR = [
    ("2", "43.6%", "45.6%", "66.5%", "79.0%"),
    ("3", "&ndash;", "75.2%", "92.7%", "99.0%"),
    ("4", "93.3%", "95.5%", "100%", "95.5%"),
]
GHAFIR_RECORD = {"markov1": "76.0%", "advance_one": "72.3%", "changes": "2,286", "distinct": "13", "entropy": "0.679",
                 "top1": {"2": "45.6%", "3": "75.2%", "4": "95.5%"}, "top2": {"2": "79.0%", "3": "99.0%", "4": "95.5%"}}

UNRAVELED = [
    ("1 hour", "467", "51%", "29", "8", "0.822", "advance one, 6 of 12"),
    ("6 hours", "94", "50%", "15", "7", "0.796", "Markov, 6 of 7"),
    ("1 day", "32", "50%", "8", "5", "0.750", "three-way tie, 2 of 6"),
]
UNRAVELED_RECORD = {"1h": ("51%", "29", "8"), "6h": ("50%", "15", "7"), "1D": ("50%", "8", "5"),
                    "attack_flows": "97,243", "dedup": "80,402"}

SURVEY = [
    ("Shen et al. (CCS 2018)", "next security event", "commercial IPS telemetry", "real", "yes"),
    ("B&#259;b&#259;lau &amp; Nadeem (preprint, 2024)", "next attacker action", "competition and SOC alerts", "real", "yes"),
    ("Ghafir et al. (IEEE Access 2019)", "next APT stage", "generated, forward-only", "synthetic", "no"),
    ("Chadza et al. (PST 2019)", "next HMM state", "CSE-CIC-IDS2018 alerts", "lab", "no"),
    ("Chadza et al. (FGCS 2020)", "next HMM state", "DARPA 2000, one scenario", "lab", "no"),
    ("Dass et al. (COMPSAC 2021)", "next attack in a path", "hand-set simulation", "synthetic", "no"),
    ("Dehghan et al., ProAPT (preprint, 2022)", "next stage of every flow", "DAPT2020", "lab", "no"),
    ("Dalal et al. (J. Cloud Comput. 2023)", "class of each record", "MSCAD, random 70/30 split", "lab", "no"),
    ("Friji et al. (preprint, 2024)", "attack stage", "ToN_IoT", "lab", "no"),
    ("Zhu et al. (preprint, 2024)", "next attack events", "DARPA TC, CTI reports", "lab", "no"),
    ("Wang &amp; Stadler (preprint, 2025)", "attack stage, online", "AIT, MSCAD, CIC-IDS2017", "lab", "no"),
]

FRIDAY = [
    ("Earlier version, leaky random split", "99.2%", "0.0015%", "4"),
    ("Detector only", "99.2%", "31.0%", "84,510"),
    ("Detector + classifier", "92.7%", "0.0007%", "2"),
    ("Detector + classifier + abstain", "97.4%", "0.130%", "354"),
]
PER_TYPE = [
    ("DDoS (95,144 flows)", "100%", "95.0%", "99.4%", "0.913"),
    ("Port scan (1,683)", "97.1%", "3.4%", "28.2%", "0.804"),
    ("Botnet (736)", "9.0%", "0%", "0%", "0.553"),
]

TRANSFER = [
    ("E1 deployed as-is", "94.1%", "100%", "20.7%", "23.6%", "0.676 (0.568&ndash;0.718)"),
    ("E2 retrained on shared features", "63.9%", "98.0%", "26.2%", "89.2%", "0.642 &plusmn; 0.015"),
    ("E3 detector refitted on local normal", "33.8%", "32.8%", "7.8%", "31.9%", "0.600 &plusmn; 0.010"),
]

REALITY_CHECK_FRIDAY = {1: "WARN", 2: "WARN", 3: "INFO", 4: "WARN", 5: "WARN", 6: "PASS", 7: "FAIL"}
REALITY_CHECK_DAPT = {1: "FAIL", 2: "FAIL", 3: "INFO", 4: "WARN", 5: "FAIL", 6: "not checked", 7: "FAIL"}
CHECK_NAMES = {1: "Headline vs per attack type", 2: "False alerts per hour", 3: "Seen vs unseen attack types",
               4: "Classifier veto of detector alarms", 5: "Ranking quality (AUROC) per type",
               6: "Identical rows in training and test", 7: "Can the stage data test forecasting?"}
CIC_TRAIN_ATTACKS = "DoS Hulk,DoS GoldenEye,DoS Slowloris,DoS Slowhttptest,FTP-Patator,SSH-Patator,Heartbleed"
KILL_CHAIN = "RECON,INITIAL_COMPROMISE,LATERAL_MOVEMENT,EXFILTRATION"
