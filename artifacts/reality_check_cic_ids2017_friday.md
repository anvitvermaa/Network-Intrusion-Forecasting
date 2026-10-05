# Reality check: CIC-IDS2017 Friday

| # | Check | Status | Summary |
|---|---|---|---|
| 1 | Headline vs per-attack-type results | **WARN** | Overall 97.4% caught at 0.130% false alarms. Weak types hidden by the average: Botnet, Portscan. |
| 2 | False alarms as alerts per hour | **WARN** | 44.2 false alerts per hour over 8.0 hours; 99.6% of all alerts are real attacks. |
| 3 | Seen vs unseen attack types | **INFO** | Unseen types: 97.4% caught (97,563 flows). Seen types: n/a (0 flows). |
| 4 | Classifier veto of detector alarms | **WARN** | Of 96,823 attacks the detector caught, the final output called 1.8% normal. Worst: Botnet, 100.0% of its detector catches overruled. |
| 5 | Ranking quality without a threshold (AUROC) | **WARN** | AUROC 0.908 (0.5 = chance, 1.0 = perfect ranking). Weak types: Botnet 0.55. |
| 6 | Identical rows in training and test data | **PASS** | 0.32% of test rows also appear exactly in the training data (82 feature columns compared). |
| 7 | Can these stage sequences test forecasting? | **FAIL** | 5 real stage changes in 1 episodes; the one-line rule 'advance one stage' gets 1/5 (20%, 95% CI 1%-72%); best possible for any rule using the current stage: 80%. |

## 1. Headline vs per-attack-type results: WARN

Overall 97.4% caught at 0.130% false alarms. Weak types hidden by the average: Botnet, Portscan.

- overall: 97.4% of attacks caught, 0.130% of normal traffic flagged (354 false alarms)
- largest attack type: DDoS = 98% of all attack flows
- DDoS: 99.4% caught of 95,144 (95% CI 99%-99%)
- Portscan: 28.2% caught of 1,683 (95% CI 26%-30%)
- Botnet: 0.0% caught of 736 (95% CI 0%-0%)

_Rule of thumb: FAIL if under 50% of attacks are caught; WARN if one type is over half of all attacks or any type with 30+ examples is under 50%_

## 2. False alarms as alerts per hour: WARN

44.2 false alerts per hour over 8.0 hours; 99.6% of all alerts are real attacks.

- 354 false alarms in total
- an analyst can typically review tens of alerts per hour, not thousands

_Rule of thumb: PASS up to 10 per hour, WARN up to 100, FAIL above; depends on team size_

## 3. Seen vs unseen attack types: INFO

Unseen types: 97.4% caught (97,563 flows). Seen types: n/a (0 flows).

- unseen types in this data: Botnet, DDoS, Portscan
- every attack type here is unseen, so this is a genuine zero-day test; there is nothing seen to compare against

_Rule of thumb: WARN if unseen types are caught 20+ points less often than seen ones_

## 4. Classifier veto of detector alarms: WARN

Of 96,823 attacks the detector caught, the final output called 1.8% normal. Worst: Botnet, 100.0% of its detector catches overruled.

- Botnet: 100.0% of 66 detector catches overruled
- Portscan: 70.9% of 1,634 detector catches overruled
- DDoS: 0.6% of 95,123 detector catches overruled

_Rule of thumb: WARN if more than 20% of the detector's correct alarms are overruled, overall or for any type with 30+ catches_

## 5. Ranking quality without a threshold (AUROC): WARN

AUROC 0.908 (0.5 = chance, 1.0 = perfect ranking). Weak types: Botnet 0.55.

- DDoS: AUROC 0.913 (n=95,144)
- Portscan: AUROC 0.804 (n=1,683)
- Botnet: AUROC 0.553 (n=736)

_Rule of thumb: PASS at 0.9+ with every type (30+ examples) at 0.7+; WARN at 0.7-0.9 or if any type is below 0.7; FAIL below 0.7 overall_

## 6. Identical rows in training and test data: PASS

0.32% of test rows also appear exactly in the training data (82 feature columns compared).

- attack rows that also appear in training: 0.00% of 97,563
- normal rows that also appear in training: 0.43% of 272,696 (short, common normal flows repeat naturally)
- identical attack rows let a model memorise answers instead of learning patterns

_Rule of thumb: WARN above 1% overall, or above 1% of attack rows_

## 7. Can these stage sequences test forecasting?: FAIL

5 real stage changes in 1 episodes; the one-line rule 'advance one stage' gets 1/5 (20%, 95% CI 1%-72%); best possible for any rule using the current stage: 80%.

- distinct transitions: 5
- uncertainty about the next stage: 0.400 bits (0 = fully predictable)

_Rule of thumb: FAIL if the trivial rule already reaches the ceiling, or there are fewer than 30 stage changes: no forecaster can then show an advantage_
