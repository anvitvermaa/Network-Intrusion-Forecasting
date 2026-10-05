# Reality check: DAPT2020 deployed as-is

| # | Check | Status | Summary |
|---|---|---|---|
| 1 | Headline vs per-attack-type results | **FAIL** | Overall 23.6% caught at 20.719% false alarms. Most attacks are missed. Weak types hidden by the average: Account Bruteforce, Account Discovery, Directory Bruteforce, Network Scan, Web Vulnerability Scan. |
| 2 | False alarms as alerts per hour | **FAIL** | 129.3 false alerts per hour over 82.6 hours; 33.6% of all alerts are real attacks. |
| 3 | Seen vs unseen attack types | **INFO** | Unseen types: 23.6% caught (22,979 flows). Seen types: n/a (0 flows). |
| 4 | Classifier veto of detector alarms | **WARN** | Of 22,975 attacks the detector caught, the final output called 76.4% normal. Worst: Web Vulnerability Scan, 98.2% of its detector catches overruled. |
| 5 | Ranking quality without a threshold (AUROC) | **FAIL** | AUROC 0.676 (0.5 = chance, 1.0 = perfect ranking). Weak types: Network Scan 0.65, Web Vulnerability Scan 0.62, Account Discovery 0.58, Account Bruteforce 0.64, SQL Injection 0.64. |
| 6 | Identical rows in training and test data | **NOT CHECKED** | Pass --overlap-train and --overlap-test. |
| 7 | Can these stage sequences test forecasting? | **FAIL** | 11 real stage changes in 7 episodes; the one-line rule 'advance one stage' gets 11/11 (100%, 95% CI 72%-100%); best possible for any rule using the current stage: 100%. |

## 1. Headline vs per-attack-type results: FAIL

Overall 23.6% caught at 20.719% false alarms. Most attacks are missed. Weak types hidden by the average: Account Bruteforce, Account Discovery, Directory Bruteforce, Network Scan, Web Vulnerability Scan.

- overall: 23.6% of attacks caught, 20.719% of normal traffic flagged (10,687 false alarms)
- largest attack type: Directory Bruteforce = 43% of all attack flows
- Directory Bruteforce: 31.3% caught of 9,970 (95% CI 30%-32%)
- Network Scan: 23.7% caught of 7,742 (95% CI 23%-25%)
- Web Vulnerability Scan: 1.8% caught of 2,574 (95% CI 1%-2%)
- Account Discovery: 10.5% caught of 2,408 (95% CI 9%-12%)
- Account Bruteforce: 46.1% caught of 141 (95% CI 38%-55%)
- SQL Injection: 54.8% caught of 84 (95% CI 44%-66%)
- Backdoor: 75.0% caught of 20 (95% CI 51%-91%)
- Privilege Escalation: 100.0% caught of 13 (95% CI 75%-100%)
- Command Injection: 33.3% caught of 12 (95% CI 10%-65%)
- CSRF: 42.9% caught of 7 (95% CI 10%-82%)
- Data Exfiltration: 83.3% caught of 6 (95% CI 36%-100%)
- Malware Download: 100.0% caught of 2 (95% CI 16%-100%)
- too few examples to judge (n < 30): Backdoor, CSRF, Command Injection, Data Exfiltration, Malware Download, Privilege Escalation

_Rule of thumb: FAIL if under 50% of attacks are caught; WARN if one type is over half of all attacks or any type with 30+ examples is under 50%_

## 2. False alarms as alerts per hour: FAIL

129.3 false alerts per hour over 82.6 hours; 33.6% of all alerts are real attacks.

- 10,687 false alarms in total
- an analyst can typically review tens of alerts per hour, not thousands
- hours = first to last timestamp; if capture was not continuous (nights, gaps), the true busy-hour rate is higher

_Rule of thumb: PASS up to 10 per hour, WARN up to 100, FAIL above; depends on team size_

## 3. Seen vs unseen attack types: INFO

Unseen types: 23.6% caught (22,979 flows). Seen types: n/a (0 flows).

- unseen types in this data: Account Bruteforce, Account Discovery, Backdoor, CSRF, Command Injection, Data Exfiltration, Directory Bruteforce, Malware Download, Network Scan, Privilege Escalation, SQL Injection, Web Vulnerability Scan
- every attack type here is unseen, so this is a genuine zero-day test; there is nothing seen to compare against

_Rule of thumb: WARN if unseen types are caught 20+ points less often than seen ones_

## 4. Classifier veto of detector alarms: WARN

Of 22,975 attacks the detector caught, the final output called 76.4% normal. Worst: Web Vulnerability Scan, 98.2% of its detector catches overruled.

- Web Vulnerability Scan: 98.2% of 2,573 detector catches overruled
- Account Discovery: 89.5% of 2,408 detector catches overruled
- Network Scan: 76.3% of 7,741 detector catches overruled
- Directory Bruteforce: 68.7% of 9,969 detector catches overruled
- Account Bruteforce: 53.6% of 140 detector catches overruled
- SQL Injection: 45.2% of 84 detector catches overruled

_Rule of thumb: WARN if more than 20% of the detector's correct alarms are overruled, overall or for any type with 30+ catches_

## 5. Ranking quality without a threshold (AUROC): FAIL

AUROC 0.676 (0.5 = chance, 1.0 = perfect ranking). Weak types: Network Scan 0.65, Web Vulnerability Scan 0.62, Account Discovery 0.58, Account Bruteforce 0.64, SQL Injection 0.64.

- Directory Bruteforce: AUROC 0.737 (n=9,970)
- Network Scan: AUROC 0.648 (n=7,742)
- Web Vulnerability Scan: AUROC 0.615 (n=2,574)
- Account Discovery: AUROC 0.580 (n=2,408)
- Account Bruteforce: AUROC 0.641 (n=141)
- SQL Injection: AUROC 0.641 (n=84)

_Rule of thumb: PASS at 0.9+ with every type (30+ examples) at 0.7+; WARN at 0.7-0.9 or if any type is below 0.7; FAIL below 0.7 overall_

## 6. Identical rows in training and test data: NOT CHECKED

Pass --overlap-train and --overlap-test.


## 7. Can these stage sequences test forecasting?: FAIL

11 real stage changes in 7 episodes; the one-line rule 'advance one stage' gets 11/11 (100%, 95% CI 72%-100%); best possible for any rule using the current stage: 100%.

- distinct transitions: 3
- uncertainty about the next stage: 0.000 bits (0 = fully predictable)

_Rule of thumb: FAIL if the trivial rule already reaches the ceiling, or there are fewer than 30 stage changes: no forecaster can then show an advantage_
