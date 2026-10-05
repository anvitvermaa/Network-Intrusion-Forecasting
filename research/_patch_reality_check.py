

#!/usr/bin/env python3

"""Fix reality_check.py so per-attack-type weaknesses can no longer hide inside overall averages.

All edits must match exactly once, or nothing is written."""

import sys

 

P = "research/reality_check.py"

try:

    src = open(P).read()

except FileNotFoundError:

    sys.exit(f"[FAIL] {P} not found. Run this from ~/network-intrusion-forecasting. Nothing written.")

if "PATCHED_V2" in src:

    sys.exit("[FAIL] This patch is already applied. Nothing written.")

 

E = [

    # marker

    ('MIN_N = 30\n', 'MIN_N = 30\nPATCHED_V2 = True  # per-type checks: weaknesses cannot hide in averages\n'),

    # check 1: FAIL when overall detection is low

    ('        status = "WARN" if (rec >= 0.9 and weak) or share > 0.5 else "PASS"\n',

     '        status = "FAIL" if rec < 0.5 else ("WARN" if weak or share > 0.5 else "PASS")\n'),

    ('        summ = f"Overall {pc(rec)} caught at {pc(far, 3)} false alarms."\n',

     '        summ = f"Overall {pc(rec)} caught at {pc(far, 3)} false alarms."\n        if rec < 0.5:\n            summ += " Most attacks are missed."\n'),

    ('              "WARN if one type is over half of all attacks, or if overall recall is 90%+ while some type with 30+ examples is under 50%")\n',

     '              "FAIL if under 50% of attacks are caught; WARN if one type is over half of all attacks or any type with 30+ examples is under 50%")\n'),

    # check 2: note on idle periods when hours come from timestamps

    ('    hours = a.hours\n',

     '    hours = a.hours\n    hours_from_span = False\n'),

    ('            hours = max((ts.max() - ts.min()).total_seconds() / 3600.0, 1e-9)\n',

     '            hours = max((ts.max() - ts.min()).total_seconds() / 3600.0, 1e-9)\n            hours_from_span = True\n'),

    ('              [f"{fp:,} false alarms in total", "an analyst can typically review tens of alerts per hour, not thousands"],\n',

     '              [f"{fp:,} false alarms in total", "an analyst can typically review tens of alerts per hour, not thousands"]\n'

     '              + (["hours = first to last timestamp; if capture was not continuous (nights, gaps), the true busy-hour rate is higher"] if hours_from_span else []),\n'),

    # check 3: INFO when every attack type is unseen

    ('        status = "PASS" if (ru is not None and (rs is None or ru >= rs - 0.2)) else "WARN"\n',

     '        if rs is None:\n            status = "INFO"\n        else:\n            status = "PASS" if (ru is not None and ru >= rs - 0.2) else "WARN"\n'),

    ('              [f"unseen types in this data: {\', \'.join(sorted(set(lab[mu]))) or \'none\'}"],\n',

     '              [f"unseen types in this data: {\', \'.join(sorted(set(lab[mu]))) or \'none\'}"]\n'

     '              + (["every attack type here is unseen, so this is a genuine zero-day test; there is nothing seen to compare against"] if rs is None else []),\n'),

    # check 4: per-type veto

    ('        status = "WARN" if rate > 0.2 else "PASS"\n        R.add(4, "Classifier veto of detector alarms", status,\n              f"Of {int(caught.sum()):,} attacks the detector caught, the final output called {pc(rate)} normal.",\n',

     '        bad = [r for r in rows if r[2] > 0.2]\n        status = "WARN" if rate > 0.2 or bad else "PASS"\n        R.add(4, "Classifier veto of detector alarms", status,\n              f"Of {int(caught.sum()):,} attacks the detector caught, the final output called {pc(rate)} normal."\n              + (f" Worst: {bad[0][0]}, {pc(bad[0][2])} of its detector catches overruled." if bad else ""),\n'),

    ('              "WARN if more than 20% of the detector\'s correct alarms are overruled")\n',

     '              "WARN if more than 20% of the detector\'s correct alarms are overruled, overall or for any type with 30+ catches")\n'),

    # check 5: per-type AUROC

    ('            det = []\n            for t in sorted(set(lab[y]), key=lambda t: -(lab == t).sum()):\n',

     '            det, weak_auc = [], []\n            for t in sorted(set(lab[y]), key=lambda t: -(lab == t).sum()):\n'),

    ('                    det.append(f"{t}: AUROC {roc_auc_score(m[sel], s[sel]):.3f} (n={int(m.sum()):,})")\n            status = "PASS" if auc >= 0.9 else ("WARN" if auc >= 0.7 else "FAIL")\n',

     '                    v = roc_auc_score(m[sel], s[sel])\n                    det.append(f"{t}: AUROC {v:.3f} (n={int(m.sum()):,})")\n                    if v < 0.7:\n                        weak_auc.append(f"{t} {v:.2f}")\n            status = "FAIL" if auc < 0.7 else ("WARN" if auc < 0.9 or weak_auc else "PASS")\n'),

    ('                  f"AUROC {auc:.3f} (0.5 = chance, 1.0 = perfect ranking).", det,\n',

     '                  f"AUROC {auc:.3f} (0.5 = chance, 1.0 = perfect ranking)." + (f" Weak types: {\', \'.join(weak_auc)}." if weak_auc else ""), det,\n'),

    ('                  "PASS at 0.9+, WARN at 0.7-0.9, FAIL below 0.7; below 0.5 means attacks look more normal than normal traffic")\n',

     '                  "PASS at 0.9+ with every type (30+ examples) at 0.7+; WARN at 0.7-0.9 or if any type is below 0.7; FAIL below 0.7 overall")\n'),

    # check 6: split duplicates into attack and normal rows

    ('        share = float(np.mean([h in ht for h in hv]))\n        status = "PASS" if share <= 0.01 else "WARN"\n',

     '        dup = np.array([h in ht for h in hv])\n        share = float(dup.mean())\n'

     '        te_att = ~np.isin(te["label"].astype(str).str.strip().values, list(benign)) if "label" in te.columns else np.zeros(len(te), bool)\n'

     '        share_att = float(dup[te_att].mean()) if te_att.any() else 0.0\n'

     '        share_ben = float(dup[~te_att].mean()) if (~te_att).any() else 0.0\n'

     '        status = "PASS" if share <= 0.01 and share_att <= 0.01 else "WARN"\n'),

    ('              ["identical rows let a model memorise answers instead of learning patterns"],\n              "WARN above 1%")\n',

     '              [f"attack rows that also appear in training: {pc(share_att, 2)} of {int(te_att.sum()):,}",\n'

     '               f"normal rows that also appear in training: {pc(share_ben, 2)} of {int((~te_att).sum()):,} (short, common normal flows repeat naturally)",\n'

     '               "identical attack rows let a model memorise answers instead of learning patterns"],\n'

     '              "WARN above 1% overall, or above 1% of attack rows")\n'),

]

 

for old, new in E:

    c = src.count(old)

    if c != 1:

        print(f"[FAIL] expected 1 match, found {c} for:\n{old[:300]}\nNothing written.")

        sys.exit(1)

    src = src.replace(old, new)

open(P, "w").write(src)

print(f"[OK] {P}: {len(E)} edits")
