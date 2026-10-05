

#!/usr/bin/env python3

"""Add exact Clopper-Pearson intervals to the audit (bootstrap CIs collapse at 0/n and n/n)."""

import sys

 

 

def apply(path, patches):

    src = open(path).read()

    for old, new in patches:

        c = src.count(old)

        if c != 1:

            print(f"[FAIL] {path}: expected 1 match, found {c} for:\n{old}\nNothing written.")

            sys.exit(1)

        src = src.replace(old, new)

    open(path, "w").write(src)

    print(f"[OK] {path}: {len(patches)} patches")

 

 

apply("research/forecastability.py", [

    (

        "def _h(p):",

        "def exact_ci(k, n, alpha=0.05):\n    \"\"\"Clopper-Pearson exact binomial interval; valid at 0/n and n/n, unlike the bootstrap.\"\"\"\n    from scipy.stats import beta\n    if n == 0:\n        return [None, None]\n    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))\n    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))\n    return [lo, hi]\n\n\ndef _h(p):",

    ),

])

 

apply("research/forecast_audit.py", [

    (

        "                     \"acc_changes_ci95\": F._bootstrap_ci(c_eps, N_BOOT)}",

        "                     \"acc_changes_ci95\": F._bootstrap_ci(c_eps, N_BOOT),\n                     \"acc_all_exact95\": F.exact_ci(int(a.sum()), int(len(a))),\n                     \"acc_changes_exact95\": F.exact_ci(int(c.sum()), int(len(c)))}",

    ),

    (

        "        lo, hi = r[\"acc_changes_ci95\"]",

        "        lo, hi = r[\"acc_changes_exact95\"]",

    ),

    (

        "    print(f\"    {'method':<22} {'acc all steps':>16} {'n':>7}   {'acc at stage changes':>22} {'n':>5}\")",

        "    print(f\"    {'method':<22} {'acc all steps':>16} {'n':>7}   {'acc at stage changes [exact 95% CI]':>36} {'n':>5}\")",

    ),

    (

        "        print(f\"    {name:<22} {aa:>16} {r['n_all']:>7}   {ac + ci:>22} {r['n_changes']:>5}\")",

        "        print(f\"    {name:<22} {aa:>16} {r['n_all']:>7}   {ac + ci:>36} {r['n_changes']:>5}\")",

    ),

])
