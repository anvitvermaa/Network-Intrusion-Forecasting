#!/usr/bin/env python3

"""Patch evaluate.py (zero-day-aware two-stage table) + silence ZAT prints in Pipeline."""

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

 

apply("evaluation/evaluate.py", [

    (

        """print(f"  {'Attack':<26} {'n':>7} {'AnomOnly':>9} {'+Classify':>10}")""",

        """print(f"  {'Attack':<26} {'n':>7} {'AnomOnly':>9} {'Detected':>9} {'Named':>8}")\n    print("  (Detected = flagged as any attack incl. UNKNOWN; Named = exact class. Zero-day classes cannot be Named.)")""",

    ),

    (

        """        clf_rate = float((y_pred[mask] == lbl).mean())""",

        """        clf_rate = float((y_pred[mask] == lbl).mean())\n        det_rate = float(pred_is_attack[mask].mean())""",

    ),

    (

        """two_stage[lbl] = {"n":n, "anomaly_only":anom_rate, "with_classifier":clf_rate}""",

        """two_stage[lbl] = {"n":n, "anomaly_only":anom_rate, "detected_full_pipeline":det_rate, "named_correctly":clf_rate}""",

    ),

    (

        """print(f"  {lbl:<26} {n:>7,} {anom_rate:>8.0%} {clf_rate:>9.0%}")""",

        """print(f"  {lbl:<26} {n:>7,} {anom_rate:>8.0%} {det_rate:>8.1%} {clf_rate:>7.0%}")""",

    ),

    (

        """print("3. PER-CLASS REPORT (with support -- rare classes shown honestly)")""",

        """print("3. PER-CLASS REPORT -- EXACT-LABEL accuracy (zero-day classes are 0 by construction;")\n    print("   see artifacts/temporal_eval.json for per-class DETECTION rates with 95% CIs)")""",

    ),

])

 

apply("streaming/pipeline_consumer.py", [

    (

        "import argparse, json, os, time",

        "import argparse, contextlib, io, json, os, time",

    ),

    (

        "        Xa = self.to_matrix.transform(df[self.anom_features])",

        "        with contextlib.redirect_stdout(io.StringIO()):\n            Xa = self.to_matrix.transform(df[self.anom_features])",

    ),

])


