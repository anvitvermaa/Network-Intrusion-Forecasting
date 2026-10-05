
#!/usr/bin/env python3

"""Update correctness_gate.py: offline reference implements the tau/UNKNOWN spec independently,

random sample (includes attacks), JSON round-trip identical to producer.py, confidence on mismatches."""

import sys

 

P = "streaming/correctness_gate.py"

src = open(P).read()

patches = [

    (

        "        ids = pipe.xgb.predict(Xc)",

        "        P = pipe.xgb.predict_proba(Xc)\n        ids = P.argmax(axis=1)\n        conf = P.max(axis=1)",

    ),

    (

        "            name = pipe.classes[ids[k]]",

        "            name = pipe.classes[ids[k]]\n            if pipe.tau > 0 and conf[k] < pipe.tau:\n                name = \"UNKNOWN_ATTACK\"",

    ),

    (

        "            si = pipe.sidx.get(stg, 0)",

        "            if stg == \"UNKNOWN\":\n                continue\n            si = pipe.sidx.get(stg, 0)",

    ),

    (

        ".head(n_test).reset_index(drop=True)",

        ".sample(n=n_test, random_state=42).reset_index(drop=True)",

    ),

    (

        "    records = df.to_dict(orient=\"records\")",

        "    records = [json.loads(json.dumps(r, default=str)) for r in df.to_dict(orient=\"records\")]  # identical serialization to producer.py",

    ),

    (

        "            print(f\"      row {i}: offline={off_class[i]} vs streaming={str_class[i]}\")",

        "            print(f\"      row {i}: offline={off_class[i]} vs streaming={str_class[i]} (stream conf={stream_results[i]['clf_confidence']})\")",

    ),

    (

        "-- consistent with Phase-1 Stage-A behavior\")",

        "-- consistent with Phase-1 Stage-A behavior\")\n    n_unk = int((str_class == \"UNKNOWN_ATTACK\").sum())\n    print(f\"[sanity] {n_unk:,} flows abstained as UNKNOWN_ATTACK (tau={pipe.tau})\")",

    ),

]

for old, new in patches:

    c = src.count(old)

    if c != 1:

        print(f"[FAIL] expected 1 match, found {c} for:\n{old}\nNothing written.")

        sys.exit(1)

    src = src.replace(old, new)

open(P, "w").write(src)

print(f"[OK] applied {len(patches)} patches to {P}")
