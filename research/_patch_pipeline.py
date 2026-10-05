

#!/usr/bin/env python3

"""One-shot patch: make Pipeline use temporal Stage B + UNKNOWN abstention by default."""

import sys

 

P = "streaming/pipeline_consumer.py"

src = open(P).read()

 

patches = [

    (

        'BOOTSTRAP = "localhost:9092"',

        'BOOTSTRAP = "localhost:9092"\nDEFAULT_TAU = 0.999  # chosen on VAL (Thursday) in research/temporal_pipeline.py\nUNKNOWN_LABEL = "UNKNOWN_ATTACK"',

    ),

    (

        '"Portscan": "RECON",',

        '"Portscan": "RECON",\n    "UNKNOWN_ATTACK": "UNKNOWN",',

    ),

    (

        '    def __init__(self):',

        '    def __init__(self, model=None):\n        self.model = model or os.environ.get("NIF_MODEL", "temporal")\n        self.tau = 0.0',

    ),

    (

        '        self.classes = cspec["classes"]',

        '        self.classes = cspec["classes"]\n        if self.model == "temporal":\n            self.xgb = XGBClassifier()\n            self.xgb.load_model(os.path.join(MODELS, "xgb_temporal.json"))\n            tspec = json.load(open(os.path.join(MODELS, "xgb_temporal_spec.json")))\n            self.clf_features = tspec["features"]\n            self.classes = tspec["classes"]\n            self.tau = float(os.environ.get("NIF_TAU", DEFAULT_TAU))\n        print(f"[pipeline] Stage B model={self.model} classes={len(self.classes)} tau={self.tau}")',

    ),

    (

        '        fc_prob = np.zeros(n)',

        '        fc_prob = np.zeros(n)\n        clf_conf = np.zeros(n)',

    ),

    (

        '            ids = self.xgb.predict(Xc)\n            names = [self.classes[i] for i in ids]',

        '            P = self.xgb.predict_proba(Xc)\n            ids = P.argmax(axis=1)\n            confs = P.max(axis=1)\n            names = [self.classes[i] for i in ids]\n            if self.tau > 0:\n                names = [UNKNOWN_LABEL if confs[k] < self.tau else names[k] for k in range(len(names))]\n            for k, row_i in enumerate(idx):\n                clf_conf[row_i] = float(confs[k])',

    ),

    (

        '                cur_stage[row_i] = stg',

        '                cur_stage[row_i] = stg\n                if stg == "UNKNOWN":\n                    continue',

    ),

    (

        '                "forecast_prob": round(fc_prob[i], 3),',

        '                "forecast_prob": round(fc_prob[i], 3),\n                "clf_confidence": round(float(clf_conf[i]), 4),',

    ),

]

 

for old, new in patches:

    c = src.count(old)

    if c != 1:

        print(f"[FAIL] expected exactly 1 match, found {c} for:\n{old}\nNothing written.")

        sys.exit(1)

    src = src.replace(old, new)

 

open(P, "w").write(src)

print(f"[OK] applied {len(patches)} patches to {P}")
