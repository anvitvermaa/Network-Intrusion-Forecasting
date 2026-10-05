import json
import os
import time
from collections import Counter
import streamlit as st
import streamlit.components.v1 as components
import _diagram
import _runner as R
import _theme as T

T.setup("How the system works", wide=True)
T.masthead("How the system works", "From raw network flows to a forecast of the attacker's next stage, in real time.")

components.html(_diagram.HTML, height=600, scrolling=False)
T.caption("An animation of the architecture, not a recording: each dot takes the route that the measured CIC-IDS2017 Friday "
          "proportions give it. The real system runs below.")

T.section("Watch a real run", "Start the real pipeline in two terminals; this panel reads its verdicts as they are written.")
T.table(["Terminal", "Command", "What it does"], [
    ["1", "<code>cd streaming &amp;&amp; docker compose up -d &amp;&amp; cd .. &amp;&amp; rm -f streaming/forecasts.jsonl</code>",
     "Starts Kafka and clears the previous run"],
    ["1", "<code>python streaming/pipeline_consumer.py --count 20000</code>", "Starts the scoring service: detect, classify, forecast"],
    ["2", "<code>python streaming/producer.py --limit 20000 --rate 500</code>", "Streams 20,000 Friday flows into Kafka, 500 per second"],
])

LIVE = R.path("streaming", "forecasts.jsonl")
BENIGN = {"Benign", "BENIGN", "benign", "Normal"}


def read_verdicts():
    rows = []
    with open(LIVE) as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass  # a line still being written
    return rows


def live_panel():
    if not os.path.exists(LIVE):
        T.note("No verdicts yet. Start the two terminals above; counts appear here within a second of the first batch.")
        return
    age = time.time() - os.path.getmtime(LIVE)
    rows = read_verdicts()
    n = len(rows)
    if n == 0:
        T.note("The verdicts file exists but is empty. The scoring service is waiting for flows; start the producer.")
        return
    status = "Receiving verdicts now" if age < 3 else f"Idle: last verdict written {int(age)} seconds ago"
    flagged = sum(1 for r in rows if r.get("is_anomaly"))
    alarms = [r for r in rows if str(r.get("pred_class")) not in BENIGN]
    unknown = sum(1 for r in alarms if r.get("pred_class") == "UNKNOWN_ATTACK")
    forecasts = sum(1 for r in rows if r.get("forecast_next"))
    T.table(["Status", "Flows scored", "Flagged by detector", "Final alarms", "Escalated as unknown", "Stage forecasts"],
            [[status, f"{n:,}", f"{flagged:,}", f"{len(alarms):,}", f"{unknown:,}", f"{forecasts:,}"]], num_cols=(1, 2, 3, 4, 5))
    by = {}
    for r in rows:
        lab = str(r.get("true_label"))
        e = by.setdefault(lab, {"n": 0, "flag": 0, "alarm": 0, "as": Counter()})
        e["n"] += 1
        e["flag"] += int(bool(r.get("is_anomaly")))
        if str(r.get("pred_class")) not in BENIGN:
            e["alarm"] += 1
            e["as"][str(r.get("pred_class"))] += 1
    out = []
    for lab, e in sorted(by.items(), key=lambda kv: -kv[1]["n"]):
        normal = lab in BENIGN
        top = e["as"].most_common(1)[0][0] if e["as"] else "&ndash;"
        out.append([lab + (" (normal)" if normal else ""), f"{e['n']:,}", f"{100 * e['flag'] / e['n']:.1f}%",
                    f"{100 * e['alarm'] / e['n']:.1f}%", top])
    T.table(["True label", "Flows", "Flagged by detector", "Final alarm", "Most often reported as"], out, num_cols=(1, 2, 3),
            cap="For normal traffic, &ldquo;final alarm&rdquo; is the false-alarm rate; for attacks, it is the share caught. "
                "These are the flows streamed so far, not the full day, so they will differ from the Findings page.")
    recent = []
    for r in rows[-8:][::-1]:
        fc = r.get("forecast_next") or "&ndash;"
        if r.get("forecast_next"):
            fc += f" ({float(r.get('forecast_prob', 0)):.2f})"
        recent.append([str(r.get("true_label")), "flagged" if r.get("is_anomaly") else "cleared",
                       str(r.get("pred_class")), str(r.get("current_stage")), fc])
    T.table(["True label", "Detector", "Final verdict", "Stage now", "Next stage forecast"], recent,
            cap="The eight most recent verdicts, newest first.")


if hasattr(st, "fragment"):
    follow = st.toggle("Follow the run live (updates every second)", value=False)
    if follow:
        st.fragment(run_every=1.0)(live_panel)()
    else:
        live_panel()
else:
    T.note("Live updating needs Streamlit 1.37 or newer (<code>pip install -U streamlit</code>). Until then, press Refresh during the run.")
    st.button("Refresh")
    live_panel()
