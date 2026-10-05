"""Animated architecture diagram, rendered with streamlit.components.v1.html. Dots move in the real Friday proportions."""

HTML = r"""
<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Newsreader:opsz,wght@6..72,400;6..72,500;6..72,600&display=swap" rel="stylesheet">
<style>
  :root { --paper:#F5F0E6; --sheet:#FBF8F1; --ink:#1F1D1A; --muted:#6A6357; --rule:#D9D0BE; --blue:#23466B; --red:#9B2C2C; --norm:#A39A8A; }
  html, body { margin:0; background:var(--paper); color:var(--ink); font-family:'Newsreader', Georgia, serif; }
  .wrap { padding: 4px 2px 0 2px; }
  svg { width:100%; height:auto; display:block; }
  .node rect { fill:var(--sheet); stroke:var(--ink); stroke-width:1.2; cursor:pointer; }
  .node:hover rect, .node.on rect { stroke:var(--blue); stroke-width:2.4; }
  .node:focus { outline:none; } .node:focus-visible rect { stroke:var(--blue); stroke-width:3; }
  .t { font-size:20px; font-weight:600; fill:var(--ink); pointer-events:none; }
  .s { font-size:15px; fill:var(--muted); pointer-events:none; }
  .c { font-size:15px; fill:var(--blue); font-weight:600; pointer-events:none; font-variant-numeric:tabular-nums; }
  .lab { font-size:15px; fill:var(--ink); text-anchor:middle; }
  .cnt { font-size:18px; fill:var(--blue); font-weight:600; text-anchor:middle; font-variant-numeric:tabular-nums; }
  .box { fill:none; stroke:var(--ink); stroke-dasharray:5 4; stroke-width:1; }
  .boxlab { font-size:15px; fill:var(--muted); font-style:italic; }
  .edge { stroke:var(--ink); stroke-width:1.2; fill:none; }
  .drop { stroke:var(--rule); stroke-width:1.4; stroke-dasharray:3 3; fill:none; }
  .log { fill:var(--sheet); stroke:var(--ink); stroke-width:1.2; }
  .seg { stroke:var(--rule); stroke-width:1; }
  .bar { display:flex; gap:14px; align-items:baseline; margin:6px 4px 8px 4px; font-size:15px; color:var(--muted); flex-wrap:wrap; }
  button { font-family:inherit; font-size:15px; background:var(--blue); color:#FBF8F1; border:0; border-radius:3px; padding:6px 14px; cursor:pointer; }
  button:focus-visible { outline:2px solid var(--ink); outline-offset:2px; }
  .panel { border-left:3px solid var(--blue); background:var(--sheet); padding:12px 16px; margin:6px 4px 4px 4px; min-height:64px; font-size:16.5px; line-height:1.55; max-width:62em; }
  .panel b { font-weight:600; }
</style></head><body><div class="wrap">
<div class="bar"><button id="pp" aria-pressed="false">Pause</button><button id="rs">Reset counts</button>
  <span id="info">One dot is one flow. Grey: normal traffic. Red: attack. Proportions are the measured CIC-IDS2017 Friday results.</span></div>
<svg viewBox="0 92 1200 418" role="img" aria-label="Flows travel from the traffic source through the producer and Kafka into the scoring service, then as verdicts to the dashboard">
  <defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#1F1D1A"/></marker></defs>
  <rect class="box" x="578" y="100" width="604" height="234" rx="4"/>
  <text class="boxlab" x="594" y="124">Scoring service, streaming/stream_pipeline.py</text>
  <path class="edge" d="M170 210 H203" marker-end="url(#ar)"/>
  <path class="edge" d="M345 210 H378" marker-end="url(#ar)"/>
  <path class="edge" d="M540 210 H598" marker-end="url(#ar)"/>
  <path class="edge" d="M760 210 H798" marker-end="url(#ar)"/>
  <path class="edge" d="M960 210 H998" marker-end="url(#ar)"/>
  <path class="drop" d="M680 262 V445"/><path class="drop" d="M820 262 V445"/><path class="drop" d="M940 262 V445"/><path class="drop" d="M1080 262 V445"/>
  <path class="edge" d="M578 460 H544" marker-end="url(#ar)"/>
  <g id="dots"></g>
  <rect class="log" x="578" y="445" width="604" height="30"/>
  <g id="segs"></g>
  <text class="s" x="578" y="497">Kafka topic: verdicts</text><text class="c" id="c_out" x="1182" y="497" text-anchor="end">0 published</text>
  <text class="lab" x="680" y="356">Cleared by</text><text class="lab" x="680" y="374">detector</text><text class="cnt" id="n_a" x="680" y="398">0</text><text class="s" id="m_a" x="680" y="420" text-anchor="middle"></text>
  <text class="lab" x="820" y="356">Overruled</text><text class="lab" x="820" y="374">to normal</text><text class="cnt" id="n_v" x="820" y="398">0</text><text class="s" id="m_v" x="820" y="420" text-anchor="middle"></text>
  <text class="lab" x="940" y="356">Escalated</text><text class="lab" x="940" y="374">as unknown</text><text class="cnt" id="n_u" x="940" y="398">0</text><text class="s" id="m_u" x="940" y="420" text-anchor="middle"></text>
  <text class="lab" x="1080" y="356">Named, with</text><text class="lab" x="1080" y="374">stage forecast</text><text class="cnt" id="n_n" x="1080" y="398">0</text><text class="s" id="m_n" x="1080" y="420" text-anchor="middle"></text>
  <g class="node" data-k="src" tabindex="0"><rect x="20" y="158" width="150" height="104" rx="3"/><text class="t" x="34" y="192">Traffic</text><text class="s" x="34" y="216">CIC-IDS2017</text><text class="c" id="c_src" x="34" y="242">0 sent</text></g>
  <g class="node" data-k="prod" tabindex="0"><rect x="205" y="158" width="140" height="104" rx="3"/><text class="t" x="219" y="192">Producer</text><text class="s" x="219" y="216">producer.py</text><text class="c" x="219" y="242">publishes flows</text></g>
  <g class="node" data-k="kin" tabindex="0"><rect x="380" y="158" width="160" height="104" rx="3"/><text class="t" x="394" y="192">Kafka: flows</text><text class="s" x="394" y="216">ordered log</text><text class="c" id="c_off" x="394" y="242">offset 0</text></g>
  <g class="node" data-k="a" tabindex="0"><rect x="600" y="158" width="160" height="104" rx="3"/><text class="t" x="614" y="192">A. Detect</text><text class="s" x="614" y="216">Isolation Forest</text><text class="c" id="c_a" x="614" y="242">0 flagged</text></g>
  <g class="node" data-k="b" tabindex="0"><rect x="800" y="158" width="160" height="104" rx="3"/><text class="t" x="814" y="192">B. Classify</text><text class="s" x="814" y="216">XGBoost, abstain</text><text class="c" id="c_b" x="814" y="242">0 named</text></g>
  <g class="node" data-k="c" tabindex="0"><rect x="1000" y="158" width="160" height="104" rx="3"/><text class="t" x="1014" y="192">C. Forecast</text><text class="s" x="1014" y="216">HMM, next stage</text><text class="c" id="c_c" x="1014" y="242">0 forecasts</text></g>
  <g class="node" data-k="dash" tabindex="0"><rect x="364" y="425" width="180" height="70" rx="3"/><text class="t" x="378" y="455">Dashboard</text><text class="s" x="378" y="477">alerts and response</text></g>
  <g class="node" data-k="kout" tabindex="0"><rect x="578" y="445" width="604" height="30" fill-opacity="0" style="fill:transparent;stroke:transparent"/></g>
  <circle cx="34" cy="455" r="6" fill="#A39A8A"/><text class="s" x="48" y="460">normal flow</text>
  <circle cx="160" cy="455" r="6" fill="#9B2C2C"/><text class="s" x="174" y="460">attack flow</text>
  <text class="s" x="20" y="490">A red dot in a cleared bin</text><text class="s" x="20" y="508">is a missed attack.</text>
</svg>
<div class="panel" id="panel" aria-live="polite"><b>Click any box</b> to see what it does, which file runs it, and what it achieved on unseen Friday traffic.</div>
</div>
<script>
const INFO = {
 src: "<b>Friday traffic.</b> The test day of CIC-IDS2017 (corrected): 370,259 flows, 26% of them attacks: DDoS, port scan and botnet. None of these attack labels appears in training. Each flow is one row of 82 features.",
 prod: "<b>Producer</b> (streaming/producer.py) reads the flows and publishes them to Kafka at a set rate, as a network sensor would, for example 500 flows per second.",
 kin: "<b>Kafka topic &ldquo;flows&rdquo;.</b> An ordered, durable log. The producer and the scorer never wait for each other, and nothing is lost if the scorer is briefly slower. Kafka sustained 39,000 messages per second in our replay test.",
 a: "<b>A. Detect: Isolation Forest</b>, trained on normal traffic only. It flags flows that look unusual. On Friday it flags 99.2% of attack flows, but also 31.0% of normal flows, so it cannot raise alarms on its own.",
 b: "<b>B. Classify: XGBoost.</b> Names the attack type of every flagged flow. When its top probability is below 0.999, it answers UNKNOWN_ATTACK and escalates instead of guessing. It removes almost all false alarms (354 of 272,696 normal flows remain), but it also overrules 70.9% of the detector's correct port-scan alarms and every botnet alarm.",
 c: "<b>C. Forecast: hidden Markov model.</b> Maps the attack class to a kill-chain stage and predicts the next one, using a prior that encodes the textbook order. On every public benchmark we tested, this cannot be told apart from the one-line rule &ldquo;advance one stage&rdquo;: see Findings.",
 kout: "<b>Kafka topic &ldquo;verdicts&rdquo;.</b> Every flow gets a verdict: cleared as normal, escalated as an unknown attack, or a named attack with a next-stage forecast. streaming/pipeline_consumer.py writes the same verdicts to streaming/forecasts.jsonl, which the panel below this diagram reads.",
 dash: "<b>Dashboard.</b> Reads the verdicts and shows alerts, forecasts and a simulated response. The &ldquo;Watch a real run&rdquo; panel on this page reads the same verdicts while the real pipeline runs."
};
const panel = document.getElementById('panel');
document.querySelectorAll('.node').forEach(g => {
  const show = () => { document.querySelectorAll('.node').forEach(n => n.classList.remove('on')); g.classList.add('on'); panel.innerHTML = INFO[g.dataset.k]; };
  g.addEventListener('click', show); g.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); show(); } });
});
const segs = document.getElementById('segs');
for (let x = 590; x < 1182; x += 12) { const l = document.createElementNS('http://www.w3.org/2000/svg','line'); l.setAttribute('class','seg'); l.setAttribute('x1',x); l.setAttribute('x2',x); l.setAttribute('y1',446); l.setAttribute('y2',474); segs.appendChild(l); }

// Measured Friday proportions (Findings page): attacks 26.3% of flows.
const P_ATTACK = 0.263;
const OUT_NORMAL = [["a", 0.690], ["v", 0.3087], ["u", 0.0010], ["n", 0.0003]];
const OUT_ATTACK = [["a", 0.008], ["v", 0.018], ["u", 0.047], ["n", 0.927]];
const S = [95, 210], PR = [275, 210], K = [460, 210], A = [680, 210], B = [880, 210], C = [1080, 210], END = [470, 460];
const PATHS = {
  a: [S, PR, K, A, [680, 250], [680, 460], END],
  v: [S, PR, K, A, B, [820, 250], [820, 460], END],
  u: [S, PR, K, A, B, [940, 250], [940, 460], END],
  n: [S, PR, K, A, B, C, [1080, 250], [1080, 460], END]
};
const DROP_INDEX = {a: 5, v: 6, u: 6, n: 7};
const counts = {sent: 0, off: 0, flag: 0, named: 0, fc: 0, out: 0, a: 0, v: 0, u: 0, n: 0, ma: 0, mv: 0, mu: 0, mn: 0};
function pick(table) { let r = Math.random(), acc = 0; for (const [k, p] of table) { acc += p; if (r < acc) return k; } return table[0][0]; }
function lens(pts) { const L = []; for (let i = 1; i < pts.length; i++) L.push(Math.hypot(pts[i][0]-pts[i-1][0], pts[i][1]-pts[i-1][1])); return L; }
const dotsG = document.getElementById('dots'); const dots = [];
function spawn() {
  const atk = Math.random() < P_ATTACK; const out = pick(atk ? OUT_ATTACK : OUT_NORMAL);
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  el.setAttribute('r', 4.2); el.setAttribute('fill', atk ? '#9B2C2C' : '#A39A8A'); dotsG.appendChild(el);
  dots.push({el, atk, out, pts: PATHS[out], L: lens(PATHS[out]), seg: 0, t: 0, done: {}});
  counts.sent++; counts.off++;
}
function passed(d, idx) {
  if (d.done[idx]) return; d.done[idx] = true;
  if (idx === 3 && d.out !== 'a') counts.flag++;
  if (idx === 4 && d.out === 'n') counts.named++;
  if (idx === 5 && d.out === 'n') counts.fc++;
  if (idx === DROP_INDEX[d.out]) { counts[d.out]++; counts.out++; if ((d.atk && d.out !== 'n' && d.out !== 'u') || (!d.atk && (d.out === 'n' || d.out === 'u'))) counts['m' + d.out]++; }
}
let running = !window.matchMedia('(prefers-reduced-motion: reduce)').matches, last = 0, acc = 0;
const SPEED = 230;
function txt(id, v) { document.getElementById(id).textContent = v; }
function render() {
  txt('c_src', counts.sent.toLocaleString() + ' sent'); txt('c_off', 'offset ' + counts.off.toLocaleString());
  txt('c_a', counts.flag.toLocaleString() + ' flagged'); txt('c_b', counts.named.toLocaleString() + ' named');
  txt('c_c', counts.fc.toLocaleString() + ' forecasts'); txt('c_out', counts.out.toLocaleString() + ' published');
  for (const k of ['a', 'v', 'u', 'n']) txt('n_' + k, counts[k].toLocaleString());
  txt('m_a', counts.ma ? counts.ma + ' missed attacks' : ''); txt('m_v', counts.mv ? counts.mv + ' were attacks' : '');
  txt('m_u', counts.mu ? counts.mu + ' were normal' : ''); txt('m_n', counts.mn ? counts.mn + ' false alarms' : '');
}
function step(ts) {
  const dt = last ? Math.min((ts - last) / 1000, 0.05) : 0; last = ts;
  if (running) {
    acc += dt; while (acc > 0.16) { acc -= 0.16; if (dots.length < 140) spawn(); }
    for (let i = dots.length - 1; i >= 0; i--) {
      const d = dots[i]; let move = SPEED * dt;
      while (move > 0 && d.seg < d.L.length) {
        const rem = d.L[d.seg] * (1 - d.t);
        if (move >= rem) { move -= rem; d.seg++; d.t = 0; passed(d, d.seg); } else { d.t += move / d.L[d.seg]; move = 0; }
      }
      if (d.seg >= d.L.length) { d.el.remove(); dots.splice(i, 1); continue; }
      const a = d.pts[d.seg], b = d.pts[d.seg + 1];
      d.el.setAttribute('cx', a[0] + (b[0] - a[0]) * d.t); d.el.setAttribute('cy', a[1] + (b[1] - a[1]) * d.t);
    }
    render();
  }
  requestAnimationFrame(step);
}
const pp = document.getElementById('pp');
function setBtn() { pp.textContent = running ? 'Pause' : 'Play'; pp.setAttribute('aria-pressed', String(!running)); }
pp.onclick = () => { running = !running; last = 0; setBtn(); };
document.getElementById('rs').onclick = () => { for (const k in counts) counts[k] = 0; render(); };
setBtn(); render(); requestAnimationFrame(step);
</script></body></html>
"""
