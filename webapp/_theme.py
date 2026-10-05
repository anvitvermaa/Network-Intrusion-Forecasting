"""Visual theme and small page components. Warm paper, ink-blue accent, one serif family."""
import html
import os
import streamlit as st

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,500;0,6..72,600;1,6..72,400&display=swap');
:root { --paper:#F5F0E6; --sheet:#FBF8F1; --ink:#1F1D1A; --muted:#6A6357; --rule:#D9D0BE; --blue:#23466B; --green:#2F5D3A; --red:#9B2C2C; }
html, body, [class*="css"], .stMarkdown, .stText, p, li, td, th, label, button, input, textarea {
  font-family: 'Newsreader', Georgia, 'Times New Roman', serif !important; font-variant-numeric: tabular-nums; }
.stApp { background: var(--paper); color: var(--ink); }
header[data-testid="stHeader"] { background: transparent; }
#MainMenu, footer, [data-testid="stMainMenu"], [data-testid="stAppDeployButton"], .stDeployButton, [data-testid="stDecoration"] { display: none !important; }
[data-testid="stExpandSidebarButton"], [data-testid="stSidebarCollapsedControl"], [data-testid="collapsedControl"] { display: flex !important; visibility: visible !important; }
.topnav { border-bottom: 1px solid var(--rule); margin: -1.2rem 0 1.6rem 0; padding-bottom: 0.2rem; }
.topnav [data-testid="stPageLink"] a, .topnav [data-testid="stPageLink-NavLink"] { padding: 0.15rem 0.2rem; }
.topnav [data-testid="stPageLink"] p, .topnav [data-testid="stPageLink-NavLink"] p { font-size: 1.02rem; color: var(--blue); }
.block-container { max-width: 790px; padding-top: 2.6rem; padding-bottom: 5rem; }
section[data-testid="stSidebar"] { background: #EFE8DA; border-right: 1px solid var(--rule); }
section[data-testid="stSidebar"] * { color: var(--ink); }
.mast-title { font-size: 2.55rem; line-height: 1.12; font-weight: 500; letter-spacing: -0.01em; margin: 0 0 0.6rem 0; }
.mast-dek { font-size: 1.32rem; line-height: 1.4; color: var(--muted); font-style: italic; margin: 0 0 0.9rem 0; max-width: 34em; }
.mast-by { font-size: 1.0rem; color: var(--muted); margin-bottom: 1.4rem; padding-bottom: 1.1rem; border-bottom: 1px solid var(--rule); }
.prose p, .prose li { font-size: 1.12rem; line-height: 1.62; max-width: 38em; }
.prose p { margin: 0 0 0.9rem 0; }
h2.sec { font-size: 1.62rem; font-weight: 500; margin: 2.4rem 0 0.25rem 0; padding-top: 1.1rem; border-top: 1px solid var(--rule); }
p.sec-sub { color: var(--muted); font-size: 1.05rem; margin: 0 0 1rem 0; max-width: 38em; }
h3.sub { font-size: 1.24rem; font-weight: 600; margin: 1.6rem 0 0.4rem 0; }
table.led { border-collapse: collapse; width: 100%; margin: 0.6rem 0 0.3rem 0; font-size: 1.0rem; background: var(--sheet); }
table.led, table.led th, table.led td { border-left: 0 !important; border-right: 0 !important; border-top: 0 !important; }
table.led { border: 0 !important; }
table.led th { text-align: left; font-weight: 600; border-bottom: 1.5px solid var(--ink); padding: 0.42rem 0.6rem; vertical-align: bottom; }
table.led td { border-bottom: 1px solid var(--rule); padding: 0.4rem 0.6rem; vertical-align: top; }
table.led td.num, table.led th.num { text-align: right; white-space: nowrap; }
table.led tr.hl td { background: #EAF0F6; }
table.small { font-size: 0.86rem; }
table.small td, table.small th { padding: 0.3rem 0.4rem; }
p.cap { font-size: 0.97rem; color: var(--muted); line-height: 1.5; margin: 0.35rem 0 1.4rem 0; max-width: 40em; }
.note { border-left: 3px solid var(--blue); background: var(--sheet); padding: 0.75rem 1rem; margin: 1rem 0 1.2rem 0; font-size: 1.05rem; line-height: 1.55; }
.note.warn { border-left-color: var(--red); }
.ok { color: var(--green); font-weight: 600; }
.bad { color: var(--red); font-weight: 600; }
.na { color: var(--muted); }
.stButton > button { background: var(--blue); color: #FBF8F1 !important; border: 0; border-radius: 3px; padding: 0.45rem 1.1rem; font-size: 1.0rem; }
.stButton > button:hover { background: #1A3652; color: #FBF8F1 !important; }
.stButton > button:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }
[data-testid="stImage"] img { border: 1px solid var(--rule); background: #fff; }
code, pre, .stCode * { font-family: ui-monospace, 'SFMono-Regular', Menlo, monospace !important; font-size: 0.85rem !important; }
@media (max-width: 640px) { .mast-title { font-size: 1.9rem; } .prose p, .prose li { font-size: 1.05rem; } table.led { font-size: 0.9rem; } }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
</style>
"""

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def setup(title, wide=False):
    st.set_page_config(page_title=title, layout="wide" if wide else "centered", initial_sidebar_state="expanded")
    st.markdown(CSS, unsafe_allow_html=True)
    if wide:
        st.markdown("<style>.block-container { max-width: 1240px; }</style>", unsafe_allow_html=True)
    nav()
    with st.sidebar:
        st.markdown("**Counting Flows, Not Transitions**")
        st.caption("A forecastability audit of kill-chain stage prediction. DSN4091 capstone.")


PAGES = [("Home.py", "Home"), ("pages/0_System.py", "System"), ("pages/1_Method.py", "Method"),
         ("pages/2_Findings.py", "Findings"), ("pages/3_Run.py", "Run"), ("pages/4_Limitations.py", "Limitations")]


def nav():
    """A top navigation row on every page, so moving between pages never depends on the sidebar."""
    st.markdown('<div class="topnav">', unsafe_allow_html=True)
    cols = st.columns(len(PAGES))
    for col, (path, label) in zip(cols, PAGES):
        with col:
            st.page_link(path, label=label)
    st.markdown('</div>', unsafe_allow_html=True)


def raw(h):
    st.markdown(h, unsafe_allow_html=True)


def masthead(title, dek, byline=None):
    raw(f'<div class="mast-title">{title}</div><div class="mast-dek">{dek}</div>'
        + (f'<div class="mast-by">{byline}</div>' if byline else ""))


def section(title, sub=None):
    raw(f'<h2 class="sec">{title}</h2>' + (f'<p class="sec-sub">{sub}</p>' if sub else ""))


def sub(title):
    raw(f'<h3 class="sub">{title}</h3>')


def prose(*paragraphs):
    raw('<div class="prose">' + "".join(f"<p>{p}</p>" for p in paragraphs) + "</div>")


def bullets(items):
    raw('<div class="prose"><ul>' + "".join(f"<li>{i}</li>" for i in items) + "</ul></div>")


def note(text, warn=False):
    raw(f'<div class="note{" warn" if warn else ""}">{text}</div>')


def caption(text):
    raw(f'<p class="cap">{text}</p>')


def table(headers, rows, cap=None, num_cols=(), highlight=(), small=False):
    th = "".join(f'<th class="{"num" if i in num_cols else ""}">{h}</th>' for i, h in enumerate(headers))
    body = ""
    for r, row in enumerate(rows):
        tds = "".join(f'<td class="{"num" if i in num_cols else ""}">{c}</td>' for i, c in enumerate(row))
        body += f'<tr class="{"hl" if r in highlight else ""}">{tds}</tr>'
    raw(f'<table class="led{" small" if small else ""}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>')
    if cap:
        caption(cap)


def figure(rel_path, cap):
    p = os.path.join(ROOT, rel_path)
    if os.path.exists(p):
        st.image(p)
        caption(cap)


def mark(ok):
    if ok is None:
        return '<span class="na">not compared</span>'
    return '<span class="ok">&#10003; matches</span>' if ok else '<span class="bad">&#10007; differs</span>'


def esc(s):
    return html.escape(str(s))
