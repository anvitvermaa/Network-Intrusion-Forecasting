"""Run the project's real research scripts from the website and stream their output into the page."""
import json
import os
import subprocess
import sys
import streamlit as st

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def path(*parts):
    return os.path.join(ROOT, *parts)


def exists(rel):
    return os.path.exists(path(rel))


def load_json(rel):
    with open(path(rel)) as f:
        return json.load(f)


def run(args, height_lines=18):
    """Run `python <args>` from the project root. Shows the live output; returns (exit code, full log)."""
    box = st.empty()
    lines = []
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    proc = subprocess.Popen([sys.executable] + list(args), cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
    for line in proc.stdout:
        lines.append(line.rstrip("\n"))
        box.code("\n".join(lines[-height_lines:]), language=None)
    proc.wait()
    return proc.returncode, "\n".join(lines)
