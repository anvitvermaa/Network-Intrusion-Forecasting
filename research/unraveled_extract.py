

#!/usr/bin/env python3
"""Stream the Unraveled network-flow files (about 22 GB in total) and keep only what the audit needs.

For every attack flow (Stage != Benign) it keeps: file, src_ip, dst_ip, first-seen timestamp (ms),
Activity, Stage, DefenderResponse, Signature. Benign rows are only counted. Nothing large is stored:
each file is read line by line straight from the network.

Rows are parsed by position: src_ip, dst_ip and the timestamp are columns 3, 7 and 15 (before any
free-text field), and the four labels are the last four columns. This is robust to the rows whose
user-agent strings contain commas (a known NFStream export issue).

Output: data/processed/unraveled_attacks.parquet and artifacts/unraveled_extract.json
Re-running skips files already processed (progress is kept in data/processed/unraveled_parts/).
"""
import io
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
PARTS = os.path.join(ROOT, "data", "processed", "unraveled_parts")
OUT = os.path.join(ROOT, "data", "processed", "unraveled_attacks.parquet")
API = "https:" + "//" + "gitlab" + ".com" + "/api/v4/projects/" + "35594914" + "/repository"
IP = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def get(url, retries=4):
    for i in range(retries):
        try:
            return urllib.request.urlopen(url, timeout=120)
        except Exception as e:
            if i == retries - 1:
                raise
            print(f"   retry {i + 1} after error: {e}")
            time.sleep(5 * (i + 1))


def list_files():
    files, page = [], 1
    while True:
        url = f"{API}/tree?path=data/network-flows&recursive=true&per_page=100&page={page}"
        t = json.load(get(url))
        if not t:
            break
        files += [e["path"] for e in t if e["type"] == "blob" and e["path"].endswith(".csv")]
        page += 1
    return sorted(files)


def process(path):
    url = f"{API}/files/{urllib.parse.quote(path, safe='')}/raw?ref=master"
    stream = io.TextIOWrapper(get(url), encoding="utf-8", errors="replace")
    header = stream.readline().rstrip("\n").split(",")
    assert header[2] == "src_ip" and header[6] == "dst_ip" and header[14] == "bidirectional_first_seen_ms", header[:16]
    assert header[-4:] == ["Activity", "Stage", "DefenderResponse", "Signature"], header[-4:]
    rows, n, malformed, unparsed = [], 0, 0, 0
    for line in stream:
        p = line.rstrip("\n").split(",")
        n += 1
        if len(p) != len(header):
            malformed += 1
        act, stage, resp, sig = (x.strip() for x in p[-4:])
        if stage == "Benign":
            continue
        if not (IP.match(p[2]) and IP.match(p[6]) and p[14].isdigit()):
            unparsed += 1
            continue
        rows.append((path, p[2], p[6], int(p[14]), act, stage, resp, sig))
    return rows, {"rows": n, "malformed": malformed, "attack_rows": len(rows), "attack_unparsed": unparsed}


def main():
    os.makedirs(PARTS, exist_ok=True)
    files = list_files()
    print(f"[list] {len(files)} flow files")
    stats = {}
    t0 = time.time()
    for i, path in enumerate(files, 1):
        part = os.path.join(PARTS, path.replace("/", "__") + ".parquet")
        meta = part + ".json"
        if os.path.exists(part) and os.path.exists(meta):
            stats[path] = json.load(open(meta))
            continue
        rows, st = process(path)
        pd.DataFrame(rows, columns=["file", "src_ip", "dst_ip", "ts_ms", "Activity", "Stage", "DefenderResponse", "Signature"]).to_parquet(part)
        json.dump(st, open(meta, "w"))
        stats[path] = st
        print(f"[{i:>3}/{len(files)}] {path.split('/')[-2]}/{path.split('/')[-1]}: {st['rows']:,} rows, "
              f"{st['attack_rows']:,} attack ({time.time() - t0:.0f}s elapsed)")
    df = pd.concat([pd.read_parquet(os.path.join(PARTS, f.replace('/', '__') + ".parquet")) for f in files], ignore_index=True)
    df.to_parquet(OUT)
    summary = {"files": len(files), "rows": sum(s["rows"] for s in stats.values()),
               "malformed_rows": sum(s["malformed"] for s in stats.values()),
               "attack_rows": int(len(df)), "attack_rows_unparsed": sum(s["attack_unparsed"] for s in stats.values()),
               "stage_counts": df["Stage"].value_counts().to_dict(), "signature_counts": df["Signature"].value_counts().to_dict(),
               "response_counts": df["DefenderResponse"].value_counts().to_dict()}
    json.dump(summary, open(os.path.join(ROOT, "artifacts", "unraveled_extract.json"), "w"), indent=2)
    print(json.dumps(summary, indent=2))
    print(f"[saved] {OUT}")


if __name__ == "__main__":
    main()
