#!/usr/bin/env python3

"""Undo copy-paste damage where every line break became two (a blank line after every line).

Usage: python3 fix_doubled_lines.py path/to/file

Only changes the file if the damage pattern is detected; keeps a .bak copy."""

import re

import shutil

import sys

 

p = sys.argv[1]

s = open(p, encoding="utf-8").read().replace("\r\n", "\n")

lines = s.split("\n")

nonblank_followed_by_blank = sum(1 for i in range(len(lines) - 1) if lines[i].strip() and not lines[i + 1].strip())

nonblank = sum(1 for l in lines if l.strip())

ratio = nonblank_followed_by_blank / max(nonblank, 1)

print(f"{nonblank} non-empty lines; {ratio:.0%} of them are followed by a blank line")

if ratio < 0.8:

    print("No doubling detected. File left unchanged.")

    sys.exit(0)

shutil.copy(p, p + ".bak")

fixed = s.replace("\n\n", "\n")

fixed = "\n".join(l.rstrip() for l in fixed.split("\n"))

open(p, "w", encoding="utf-8").write(fixed)

print(f"Fixed: every doubled line break halved. Original saved as {p}.bak")
