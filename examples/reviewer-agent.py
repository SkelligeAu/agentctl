#!/usr/bin/env python3
"""
reviewer-agent — pure-Python port of reviewer-agent.c, using the
agentctl Python SDK.

Same wire format, same on-disk task tree, same artifact set
(`review.md`, `risks.json`, `patch-suggestions.diff`), same caps
semantics. Only the language is different.

Invoked by agentctl as:
    agentctl start <name> --runtime /abs/path/to/reviewer-agent.py
"""

import json
import os
import sys

# Locate the SDK whether we live alongside it in the repo or are run via
# realpath from elsewhere. The repo layout puts the SDK at sdk/python/.
_here = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(_here, "..", "sdk", "python"))

# `require_capability` is still exported for Python authors who want
# application-layer cap gating; it is NOT used here because as of the v1
# broker the canonical authority gate is fd possession (issued by agentd),
# not the legacy caps-file overlay. See README §Capabilities.
from agent import Agent  # noqa: E402


PATTERNS = [
    ("TODO",     "low"),
    ("FIXME",    "low"),
    ("password", "high"),
    ("secret",   "high"),
    ("eval",     "med"),
    ("strcpy",   "high"),
    ("gets",     "high"),
]


def count_pattern(hay: bytes, needle: bytes) -> int:
    if not needle:
        return 0
    n = len(hay)
    nl = len(needle)
    if nl > n:
        return 0
    return sum(1 for i in range(n - nl + 1) if hay[i:i + nl] == needle)


def count_diff(buf: bytes):
    """Lines beginning with '+' / '-' (but not '+++' / '---' headers)."""
    added = removed = 0
    at_line_start = True
    for i, b in enumerate(buf):
        if at_line_start:
            tri = buf[i:i + 3]
            if b == ord('+') and tri != b"+++":
                added += 1
            elif b == ord('-') and tri != b"---":
                removed += 1
        at_line_start = (b == ord('\n'))
    return added, removed


agent = Agent()


@agent.handler("review")
def review(task):
    payload = task.payload
    plen = len(payload)
    added, removed = count_diff(payload)
    counts = [count_pattern(payload, p.encode()) for p, _ in PATTERNS]

    md = ["# Review", "",
          f"- payload bytes: {plen}",
          f"- lines added:   {added}",
          f"- lines removed: {removed}", "",
          "## Findings", "",
          "| Pattern | Count | Severity |",
          "|---|---:|---|"]
    total = high = 0
    for (needle, sev), c in zip(PATTERNS, counts):
        md.append(f"| {needle} | {c} | {sev} |")
        total += c
        if sev == "high":
            high += c
    md += ["", "## Summary", "",
           f"{total} findings total; {high} high-severity.", ""]
    task.write_artifact("review.md", "\n".join(md))

    findings_arr = [
        {"pattern": n, "count": c, "severity": s}
        for (n, s), c in zip(PATTERNS, counts) if c > 0
    ]
    risks = {"added": added, "removed": removed, "findings": findings_arr}
    task.write_artifact("risks.json", json.dumps(risks, indent=2) + "\n")

    task.write_artifact("patch-suggestions.diff", payload)

    findings_total = sum(counts)
    task.event(f"review done added={added} removed={removed} "
               f"findings={findings_total}")
    task.complete(f"status: completed\nadded: {added}\nremoved: {removed}\n"
                  f"findings: {findings_total}\n")


if __name__ == "__main__":
    agent.run()
