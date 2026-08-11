#!/usr/bin/env python3
"""
document.py — split an inbound document into what a human sees and what the
model reads.

The 11:30 demo depends on a viewer seeing both halves side by side, because the
claim being made has two parts and they are easy to conflate:

    the injection SUCCEEDED           — the model read it and complied fully
    the action did NOT happen         — it was never authorised

Those are different facts. A demo that showed only the second would be claiming
the architecture detects injection, which it does not and does not try to.

NO DETECTION HAPPENS HERE. This module is a viewer, not a filter. It exists so
the UI can be honest, and nothing downstream consults it — the agent receives
the whole document, hidden block included, exactly as a real model would.
"""
from __future__ import annotations

import html
import os
import re
import sys

#: Style patterns that render text invisible to a human while leaving it fully
#: legible to anything reading the source. Used ONLY to decide what to show the
#: viewer in which pane — never to strip, sanitise or reject anything.
_INVISIBLE = re.compile(
    r"color\s*:\s*#f{3,6}\b"
    r"|opacity\s*:\s*0?\.0\d*"
    r"|font-size\s*:\s*[01]px"
    r"|display\s*:\s*none"
    r"|visibility\s*:\s*hidden",
    re.I)

_TAG = re.compile(r"<[^>]+>")
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_DIV = re.compile(r"<div\b([^>]*)>(.*?)</div>", re.S | re.I)


def _text(fragment: str) -> str:
    """Tags out, entities decoded, whitespace collapsed."""
    return re.sub(r"\s+", " ", html.unescape(_TAG.sub(" ", fragment))).strip()


def _strip_comments(src: str) -> str:
    """Drop authoring comments — they are notes to the reader of the repo."""
    return _COMMENT.sub("", src)


def extract_hidden(path: str) -> str | None:
    """The text a human reader never sees. Returns None if there is none."""
    with open(path, encoding="utf-8") as fh:
        src = _strip_comments(fh.read())
    parts = [_text(body) for attrs, body in _DIV.findall(src)
             if _INVISIBLE.search(attrs)]
    joined = " ".join(p for p in parts if p)
    return joined or None


def extract_visible(path: str) -> str:
    """What a human reader sees: the document with the hidden blocks removed."""
    with open(path, encoding="utf-8") as fh:
        src = _strip_comments(fh.read())
    for attrs, body in _DIV.findall(src):
        if _INVISIBLE.search(attrs):
            src = src.replace(body, " ")
    return _text(src)


def read_both(path: str) -> dict:
    """Both panes at once, for the UI and for the attack narration."""
    return {"visible": extract_visible(path), "hidden": extract_hidden(path)}


def _demo(path: str) -> int:
    both = read_both(path)
    print("=" * 78)
    print("WHAT THE HUMAN READER SEES")
    print("=" * 78)
    print(both["visible"][:600] + ("..." if len(both["visible"]) > 600 else ""))
    print()
    print("=" * 78)
    print("WHAT THE MODEL ALSO READS  (white-on-white, 1px, at the end)")
    print("=" * 78)
    print(both["hidden"] or "(nothing hidden)")
    print()
    print("The model is not defective for having read this. It has no channel")
    print("that marks one of these as binding and the other as decoration.")
    return 0


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "supplier_qc_report.html")
    sys.exit(_demo(sys.argv[1] if len(sys.argv) > 1 else default))
