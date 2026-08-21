#!/usr/bin/env python3
"""
spec-lookup.py — answer a question about the specifications without reading them.

WHY THIS EXISTS. The two normative documents are ~2,984 and ~3,100 lines. Nothing
indexes them: the code graph in `.code-review-graph/` holds 827 nodes across 42
source files and **zero markdown**, so every question about a clause has been
answered by paging prose into context. On 2026-08-21 one session spent six such
reads deriving 23 artifact names for the flow-leg register, then wrote a
throwaway extractor that produced the same answer for a thousandth of the cost --
and the extractor immediately caught two names the specification does not use.
The cheap method was also the better method, and it was reached last.

This is that extractor, made permanent and given the queries the session actually
needed. Read to orient; use this to extract.

USAGE
  ./tools/spec-lookup.py clause AT-1 DR-13 CL-7      full text of each clause
  ./tools/spec-lookup.py section 8.6                 full text of a section
  ./tools/spec-lookup.py map                         every heading, with line numbers
  ./tools/spec-lookup.py find "quorum threshold"     which clauses mention a term
  ./tools/spec-lookup.py defines "Attestation Object"  where a term is NAMED
  ./tools/spec-lookup.py count "Door A" "Door B"     occurrences, per document

  --doc spec|deploy|both   (default both)
  --brief                  first line of each hit only -- the cheap default for
                           surveying; ask for the full text once you know which

WHAT IT IS NOT. It is not an index of meaning and it does not know which clause
is RIGHT for a question. `find` is a text search with clause-level granularity,
which is the useful unit here because clause ids are how this repository cites
anything. Reading the clause it points at is still the reader's job.

`defines` is the one that earns its place: it asks whether a term is used inside
a cited clause or section, which is the check that stopped two coined artifact
names from entering the leg register. Naming an object the specification already
names, differently, is the encoding-split defect at the vocabulary level.
"""
import argparse, re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = {
    "spec":   ROOT / "spec/ACP-SPEC-001.md",
    "deploy": ROOT / "spec/ACP-DEPLOY-001.md",
}

# A clause bullet: `- **AT-1 (REVISED...).** text` or `- **DP-83 (NEW ...).**`
CLAUSE_RE = r'^\s*-\s+\*\*([A-Z][A-Za-z0-9]*-\d+[a-z]?)\b'
HEADING_RE = r'^(#{2,4})\s+(.*)$'


def load(which):
    names = list(DOCS) if which == "both" else [which]
    for n in names:
        p = DOCS[n]
        if not p.exists():
            print(f"missing: {p}", file=sys.stderr); continue
        yield n, p.read_text().splitlines()


def clause_span(lines, cid):
    """A clause runs to the next clause bullet at any depth, or the next heading.

    Sub-clauses (AT-8a under AT-8) are separate bullets, so asking for AT-8 gives
    AT-8 and not its children. That is deliberate: the register cites them
    separately and conflating them would make a citation check pass on the wrong
    text.
    """
    pat = r'^\s*-\s+\*\*' + re.escape(cid) + r'\b'
    for i, l in enumerate(lines):
        if re.match(pat, l):
            j = i + 1
            while j < len(lines) and not re.match(CLAUSE_RE, lines[j]) \
                    and not re.match(HEADING_RE, lines[j]):
                j += 1
            return i + 1, lines[i:j]
    return None, None


def section_span(lines, num):
    pat = r'^#{2,4}\s+' + re.escape(num) + r'[\s.]'
    for i, l in enumerate(lines):
        if re.match(pat, l):
            j = i + 1
            while j < len(lines) and not re.match(HEADING_RE, lines[j]):
                j += 1
            return i + 1, lines[i:j]
    return None, None


def emit(doc, line, body, brief):
    head = body[0] if body else ""
    if brief:
        print(f"  [{doc}:{line}] {head[:200]}")
    else:
        print(f"\n===== {doc}:{line} " + "=" * 40)
        print("\n".join(body).rstrip())


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("mode", choices=["clause", "section", "map", "find", "defines", "count"])
    ap.add_argument("terms", nargs="*")
    ap.add_argument("--doc", default="both", choices=["spec", "deploy", "both"])
    ap.add_argument("--brief", action="store_true")
    a = ap.parse_args()
    found = False

    for doc, lines in load(a.doc):
        if a.mode == "map":
            for i, l in enumerate(lines):
                m = re.match(HEADING_RE, l)
                if m: print(f"  [{doc}:{i+1}] {'  ' * (len(m.group(1)) - 2)}{m.group(2)}")
            found = True

        elif a.mode == "count":
            for t in a.terms:
                n = sum(l.lower().count(t.lower()) for l in lines)
                print(f"  [{doc}] {t!r}: {n}")
            found = True

        elif a.mode in ("clause", "section"):
            span = clause_span if a.mode == "clause" else section_span
            for t in a.terms:
                line, body = span(lines, t)
                if body: emit(doc, line, body, a.brief); found = True

        elif a.mode == "find":
            # Clause-level granularity: report the clause id a hit falls under,
            # because a bare line number is not something anyone can cite.
            cur, curline = None, 0
            for i, l in enumerate(lines):
                m = re.match(CLAUSE_RE, l)
                if m: cur, curline = m.group(1), i + 1
                if re.match(HEADING_RE, l): cur = None
                for t in a.terms:
                    if t.lower() in l.lower():
                        where = f"{cur} (line {curline})" if cur else f"line {i+1}"
                        print(f"  [{doc}] {where}: {l.strip()[:180]}")
                        found = True

        elif a.mode == "defines":
            # "Is TERM actually used inside CITATION?" -- the anti-coinage check.
            if len(a.terms) != 2:
                sys.exit("defines takes exactly two arguments: TERM CITATION")
            term, cite = a.terms
            span = section_span if cite.lstrip("§")[0].isdigit() else clause_span
            line, body = span(lines, cite.lstrip("§"))
            if body is None: continue
            text = "\n".join(body)
            ok = term.lower() in text.lower()
            print(f"  [{doc}:{line}] {cite} {'CONTAINS' if ok else 'DOES NOT CONTAIN'} {term!r}")
            found = True

    if not found:
        print("  (no match)")
        return 1
    return 0


sys.exit(main())
