#!/usr/bin/env python3
"""
check-flow-legs.py — an executable consumer for the flow-leg document.

Each leg names a receiver obligation and cites the clauses that impose it. This
asserts every cited clause is ENFORCED SOMEWHERE in the Python reference: it
appears as the label of a FailClosed or CriticalAlert raise site, or as a
mutation-target marker.

WHAT THIS CATCHES. A leg citing a clause nothing enforces -- a receiver
obligation that reads as a control and is a sentence. That is the failure the
document is most exposed to, because a clause id resolving in the spec proves
only that someone WROTE the rule, never that anything APPLIES it.

It also asserts DP-83's other half, which had no consumer at all until ACP-78:
every leg NAMES THE ARTIFACT it carries, every artifact name comes from a CLOSED
vocabulary declared in the annex, and every vocabulary entry cites a clause or
section that actually contains the term. A coined name -- a second vocabulary for
an object the specification already names, which is the defect DP-16 forbids one
layer down -- cannot survive that last check.

And it resolves DP-7's five enumerated inbound crossings against the register.
That is what found the missing time-source leg: DP-7 named the crossing, the
register omitted it, and nothing compared the two.

WHAT IT DOES NOT CATCH, stated so the claim is not read wider than it is:
it does not check the leg cites the RIGHT clause, nor that the enforcement sits
at the point the leg names. A leg citing DR-9 passes on DR-9 being raised
anywhere. That is a weaker claim than the document makes and is the residual.

Two more residuals, both from the ACP-78 checks. The vocabulary check asserts the
cited span CONTAINS the term, never that it uses it in the sense the leg means --
a term used in passing satisfies it. And the DP-7 check matches an enumerated
crossing to an artifact the register carries SOMEWHERE; it does not check the
leg's direction or its endpoints, so a crossing enumerated inbound and recorded
only outbound would pass. Both are narrower than they look and are stated here
rather than left to be assumed wider.

The DP-7 match falls back to an artifact's head noun, because DP-7 writes
"signed bundle bytes" where the vocabulary says "Policy Bundle". That looseness
already produced one false pass -- see the comment in dp7_crossings() -- and it
is the part of this file most likely to pass for the wrong reason next.
"""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC  = ROOT / "spec/ACP-DEPLOY-001.md"   # Annex A, the leg register
SRC  = ROOT / "reference/src"

# Clauses that are structural or transport obligations with no runtime raise
# site by construction. Each needs a reason, or it is an excuse.
# Where the raise label is not the clause id. Recorded, not hidden: a reader
# grepping for PB-7 in the executor finds nothing, and that is worth knowing.
ALIAS = {
 "PB-7":  "PB-DISTINCT",   # executor raises the mechanism name, not the clause id
 "9.3-7": "TR-8",          # step 7's refusal is labelled by the rule it applies
}

EXEMPT = {
 "B-1":   "schema validation at ingress; enforced in sim/ingress.py, not the executor",
 "B-1a":  "a transport requirement -- the proposal travels WITH the receipt; its"
          " violation is caught downstream as 9.3-3, which is separately cited",
 "B-3":   "a negative ROUTING obligation, like B-4: raw model output reaches the"
          " validator and nothing else. Nothing raises it because no code path"
          " exists that could -- it is enforced by the ABSENCE of a wire, and an"
          " absent wire has no line to break. `llm_agent_suite.py` covers the"
          " client's shape (no tools, no network) but does not observe where"
          " output is routed, so this is exempted, NOT covered",
 "B-4":   "a negative architectural obligation: no route exists. Nothing raises"
          " the absence of a route; D-2 says 'verified by test' at the network layer",
 "B-6":   "adapter stamps fidelity; the executor's check is 9.3-7, separately cited",
 "V-3":   "closed-grammar validation lives in the ingress schema, not a raise site",
 "PB-2":  "author != reviewer is an authoring-time control in acp-bundle-cli",
 "PB-5":  "epoch monotonicity is raised as RAD-3, separately cited",
 "PB-8":  "bundle signature verification raises CR-1/CR-4, separately cited",
 "CP-2":  "provider-level P-4 default; no reference Context provider exists yet",
 "DR-3":  "delivery fan-out; its failure is raised as DR-8, separately cited",
 "DR-11": "sampling draw is Executor-local; its absence is not a raise but a"
          " missing input -- covered by ack_suite's DR-10 sampling cases",
  "CR-3":  "conjunctive composition is a BOOLEAN (acp_executor.py:149 `all(...)`),"
          " not a raise. The refusal happens at the call site as 9.3-7b-i, which"
          " is separately cited. A raise here would be a second refusal path",
 "P-4":   "a principle, not a check: 'unknown is never LOW' is realised BY the"
          " fail-safe defaults -- 8.4-3 refusal, RV-1 IRREVERSIBLE, absent floor"
          " => T3 -- each of which raises under its own id. P-4 appears in no"
          " reference module and correctly so; citing it names the reason, not"
          " the mechanism",
 "AT-1":  "field set of the Attestation Object; violations raise AT-8b",
 "AT-5":  "single-use enforced by ledger consumption, raised as CL-3",
 "AU-1":  "chain construction is a pure function; audit_suite asserts the clause"
          " derives the implementation head (added by ACP-57)",
 "AU-2":  "database constraints, not application raises",
 "AU-3":  "external anchoring mechanism; the ordering obligation raises AU-7",
 "AU-4":  "runs outside the production domain; no in-process raise site",
 "12.5":  "NTS time discipline is a HOST obligation, not an application raise, and"
          " nothing in either repository exercises it -- ACP-DEPLOY-001 says so in"
          " as many words: 'nothing at all exercises the NTS-loss cap'. This"
          " exemption records an UNCHECKED normative MUST, not a covered one. If a"
          " time-source branch is ever built and this line still reads the same,"
          " the exemption has become a lie -- the wording 11.3 already carries",
 "11.3":  "the reconciliation job is UNIMPLEMENTED. It runs in the anchor"
          " verifier's trust domain by AU-4, never the production domain, so no"
          " in-process raise could carry it even once it exists. Annex A discloses"
          " the row as carrying no enumerated obligations. This exemption records"
          " an absent component, NOT a covered one -- if the job is built and this"
          " line still reads the same, the exemption has become a lie",
 "CL-7":  "a POSITIVE-PATH OBLIGATION, and labelled one rather than dressed up as"
          " a control. Check-then-mutate is an ORDERING property -- the read phase"
          " completes across a majority before any replica mutates -- so deleting"
          " it raises nothing; it silently corrupts instead. Proven by"
          " partition_suite.py::t_origin_binding_immutable_across_partition, which"
          " partitions so a later majority intersects a prior binding at exactly"
          " one node and asserts the prior value is ADOPTED and readable after heal",
 "RAD-4": "asserted, but as a PROCESS-ISOLATION property rather than a raise:"
          " `python3 -m sim.supervise --checks` asserts 'policy and executor"
          " independently derive the same bundle' (sim/supervise.py:86). It is a"
          " weaker consumer than a mutation-killed raise, and the gate does not"
          " run it -- noted rather than counted as equivalent",
}

def cited_clauses(doc):
    """Annex A rows: | leg | crossing | artifact | obligations |.

    A row declaring no receiving obligation is a DP-85 disclosure, not a gap,
    and is returned separately so it is counted and shown rather than skipped.

    A row that is NEITHER is returned as malformed and FAILS. It used to be
    dropped in silence -- `if ids:` with no else -- so a row whose obligation
    cell stopped parsing simply left the register, the denominator shrank, and
    the run still printed PASS. Adding the artifact column would have done
    exactly that to all 36 rows at once. A check whose coverage can fall to zero
    while it reports success is the failure this repository exists to argue
    about, so a row now leaves this function through one of three named doors.
    """
    obliged, declared_none, malformed, artifacts = {}, [], [], {}
    for line in doc.splitlines():
        m = re.match(r'\|\s*(F\d\.\d)\s*\|', line)
        if not m: continue
        leg = m.group(1)
        cells = [c.strip() for c in line.split('|')]
        # cells[0] is the empty string before the leading pipe
        artifact   = cells[3] if len(cells) > 5 else ""
        obligation = cells[4] if len(cells) > 5 else ""
        artifacts[leg] = artifact
        if 'no receiving obligation' in obligation:
            declared_none.append(leg); continue
        # Two id shapes, and omitting the second silently skipped the most
        # important obligations in the register: the 9.3 executor steps.
        ids  = re.findall(r'\b((?:AT|AC|AQ|AU|B|CL|CP|CR|DR|DS|EO|PB|RAD|RES|RK|RV|TR|V|WE|P)-\d+[a-z]?)\b', obligation)
        ids += re.findall(r'\b(\d+\.\d+(?:-[0-9a-z]+)*)\b', obligation)
        if ids: obliged[leg] = sorted(set(ids))
        else:   malformed.append(leg)
    return obliged, declared_none, malformed, artifacts


# ------------------------------------------------------- DP-83's other half
# The artifact vocabulary, and the resolver that proves each name is the
# specification's own rather than one this register coined.

def vocabulary(doc):
    """The `| Artifact | Named at |` table, read as a closed set."""
    vocab, seen_header = {}, False
    for line in doc.splitlines():
        if re.match(r'\|\s*Artifact\s*\|\s*Named at\s*\|', line):
            seen_header = True; continue
        if not seen_header: continue
        if not line.startswith('|'): break
        cells = [c.strip() for c in line.split('|')]
        if len(cells) < 4 or set(cells[1]) <= set('- '): continue
        vocab[cells[1]] = cells[2]
    return vocab


def cite_span(cite, docs):
    """Resolve `§N.N` to its heading section, or a clause id to its bullet.

    Returns None when the citation resolves nowhere, which is itself a failure:
    a name defended by a citation that does not exist is an undefended name.
    """
    for text in docs:
        lines = text.splitlines()
        if cite.startswith("\u00a7"):
            pat = r'^#{2,4}\s+' + re.escape(cite[1:]) + r'[\s.]'
        else:
            pat = r'^\s*-\s+\*\*' + re.escape(cite) + r'\b'
        for i, l in enumerate(lines):
            if re.match(pat, l):
                j = i + 1
                while j < len(lines) and not re.match(r'^#{2,4}\s', lines[j]) and (
                       cite.startswith("\u00a7") or not re.match(r'^\s*-\s+\*\*[A-Z0-9]', lines[j])):
                    j += 1
                return "\n".join(lines[i:j])
    return None


def dp7_crossings(doc):
    """DP-7's enumerated inbound crossings, as (numeral, text) pairs.

    DP-7 attests that the control plane's inbound crossings are enumerated. The
    register is where they are supposed to appear. Nothing compared the two
    until ACP-78, and the comparison immediately found (v) -- the network time
    source -- present in the clause and absent from the register.
    """
    m = re.search(r'-\s+\*\*DP-7\.[^\n]*', doc)
    if not m: return []
    parts = re.split(r'\((i|ii|iii|iv|v|vi|vii|viii|ix|x)\)\s*', m.group(0))
    out = []
    for k in range(1, len(parts) - 1, 2):
        # Bound each item to ITS OWN clause. The last item runs on into DP-7's
        # closing prose, and that prose is what made this check pass for the
        # wrong reason during development: crossing (v) -- the network time
        # source -- was satisfied by the artifact `audit record`, because the
        # word "record" appears in "not in the deployment record is a topology
        # defect". The missing leg this check exists to find would have been
        # reported as covered. Found by deleting the leg AND its vocabulary row
        # and watching the mutant survive; the orphan-vocabulary check had been
        # doing the killing.
        text = parts[k + 1]
        cut = text.find(';')
        if cut == -1: cut = text.find('. ')
        out.append((parts[k], text if cut == -1 else text[:cut]))
    return out

def enforced(src):
    ids = set()
    files = list(src.glob("*.py")) + list((ROOT/"sim").glob("*.py"))
    for f in files:
        t = f.read_text()
        ids |= set(re.findall(r'(?:FailClosed|CriticalAlert)\("([^"]+)"', t))
        # Comments are NOT enforcement. Counting them made this check vacuous:
        # DR-9 appears in docstrings across acp_ack/acp_audit, so deleting every
        # DR-9 RAISE still passed. Raise labels only.
    return ids

def main():
    doc  = DOC.read_text()
    spec = (ROOT / "spec/ACP-SPEC-001.md").read_text()
    legs, none_declared, malformed, artifacts = cited_clauses(doc)
    have = enforced(SRC)
    # a 9.3 step id enforces the checklist clauses the executor applies there
    have |= {i.split('-')[0] for i in have if i.startswith('9.3')}
    unenforced, ok = [], 0
    for leg, ids in sorted(legs.items()):
        for cid in ids:
            label = ALIAS.get(cid, cid)
            if label in have or any(h.startswith(label + "-") for h in have): ok += 1
            elif cid in EXEMPT: ok += 1
            else: unenforced.append((leg, cid))

    # --- DP-83: the artifact half ------------------------------------------
    vocab   = vocabulary(doc)
    docs    = [spec, doc]
    fails   = []
    for leg in sorted(artifacts):
        a = artifacts[leg]
        if not a:
            fails.append(f"{leg} names no artifact -- DP-83 requires one")
        elif a not in vocab:
            fails.append(f"{leg} carries '{a}', which is not in the artifact vocabulary")
    for name, cite in sorted(vocab.items()):
        span = cite_span(cite, docs)
        if span is None:
            fails.append(f"artifact '{name}' cites {cite}, which resolves nowhere")
        elif name.lower() not in span.lower():
            fails.append(f"artifact '{name}' cites {cite}, which does not contain the term"
                         f" -- a coined name, not the specification's")
    carried = set(artifacts.values())
    for name in sorted(set(vocab) - carried):
        fails.append(f"artifact '{name}' is declared and carried by no leg")

    # --- DP-7: every enumerated inbound crossing has a leg ------------------
    crossings = dp7_crossings(doc)
    if not crossings:
        fails.append("DP-7's enumerated crossings did not parse -- the check is vacuous")
    for numeral, text in crossings:
        low = text.lower()
        if not any(n.lower() in low or n.split()[-1].lower() in low for n in carried if n):
            fails.append(f"DP-7 crossing ({numeral}) names no artifact any leg carries"
                         f" -- an enumerated crossing with no row")

    for leg in malformed:
        fails.append(f"{leg} cites no clause and declares no DP-85 exemption"
                     f" -- it would once have been dropped in silence")

    print(f"legs: {len(artifacts)}   with cited obligations: {len(legs)}   clause citations: {ok + len(unenforced)}")
    print(f"legs declaring NO obligation (DP-85): {len(none_declared)} {none_declared}")
    print(f"enforced or exempt: {ok}   UNENFORCED: {len(unenforced)}")
    print(f"artifact vocabulary: {len(vocab)}   DP-7 crossings resolved: {len(crossings)}")
    for leg, cid in unenforced:
        print(f"  FAIL  {leg} cites {cid} -- no raise site, no marker, no exemption")
    for f in fails:
        print(f"  FAIL  {f}")
    bad = len(unenforced) + len(fails)
    print("RESULT:", "PASS -- obligations enforced or exempted; every leg names a specified artifact"
          if not bad else f"FAIL -- {bad} defect(s) in the leg register")
    return 1 if bad else 0

sys.exit(main())
