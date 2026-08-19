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

WHAT IT DOES NOT CATCH, stated so the claim is not read wider than it is:
it does not check the leg cites the RIGHT clause, nor that the enforcement sits
at the point the leg names. A leg citing DR-9 passes on DR-9 being raised
anywhere. That is a weaker claim than the document makes and is the residual.
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
    """Annex A rows: | leg | crossing | obligations |.

    A row declaring no receiving obligation is a DP-85 disclosure, not a gap,
    and is returned separately so it is counted and shown rather than skipped.
    """
    obliged, declared_none = {}, []
    for line in doc.splitlines():
        m = re.match(r'\|\s*(F\d\.\d)\s*\|', line)
        if not m: continue
        cells = [c.strip() for c in line.split('|')]
        obligation = cells[3] if len(cells) > 4 else ""
        if 'no receiving obligation' in obligation:
            declared_none.append(m.group(1)); continue
        # Two id shapes, and omitting the second silently skipped the most
        # important obligations in the register: the 9.3 executor steps.
        ids  = re.findall(r'\b((?:AT|AC|AQ|AU|B|CL|CP|CR|DR|DS|EO|PB|RAD|RES|RK|RV|TR|V|WE|P)-\d+[a-z]?)\b', obligation)
        ids += re.findall(r'\b(\d+\.\d+(?:-[0-9a-z]+)*)\b', obligation)
        if ids: obliged[m.group(1)] = sorted(set(ids))
    return obliged, declared_none

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
    doc = DOC.read_text()
    (legs, none_declared), have = cited_clauses(doc), enforced(SRC)
    # a 9.3 step id enforces the checklist clauses the executor applies there
    have |= {i.split('-')[0] for i in have if i.startswith('9.3')}
    unenforced, ok = [], 0
    for leg, ids in sorted(legs.items()):
        for cid in ids:
            label = ALIAS.get(cid, cid)
            if label in have or any(h.startswith(label + "-") for h in have): ok += 1
            elif cid in EXEMPT: ok += 1
            else: unenforced.append((leg, cid))
    print(f"legs with cited obligations: {len(legs)}   clause citations: {ok + len(unenforced)}")
    print(f"legs declaring NO obligation (DP-85): {len(none_declared)} {none_declared}")
    print(f"enforced or exempt: {ok}   UNENFORCED: {len(unenforced)}")
    for leg, cid in unenforced:
        print(f"  FAIL  {leg} cites {cid} -- no raise site, no marker, no exemption")
    print("RESULT:", "PASS -- every cited obligation is enforced or exempted with a reason"
          if not unenforced else f"FAIL -- {len(unenforced)} obligation(s) cite nothing that runs")
    return 1 if unenforced else 0

sys.exit(main())
