#!/usr/bin/env python3
"""
attack_registry.py — the single, explained attack surface for ACP-SPEC-001.

WHY THIS EXISTS. Until v1.3.12 the attacks lived in eight separate files. Three
consequences, all bad:

  1. A reader running conformance.py saw "44/44" and reasonably concluded that
     was the coverage. It is the v1.3.5 historical set; 33 attacks added since
     lived elsewhere.
  2. The newer attacks never met the distributed ledger. partition_integration
     replays only a SUBSET of the original vectors and skips DR-*/RV-*
     entirely, so nothing exercised an acknowledgement or an audit anchor
     arriving mid-partition -- even though ACK-5 now DEPENDS on the ledger.
  3. A change to the Executor broke one file, and you noticed only if you ran
     that file.

This module is the registry. Every attack is declared once, with the rule it
targets, the clause it defends, and a plain-language statement of what it does
and why it matters. Suites remain runnable on their own; this composes them.

    python3 attack_registry.py              # run everything, grouped
    python3 attack_registry.py --explain    # the same, with full explanations
    python3 attack_registry.py -i           # interactive browser
    python3 attack_registry.py --coverage   # clause coverage matrix
    python3 attack_registry.py --compose    # NEW: attacks x partitioned ledger
"""
from __future__ import annotations
import argparse, sys, time

import conformance as C
import cbor_suite, audit_suite, ack_suite, class_findings
from acp_executor import FailClosed, CriticalAlert


# ---------------------------------------------------------------- metadata
# (id, group, rule, one-line what, why it matters)
META = {
    # --- historical defects, replayed as live attacks -------------------
    "Y1":   ("Binding", "9.3-7b-ii", "An approval signed for action A is presented for action B.",
             "If approvals aren't bound to a specific action, one legitimate approval authorises anything."),
    "Y1b":  ("Binding", "Y1b", "The approval's identifier is supplied by the attacker instead of computed.",
             "A supplied identifier lets an attacker point the single-use check at a slot that was never consumed."),
    "Y2":   ("Freshness", "L-14", "A decision is issued with a validity window of hours instead of seconds.",
             "A long window turns a one-time authorisation into a reusable one."),
    "Y4":   ("Identity", "AT-2", "The requester's name is swapped so they appear to be an independent approver.",
             "Separation of duties collapses if the requester can also count as the approver."),
    "Z3":   ("Identity", "DS-6f", "The action's origin identifier is substituted to duplicate an action.",
             "Two executions of one authorised action is exactly what exactly-once must prevent."),
    "Z4":   ("Encoding", "AT-8b", "An extra optional field creates a second valid encoding of one approval.",
             "Two encodings of one value means the single-use ledger sees two different slots."),
    "X1":   ("Recomputation", "TR-8", "A signed decision claims the action is low risk when it is not.",
             "The lie is inside a valid signature, so only independent recomputation catches it."),
    "T15":  ("Freshness", "RAD-3", "An older policy rulebook is replayed to reinstate a withdrawn permission.",
             "Rollback undoes a security decision without touching any signature."),
    "T13":  ("Replay", "CL-2", "A decision receipt is replayed after it was already used.",
             "Without single-use, one authorisation becomes unlimited executions."),
    "T14":  ("Replay", "CL-3", "An approval is replayed onto a later action.",
             "Captured approvals must not accumulate into a quorum."),
    "T10":  ("Authorisation", "9.3-9", "A permission is revoked between approval and execution.",
             "The gap between deciding and doing is where revocation gets ignored."),
    "B-1a": ("Binding", "9.3-3", "The action is altered after it was approved.",
             "Approval must cover the exact bytes executed, not a similar request."),
    "CR":   ("Cryptography", "CR-3/CR-4", "Signature suite downgraded, a primitive stripped, or one half forged.",
             "Hybrid means both must verify; accepting either is weaker than either alone."),
    "DR":   ("Human boundary", "DR-*", "Release before the hold, shared render path, undeliverable notice, expired receipt.",
             "The human channel is where a compromised screen or a silent notification does its damage."),
    "RV":   ("Human boundary", "RV-1/RV-3", "A receipt claims an irreversible action can be undone.",
             "Reversibility decides whether silence is consent; it must be recomputed, never believed."),
    "INV":  ("Quorum", "INV-1-HIGH", "A high-impact action arrives with no approvals at all.",
             "The single invariant the whole architecture exists to hold."),
    # --- newer surfaces --------------------------------------------------
    "CBOR": ("Encoding", "AT-8a", "Non-canonical encodings: key order, padding, indefinite length, duplicates, floats.",
             "A permissive decoder silently normalises and reopens the two-encodings-one-value defect."),
    "AC":   ("Accounting", "AC-5", "Actions attributed to a victim then repudiated, to lock them out by inflating a counter.",
             "Counting decisions rather than executions turns a denial-of-service into an authorisation change."),
    "AU":   ("Audit", "AU-6/7/8", "Release without an anchored record; chain rewritten after anchoring; outage saturating approvers.",
             "If the trace can be erased, every detection-based residual downstream is worthless."),
    "ACK":  ("Identity", "ACK-1..6", "Approval by unauthenticated name, unregistered identity, forged signature, replay, expiry.",
             "The strongest human guarantee was satisfiable by typing a name. Now it needs a registered key."),
    "T32":  ("Human boundary", "T-32", "A compromised notifier certifies its own independence and delivery.",
             "OPEN. The runtime check is a lint, not a control: assurance rests on build-time separation."),
}


# Suite-level defaults. Name matching is used ONLY inside suite 1, whose test
# names carry the historical defect ids as a prefix. An earlier version matched
# substrings across all suites and filed "canonical round-trip accepted" under
# AC-5 because "ac" appears inside "accepted" -- a reminder that a classifier
# with no boundaries silently produces confident nonsense.
SUITE_DEFAULT = {"1 Conformance": None, "5 Encoding": "CBOR",
                 "7 Audit": "AU", "9 Acknowledgement": "ACK",
                 "8 Findings": "ACK"}

_PREFIXES = ("Y1b", "B-1a", "T15", "T13", "T14", "T10", "Y1", "Y2", "Y4",
             "Z3", "Z4", "X1", "CR", "DR", "RV")


def _meta(name: str, suite: str | None = None):
    default = SUITE_DEFAULT.get(suite or "", None)
    if default is not None:
        # findings suite: T-32 entries are their own category
        if suite == "8 Findings" and "T-32" in name:
            return "T32", META["T32"]
        return default, META[default]
    up = name.upper()
    for k in _PREFIXES:
        if up.startswith(k.upper()):
            return k, META[k]
    if "NO ATTESTATION" in up or "INV-1" in up:
        return "INV", META["INV"]
    for k in _PREFIXES:
        if up.split()[0].upper() == k.upper():
            return k, META[k]
    return "INV", META["INV"]


# ------------------------------------------------------------- collection
def collect():
    """
    Build the registry. Each entry:
      (suite, name, callable, kind)
    kind: 'raises'  -> must raise FailClosed/CriticalAlert
          'returns' -> returns (ok, detail)
    """
    reg = []
    for name, fn, *_ in C.ATTACKS:
        reg.append(("1 Conformance", name, fn, "raises"))
    for name, fn in cbor_suite.TESTS:
        reg.append(("5 Encoding", name, fn, "returns"))
    for name, fn in audit_suite.TESTS:
        reg.append(("7 Audit", name, fn, "returns"))
    for name, fn in ack_suite.TESTS:
        reg.append(("9 Acknowledgement", name, fn, "returns"))
    for name, fn in class_findings.TESTS:
        reg.append(("8 Findings", name, fn, "returns"))
    return reg


def run_one(kind, fn):
    """Return (ok, detail)."""
    try:
        if kind == "raises":
            fn()
            return False, "EXECUTED — did not fail closed"
        ok, detail = fn()
        return ok, detail
    except (FailClosed, CriticalAlert) as e:
        return (True, f"[{e.rule}]") if kind == "raises" else \
               (False, f"unexpected [{e.rule}]")
    except Exception as e:
        return False, f"unexpected {type(e).__name__}: {e}"


# ------------------------------------------------------------------ modes
def cmd_run(explain=False):
    reg = collect()
    print("=" * 78)
    print("ACP — CONSOLIDATED ATTACK REGISTRY")
    print("=" * 78)
    print(f"{len(reg)} attacks and positive paths across 5 suites. Every one is")
    print("declared once here, with the rule it targets and why it matters.\n")

    groups, fails = {}, 0
    for suite, name, fn, kind in reg:
        groups.setdefault(suite, []).append((name, fn, kind))

    for suite in sorted(groups):
        print(f"\n{'─'*78}\n{suite.upper()}\n{'─'*78}")
        for name, fn, kind in groups[suite]:
            ok, detail = run_one(kind, fn)
            fails += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<46} {detail}")
            if explain:
                key, (grp, rule, what, why) = _meta(name, suite)
                print(f"        · targets  : {rule}  ({grp})")
                print(f"        · attack   : {what}")
                print(f"        · matters  : {why}\n")

    print("\n" + "=" * 78)
    print(f"RESULT: {len(reg)-fails}/{len(reg)}"
          f"{' — every attack fails closed, every honest path executes' if not fails else ' — REVIEW REQUIRED'}")
    print("\nMutation controls are separate and equally load-bearing:")
    print("  python3 mutate_executor.py            19 executor checks")
    print("  python3 audit_suite.py --mutate        4 audit checks")
    print("  python3 ack_suite.py --mutate          6 acknowledgement checks")
    print("A passing suite proves nothing until you show it can fail.")
    return 1 if fails else 0


def cmd_coverage():
    reg = collect()
    cov = {}
    for suite, name, _fn, _k in reg:
        key, (grp, rule, _w, _y) = _meta(name, suite)
        cov.setdefault((grp, rule), []).append((suite.split()[0], name))
    print("=" * 78)
    print("CLAUSE COVERAGE — which defence each attack exercises")
    print("=" * 78)
    for (grp, rule) in sorted(cov):
        items = cov[(grp, rule)]
        print(f"\n{grp:<16} {rule}")
        print(f"  {len(items)} attack(s): " +
              ", ".join(sorted({f'S{s}' for s, _ in items})))
        for _s, n in items[:4]:
            print(f"    · {n}")
        if len(items) > 4:
            print(f"    · … and {len(items)-4} more")
    print("\n" + "=" * 78)
    print("NOT COVERED BY ANY ATTACK — and cannot be:")
    print("  A-7   label honesty        no test decides if a label matches the world")
    print("  A-8   display fidelity     no test proves a human read the screen")
    print("  T-32  notifier self-cert   OPEN: runtime check is a lint, not a control")
    print("  RR-1  independent review   requires a party with no authorship history")
    return 0


def cmd_compose():
    """
    NEW COVERAGE. The acknowledgement and audit machinery has never met the
    distributed ledger, even though ACK-5's single-use guarantee DEPENDS on it.
    This runs the acknowledgement attacks against a quorum ledger, including
    one arriving while the ledger has no reachable majority.
    """
    from acp_ledger import QuorumLedgerAdapter, LedgerFailClosed
    from acp_ack import AuthenticatedReleaseGate, make_ack
    from acp_executor import PendingRelease, render_from_canonical

    NOW = time.time()

    class N:
        def render(self, p): return render_from_canonical(p, "notify-mobile")
        def recipients(self, pr): return ["op_1121", "op_3307", C.OP]
        def deliver(self, r, n): return list(r)

    def build(partition=None):
        b = C.make_bundle()
        led = QuorumLedgerAdapter(5)
        if partition is not None:
            led.set_partition(partition)
        g = AuthenticatedReleaseGate(bundle=b, ledger=led, hold_seconds=60,
                                     notifier=N(), sample_rate=0.0)
        pr = PendingRelease(
            proposal_hash="sha256:c", proposal={"task_type": "modify_firewall_rule",
            "targets": ["prod-db"], "params": {}},
            receipt={"expires_at": NOW + 300}, operator=C.OP, risk="HIGH",
            idempotency_key="k", fidelity="FAITHFUL", verified_at=NOW,
            release_at=NOW + 60, reversibility="IRREVERSIBLE")
        g.hold_action(pr, render_from_canonical(pr.proposal, "approval-ui"))
        return b, g, pr, led

    results = []

    def case(name, fn):
        try:
            ok, d = fn()
        except Exception as e:
            ok, d = False, f"unexpected {type(e).__name__}: {e}"
        results.append((name, ok, d))

    def honest_on_quorum():
        b, g, pr, _ = build()
        g.confirm(pr.proposal_hash, make_ack(b, pr.proposal_hash, "op_1121",
                                             "CONFIRM", C.SIGNERS["op_1121"], now=NOW),
                  now=NOW + 1)
        out = g.release(pr.proposal_hash, NOW + 61)
        return out["executed"], "acknowledgement consumed on a 5-replica ledger"

    def replay_on_quorum():
        b, g, pr, _ = build()
        a = make_ack(b, pr.proposal_hash, "op_1121", "CONFIRM",
                     C.SIGNERS["op_1121"], now=NOW)
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        try:
            g.confirm(pr.proposal_hash, a, now=NOW + 2)
            return False, "replay accepted against the quorum ledger"
        except (CriticalAlert, LedgerFailClosed) as e:
            return True, f"replay refused [{e.rule}]"

    def ack_during_partition():
        """The composition nothing tested: an acknowledgement arriving while
        the ledger has no reachable majority. Single-use cannot be recorded,
        so it MUST fail closed rather than accept unrecorded."""
        b, g, pr, led = build()
        led.set_partition({0, 1})                      # minority
        a = make_ack(b, pr.proposal_hash, "op_1121", "CONFIRM",
                     C.SIGNERS["op_1121"], now=NOW)
        try:
            g.confirm(pr.proposal_hash, a, now=NOW + 1)
            return False, "ACCEPTED an acknowledgement it could not record"
        except (LedgerFailClosed, CriticalAlert) as e:
            return True, f"fail closed [{e.rule}]"

    def heal_does_not_resurrect():
        b, g, pr, led = build()
        a = make_ack(b, pr.proposal_hash, "op_1121", "CONFIRM",
                     C.SIGNERS["op_1121"], now=NOW)
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        led.set_partition({0, 1, 2}); led.set_partition(None)   # partition + heal
        try:
            g.confirm(pr.proposal_hash, a, now=NOW + 2)
            return False, "acknowledgement reusable after heal"
        except (CriticalAlert, LedgerFailClosed) as e:
            return True, f"still consumed after heal [{e.rule}]"

    case("honest acknowledgement on quorum ledger", honest_on_quorum)
    case("acknowledgement replay refused on quorum", replay_on_quorum)
    case("acknowledgement during partition fails closed", ack_during_partition)
    case("heal does not resurrect an acknowledgement", heal_does_not_resurrect)

    print("=" * 78)
    print("COMPOSITION — ACKNOWLEDGEMENT × DISTRIBUTED LEDGER  (new in v1.3.12)")
    print("=" * 78)
    print("ACK-5's single-use guarantee depends on the ledger, and until now no")
    print("test put the two together. Partition is an ordinary network event.\n")
    bad = 0
    for name, ok, d in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<48} {d}")
        bad += not ok
    print("=" * 78)
    print(f"RESULT: {len(results)-bad}/{len(results)}"
          f"{' — composition holds' if not bad else ' — REVIEW REQUIRED'}")
    return 1 if bad else 0


def cmd_interactive():
    reg = collect()
    groups = {}
    for suite, name, fn, kind in reg:
        groups.setdefault(suite, []).append((name, fn, kind))
    while True:
        print("\n" + "=" * 78)
        print("ACP ATTACK REGISTRY — interactive")
        print("=" * 78)
        keys = sorted(groups)
        for i, k in enumerate(keys, 1):
            print(f"  {i}. {k:<26} {len(groups[k])} attacks")
        print(f"  {len(keys)+1}. Run everything")
        print(f"  {len(keys)+2}. Clause coverage")
        print(f"  {len(keys)+3}. Composition (ack × partitioned ledger)")
        print("  q. Quit")
        try:
            c = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return 0
        if c == "q":
            return 0
        if not c.isdigit():
            continue
        n = int(c)
        if n == len(keys) + 1:
            cmd_run(explain=False); continue
        if n == len(keys) + 2:
            cmd_coverage(); continue
        if n == len(keys) + 3:
            cmd_compose(); continue
        if not (1 <= n <= len(keys)):
            continue
        suite = keys[n - 1]
        print(f"\n{suite}\n{'─'*78}")
        for j, (name, fn, kind) in enumerate(groups[suite], 1):
            print(f"  {j}. {name}")
        try:
            c2 = input("\npick one (enter = run all in this group) > ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        chosen = groups[suite] if not c2 else (
            [groups[suite][int(c2) - 1]] if c2.isdigit()
            and 1 <= int(c2) <= len(groups[suite]) else [])
        for name, fn, kind in chosen:
            key, (grp, rule, what, why) = _meta(name, suite)
            ok, detail = run_one(kind, fn)
            print(f"\n  {name}")
            print(f"    what it does : {what}")
            print(f"    why it matters: {why}")
            print(f"    rule targeted : {rule} ({grp})")
            print(f"    RESULT        : {'PASS' if ok else 'FAIL'}  {detail}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--explain", action="store_true")
    ap.add_argument("--coverage", action="store_true")
    ap.add_argument("--compose", action="store_true")
    ap.add_argument("-i", "--interactive", action="store_true")
    a = ap.parse_args()
    if a.interactive:
        return cmd_interactive()
    if a.coverage:
        return cmd_coverage()
    if a.compose:
        return cmd_compose()
    return cmd_run(explain=a.explain)


if __name__ == "__main__":
    sys.exit(main())
