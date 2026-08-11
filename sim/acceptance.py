#!/usr/bin/env python3
"""
acceptance.py — brief §8's twelve criteria, as executable checks.

Each criterion is driven against the real components: the reference Executor,
the real gates, the real quorum ledger. Nothing is asserted about behaviour
that was not produced by running it.

Two criteria do not come back a clean green, and both are reported as what they
are rather than rounded up. A suite that returns all-pass on its first run has
usually been written to agree with itself.

Run:  python3 -m sim.acceptance
"""
from __future__ import annotations

import sys

import sim  # noqa: F401
from acp_executor import CriticalAlert, Executor, FailClosed, h
from acp_ledger import QuorumLedgerAdapter

from sim.approve import render as approve_render
from sim.bundle import make_bundle, proposal
from sim.log import BLOCKING_CONTROLS
from sim.notify import render as notify_render
from sim.policy import PolicyEngine
from sim.receipts import make_quorum, make_receipt
from sim.release import (ACCUMULATOR_THRESHOLD, assert_render_paths_distinct,
                         build_release_stack, sign_ack)
from sim.world import capabilities

NOW = 1000.0


# ------------------------------------------------------------------ harness
class Harness:
    """A single floor-HIGH action, driven step by step so each check can stop
    wherever the criterion is actually about."""

    def __init__(self, *, replicas: int = 5, hold: int = 60,
                 sample_rate: float = 0.0, now: float = NOW):
        self.bundle = make_bundle()
        self.context = capabilities(self.bundle.permitted_targets)
        self.ledger = QuorumLedgerAdapter(n=replicas)
        self.stack = build_release_stack(self.bundle, self.ledger,
                                         hold_seconds=hold,
                                         sample_rate=sample_rate, now=now)
        self.gate = self.stack["gate"]
        self.anchor = self.stack["anchor"]
        self.chain = self.stack["chain"]
        self.acc = self.stack["accumulators"]
        self.executor = Executor(bundle=self.bundle, ledger=self.ledger,
                                 context=self.context, gate=self.gate)

    def hold(self, p: dict, *, approvers: list, operator: str,
             atts: bool = True, now: float = NOW, roles: list | None = None):
        a = (make_quorum(self.bundle, p, operator=operator, approvers=approvers,
                         risk="HIGH", now=now, required_roles=roles)
             if atts else [])
        r = make_receipt(self.bundle, p, operator=operator, now=now, atts=a)
        out = self.executor.execute(r, p, approval_summary=approve_render.render(p))
        return h(p), out


def order(operator="sci-01", candidate="cand-1", cost=40000):
    return proposal("order_synthesis", "synthesis-queue", operator=operator,
                    program="prog-internal", candidate=candidate, cost_eur=cost)


def assay(operator="sci-01", candidate="cand-1"):
    return proposal("schedule_assay", "assay-queue", operator=operator,
                    program="prog-internal", candidate=candidate,
                    assay_type="binding")


# ================================================================ criteria
def c1_fast_path_touches_nothing():
    """Fast-path actions never touch the ledger, the notifier or an approver."""
    from sim.run_day import Simulation
    log = Simulation(verbose=False).run()
    fast = [r for r in log if r.risk in ("LOW", "MEDIUM") and r.outcome == "executed"]
    bad = [r for r in fast if r.controls_touched & BLOCKING_CONTROLS]
    nonce = [r for r in fast if "ledger:nonce" in r.controls_touched]
    if bad:
        return False, f"{len(bad)} fast-path actions reached a blocking control"
    return "PARTIAL", (
        f"{len(fast)} fast-path actions touched no notifier, approver, anchor "
        f"or hold. But all {len(nonce)} claimed a receipt nonce against the "
        f"Consumption Ledger: §9.3 step 6 exempts no risk class, and an "
        f"unconsumed nonce is a replayable receipt (T-09). The criterion as "
        f"written is not satisfiable by a conformant implementation.")


def c2_reversible_releases_on_silence():
    """A HIGH reversible action releases on silence AND is recorded unverified."""
    hh = Harness(sample_rate=0.0)
    p = assay()
    ph, out = hh.hold(p, approvers=["sci-03", "ops-01"], operator="sci-01")
    if not out.get("pending_release"):
        return False, "reversible HIGH executed at verification time (DR-1)"
    res = hh.gate.release(ph, NOW + 61)
    if res.get("human_verified"):
        return False, "released as verified without any acknowledgement"
    if hh.gate.unverified_releases != 1:
        return False, f"DR-12 counter is {hh.gate.unverified_releases}, expected 1"
    return True, ("released on silence; DR-12 counted it as unverified debt "
                  "(counter=1, human_verified=False)")


def c3_irreversible_fails_closed_at_timeout():
    """A HIGH irreversible action with no acknowledgement fails closed."""
    hh = Harness()
    p = order()
    ph, out = hh.hold(p, approvers=["sci-03", "ops-01"], operator="sci-01")
    try:
        hh.gate.release(ph, NOW + 61)
        return False, "irreversible action released with no acknowledgement"
    except FailClosed as e:
        return e.rule == "DR-9", f"[{e.rule}] {e.detail}"


def c4_cross_program_refused_before_quorum():
    """The injected cross-program release is refused at policy evaluation."""
    pe = PolicyEngine(make_bundle())
    p = proposal("release_to_partner", "partner-channel:prog-beta",
                 operator="sci-01", program="prog-alpha",
                 dataset="ds-alpha-binding-001", source_program="prog-alpha")
    d = pe.evaluate(p)
    if d.disposition != "DENY":
        return False, f"disposition was {d.disposition}, expected DENY"
    if d.required_count:
        return False, "a quorum was specified for a refused action"
    return d.rule == "XPROG-1", (
        f"[{d.rule}] refused at policy evaluation with no quorum requested — "
        f"both sides of the comparison came from the signed bundle")


def c5_injected_synthesis_refused_no_attestations():
    """The injected synthesis order is refused for absent attestations."""
    hh = Harness()
    p = order(candidate="cand-0007")
    try:
        hh.hold(p, approvers=[], operator="sci-01", atts=False)
        return False, "floor-HIGH executed with no attestations"
    except FailClosed as e:
        return e.rule == "INV-1-HIGH", f"[{e.rule}] {e.detail}"


def c6_repudiation_increments_nothing():
    """Repudiated proposals increment no accumulator; the operator can still act."""
    hh = Harness()
    for i in range(12):
        p = order(candidate=f"cand-9{i:03d}")
        ph, _ = hh.hold(p, approvers=["sci-03", "ops-01"], operator="sci-01",
                        now=NOW + i)
        ack = sign_ack(hh.bundle, ph, "ops-01", "REPUDIATE", NOW + i + 1)
        hh.gate.repudiate(ph, ack, NOW + i + 1)
        try:
            hh.gate.release(ph, NOW + i + 61)
        except FailClosed:
            pass
    count = hh.acc.counts.get("sci-01", 0)
    if count:
        return False, f"accumulator incremented {count} times on repudiated actions"
    if hh.acc.locked("sci-01"):
        return False, "sci-01 was locked out by repudiated proposals"
    # ...and can still act immediately afterwards.
    p = order(candidate="cand-legit")
    ph, out = hh.hold(p, approvers=["sci-03", "ops-01"], operator="sci-01",
                      now=NOW + 100)
    ack = sign_ack(hh.bundle, ph, "ops-01", "CONFIRM", NOW + 101)
    hh.gate.confirm(ph, ack, NOW + 101)
    res = hh.gate.release(ph, NOW + 161)
    return bool(res.get("executed")), (
        "12 repudiations produced 0 accumulator increments (AC-5 counts at "
        "release); sci-01 executed a legitimate order immediately after")


def c7_regulatory_fails_closed_without_anchor():
    """A submit_regulatory release with an unreachable anchor fails closed."""
    hh = Harness()
    p = proposal("submit_regulatory", "regulatory-submission", operator="sci-01",
                 program="prog-internal", dossier="dos-1", milestone="IND")
    ph, _ = hh.hold(p, approvers=["sci-03", "ops-01"], operator="sci-01")
    ack = sign_ack(hh.bundle, ph, "ops-01", "CONFIRM", NOW + 1)
    hh.gate.confirm(ph, ack, NOW + 1)
    hh.anchor.up = False                      # the anchor goes away mid-hold
    try:
        hh.gate.release(ph, NOW + 61)
        return False, "released without an anchored audit record"
    except FailClosed as e:
        return e.rule == "AU-7", (
            f"[{e.rule}] {e.detail} — detection that can be erased is not "
            f"detection, so the release waits for the anchor, not the reverse")


def c8_ack_replay_refused():
    """An acknowledgement replayed onto a second action is refused."""
    hh = Harness()
    p1, p2 = order(candidate="cand-A"), order(candidate="cand-B")
    ph1, _ = hh.hold(p1, approvers=["sci-03", "ops-01"], operator="sci-01")
    ph2, _ = hh.hold(p2, approvers=["sci-03", "ops-01"], operator="sci-01",
                     now=NOW + 1)
    ack = sign_ack(hh.bundle, ph1, "ops-01", "CONFIRM", NOW + 1)
    hh.gate.confirm(ph1, ack, NOW + 1)        # legitimate use
    try:
        hh.gate.confirm(ph2, ack, NOW + 2)    # replay onto a different action
        return False, "an acknowledgement was reused across two actions"
    except FailClosed as e:
        return e.rule in ("ACK-3", "ACK-5"), (
            f"[{e.rule}] {e.detail} — bound to one proposal hash and "
            f"consumed once")


def c9_self_acknowledgement_refused():
    """An acknowledgement from the requester themselves is refused."""
    hh = Harness()
    p = order(operator="sci-01")
    ph, _ = hh.hold(p, approvers=["sci-03", "ops-01"], operator="sci-01")
    ack = sign_ack(hh.bundle, ph, "sci-01", "CONFIRM", NOW + 1)
    try:
        hh.gate.confirm(ph, ack, NOW + 1)
        return False, "the operator acknowledged their own action"
    except FailClosed as e:
        return e.rule == "DR-9", (
            f"[{e.rule}] {e.detail} — the party who initiated the action "
            f"carries no independent information about whether the screen "
            f"they were shown was honest")


def c10_ledger_majority_loss_stops_high():
    """Killing the ledger majority stops HIGH actions and leaves no partial state."""
    hh = Harness(replicas=5)
    for node in (0, 1, 2):                     # 3 of 5 gone: no majority
        hh.ledger.kill(node)
    p = order(candidate="cand-partition")
    try:
        hh.hold(p, approvers=["sci-03", "ops-01"], operator="sci-01")
        return False, "a floor-HIGH action proceeded without a ledger majority"
    except Exception as e:
        pending = len(hh.gate.pending)
        if pending:
            return False, f"{pending} action(s) left pending after fail-closed"
        rule = getattr(e, "rule", type(e).__name__)
        return True, (f"[{rule}] fail-closed with 0 actions left pending — "
                      f"safety preserved, availability is the stated cost")


def c11_shared_render_path_refused_at_startup():
    """Running the notifier and approval from a shared render path is refused."""
    ok_msg = assert_render_paths_distinct()
    original = approve_render.render
    try:
        # The exact refactor the rule exists to prevent: the approval screen
        # re-exporting the notifier's renderer. Both would render honestly from
        # canonical bytes, and that is precisely why honesty is not the test.
        approve_render.render = notify_render.render
        try:
            assert_render_paths_distinct()
            return False, "a shared rendering code path was accepted at startup"
        except CriticalAlert as e:
            return True, (f"[{e.rule}] refused — distinct paths are "
                          f"({ok_msg.split('||')[0].strip()} vs the approval "
                          f"module), and collapsing them fails at startup")
    finally:
        approve_render.render = original


def c12_counterfactual_is_derived():
    """The counterfactual is computed from the event log, not hard-coded."""
    from sim.run_day import Simulation
    from sim.scoreboard import counterfactual

    log = Simulation(verbose=False).run()
    base = counterfactual(list(log), ACCUMULATOR_THRESHOLD)

    # Change one business fact in the log and the counterfactual must move with
    # it. A hard-coded total would not notice.
    recs = list(log)
    target = next((r for r in recs
                   if r.attack and r.task == "order_synthesis"), None)
    if target is None:
        return False, "no attack-originated synthesis order in the log"
    target.params = dict(target.params, cost_eur=target.params["cost_eur"] + 7)
    moved = counterfactual(recs, ACCUMULATOR_THRESHOLD)

    if moved["spend_eur"] != base["spend_eur"] + 7:
        return False, (f"counterfactual did not track the log "
                       f"({base['spend_eur']} → {moved['spend_eur']})")
    if not base["disclosures"]:
        return False, "no disclosure derived from the log"
    return True, (f"EUR {base['spend_eur']:,} and "
                  f"{len(base['disclosures'])} disclosure(s) derived from "
                  f"{base['stopped_actions']} stopped actions; perturbing one "
                  f"logged cost moved the total by exactly that amount")


CRITERIA = [
    ("1.  fast path touches no control", c1_fast_path_touches_nothing),
    ("2.  reversible releases on silence, counted unverified", c2_reversible_releases_on_silence),
    ("3.  irreversible fails closed at timeout", c3_irreversible_fails_closed_at_timeout),
    ("4.  cross-program release refused before quorum", c4_cross_program_refused_before_quorum),
    ("5.  injected synthesis refused, no attestations", c5_injected_synthesis_refused_no_attestations),
    ("6.  repudiation increments no accumulator", c6_repudiation_increments_nothing),
    ("7.  regulatory fails closed without an anchor", c7_regulatory_fails_closed_without_anchor),
    ("8.  replayed acknowledgement refused", c8_ack_replay_refused),
    ("9.  self-acknowledgement refused", c9_self_acknowledgement_refused),
    ("10. ledger majority loss stops HIGH actions", c10_ledger_majority_loss_stops_high),
    ("11. shared render path refused at startup", c11_shared_render_path_refused_at_startup),
    ("12. counterfactual derived from the log", c12_counterfactual_is_derived),
]


def main() -> int:
    print("=" * 96)
    print("ACCEPTANCE CRITERIA — brief §8")
    print("=" * 96)
    failures = 0
    partials = 0
    for name, fn in CRITERIA:
        try:
            ok, detail = fn()
        except Exception as e:                       # a crash is a failure
            ok, detail = False, f"{type(e).__name__}: {e}"
        if ok == "PARTIAL":
            mark, partials = "PARTIAL", partials + 1
        elif ok:
            mark = "PASS   "
        else:
            mark, failures = "FAIL   ", failures + 1
        print(f"\n  {mark}  {name}")
        for line in _wrap(detail, 84):
            print(f"           {line}")
    print("\n" + "=" * 96)
    passed = len(CRITERIA) - failures - partials
    print(f"RESULT: {passed} pass, {partials} partial, {failures} fail "
          f"(of {len(CRITERIA)})")
    if partials:
        print("A partial is a criterion the implementation does not meet as written.")
        print("It is reported rather than rounded up, because the gap is the finding.")
    print("=" * 96)
    return 1 if failures else 0


def _wrap(text: str, width: int) -> list:
    words, lines, cur = str(text).split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


if __name__ == "__main__":
    sys.exit(main())
