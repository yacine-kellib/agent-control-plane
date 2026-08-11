#!/usr/bin/env python3
"""
class_findings.py — executable demonstration of T-31 and T-32.

Produced by the v1.3.11 regeneration of ACP-CLASS-001 (02b). Both findings
are UNDISCLOSED T entries: inputs consumed for a control decision, taken as
transmitted from the party being verified, and never enumerated against a
residual. By 02b's own rule that is a conformance failure, so v1.3.6 through
v1.3.10 were non-conformant against suite 12 without knowing it.

These tests PASS when the defect is present. They are the falsifying evidence
for the finding, not a regression suite.

STATUS. T-31 was CLOSED in v1.3.12 by ACK-1..ACK-6 (`acp_ack.py`); its
inversions live in `ack_suite.py` (14/14, mutants 6/6). The T-31 cases below
are retained against the UNPATCHED DeferredReleaseGate as the historical
record: they document what the defect was and prove the fix addresses a real
break, exactly as the Dafny model mechanizes defects alongside fixes (§04).
T-32 remains OPEN and is reproduced against the current code.

    python3 class_findings.py
"""
import sys, time
# Run-from-anywhere: see the note in conformance.py. isdir guard keeps it inert
# in mutation temp dirs so a mutant is never shadowed by the real module.
import os as _os
_SRC = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), _os.pardir, "src")
if _os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from acp_executor import (DeferredReleaseGate, PendingRelease,
                            render_from_canonical, CriticalAlert, FailClosed)

NOW = time.time()


def pend(ph="sha256:p", rev="IRREVERSIBLE", operator="op-1"):
    return PendingRelease(
        proposal_hash=ph,
        proposal={"task_type": "order_synthesis", "targets": ["synth-queue"],
                  "params": {}},
        receipt={"expires_at": NOW + 300}, operator=operator, risk="HIGH",
        idempotency_key="k", fidelity="FAITHFUL", verified_at=NOW,
        release_at=NOW + 60, reversibility=rev)


def approval(p):
    return render_from_canonical(p, "approval-ui")


class HonestNotifier:
    def render(self, p): return render_from_canonical(p, "notify-mobile")
    def recipients(self, pr): return ["attester-1", "attester-2"]
    def deliver(self, r, n): return list(r)


class LyingNotifier:
    """
    Compromised notification service. It renders through the APPROVAL path --
    so there is exactly one render path, not two -- and then asserts the three
    properties the Executor uses to check independence.
    """
    def render(self, p):
        s = render_from_canonical(p, "approval-ui")   # the approval path
        s.source_path = "notify-mobile"               # ...declares otherwise
        s.from_canonical = True                       # ...asserts canonicity
        return s
    def recipients(self, pr): return ["attester-1"]
    def deliver(self, r, n): return list(r)           # asserts own delivery


# ---------------------------------------------------------------- T-31
def t31_unauthenticated_acknowledgement():
    """
    DR-9 requires positive acknowledgement from a non-operator before an
    IRREVERSIBLE action releases. The acknowledgement identity is a STRING.
    No signature, no key, no credential. Anyone able to call confirm() with a
    notified name satisfies the strongest guarantee in the deferred-release
    design.

    Contrast: an ATTESTATION carries a signature verified against a key in the
    signed bundle, and Y4 specifically moved the operator identity into those
    signed bytes. Acknowledgements never got the same treatment.
    """
    g = DeferredReleaseGate(60, HonestNotifier(), 0.0)
    pr = pend()
    g.hold_action(pr, approval(pr.proposal))

    g.confirm(pr.proposal_hash, "attester-1")     # <- no proof of anything
    out = g.release(pr.proposal_hash, NOW + 61)

    ok = out["executed"] and out["human_verified"]
    return ok, ("irreversible action released, human_verified=True, "
                "zero signatures verified")


def t31_no_key_material_anywhere():
    """Second angle: the gate holds no attester keys at all, so it could not
    verify an acknowledgement even if one were offered."""
    g = DeferredReleaseGate(60, HonestNotifier(), 0.0)
    has_keys = any("key" in a.lower() for a in dir(g))
    return (not has_keys), ("the release gate holds no key material — "
                            "acknowledgement authenticity is unverifiable "
                            "by construction")


# ---------------------------------------------------------------- T-32
def t32_notifier_self_certifies():
    """
    DR-2 requires the notification path to share no rendering code with the
    approval path. The check compares two SELF-DECLARED labels and reads a
    SELF-ASSERTED boolean. A compromised notifier passes it while being the
    approval renderer.
    """
    g = DeferredReleaseGate(60, LyingNotifier(), 0.0)
    pr = pend(ph="sha256:q", rev="REVERSIBLE")
    try:
        g.hold_action(pr, approval(pr.proposal))
        return True, ("DR-2 and DR-8 passed against a notifier that IS the "
                      "approval path and certified its own independence")
    except CriticalAlert as e:
        return False, f"unexpectedly blocked [{e.rule}]"


def t32_delivery_is_self_reported():
    """DR-8 'delivery complete' is whatever the notifier returns."""
    class SilentNotifier(LyingNotifier):
        def deliver(self, r, n): return list(r)   # claims delivery, sends none
    g = DeferredReleaseGate(60, SilentNotifier(), 0.0)
    pr = pend(ph="sha256:r", rev="REVERSIBLE")
    try:
        g.hold_action(pr, approval(pr.proposal))
        return True, ("DR-8 satisfied by a notifier that delivered nothing "
                      "and said it had")
    except CriticalAlert as e:
        return False, f"unexpectedly blocked [{e.rule}]"


TESTS = [
    ("T-31 acknowledgement identity is a bare string", t31_unauthenticated_acknowledgement),
    ("T-31 gate holds no key material at all", t31_no_key_material_anywhere),
    ("T-32 notifier certifies its own independence", t32_notifier_self_certifies),
    ("T-32 delivery completeness is self-reported", t32_delivery_is_self_reported),
]


def main():
    print("=" * 74)
    print("ACP-CLASS-001 v1.3.11 — FINDINGS T-31 / T-32, DEMONSTRATED")
    print("=" * 74)
    print("These tests PASS when the defect is PRESENT. Invert them once the")
    print("v1.3.12 signed-acknowledgement fix lands.\n")
    bad = 0
    for name, fn in TESTS:
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"unexpected {type(e).__name__}: {e}"
        print(f"  {'CONFIRMED' if ok else 'NOT REPRODUCED'}  {name}")
        print(f"      {detail}")
        bad += not ok
    print("=" * 74)
    print(f"RESULT: {len(TESTS)-bad}/{len(TESTS)} findings reproduced"
          f"{' — T-31 historical (fixed v1.3.12), T-32 open' if not bad else ''}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
