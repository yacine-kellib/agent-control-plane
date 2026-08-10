#!/usr/bin/env python3
"""
ack_suite.py — Suite 9: ACK-1..ACK-6, the v1.3.12 fix for T-31.

The T-31 tests in class_findings.py PASS when the defect is present. These are
their inversions: the same attacks, now required to FAIL CLOSED, plus the
honest path, plus mutation controls so every new check is shown load-bearing.

    python3 ack_suite.py
    python3 ack_suite.py --mutate
"""
import os, shutil, subprocess, sys, tempfile, time

import conformance as C
from acp_executor import (PendingRelease, render_from_canonical, h, sign,
                            FailClosed, CriticalAlert, Ledger)
from acp_ack import AuthenticatedReleaseGate, make_ack, ACK1_FIELDS

NOW = time.time()
OP = C.OP


class Notifier:
    def render(self, p): return render_from_canonical(p, "notify-mobile")
    def recipients(self, pr): return ["op_1121", "op_3307", C.OP]
    def deliver(self, r, n): return list(r)


def gate():
    b = C.make_bundle()
    return b, AuthenticatedReleaseGate(bundle=b, ledger=Ledger(),
                                       hold_seconds=60, notifier=Notifier(),
                                       sample_rate=0.0)


def pend(b, ph="sha256:p", rev="IRREVERSIBLE"):
    return PendingRelease(
        proposal_hash=ph,
        proposal={"task_type": "modify_firewall_rule", "targets": ["prod-db"],
                  "params": {}},
        receipt={"expires_at": NOW + 300}, operator=OP, risk="HIGH",
        idempotency_key="k", fidelity="FAITHFUL", verified_at=NOW,
        release_at=NOW + 60, reversibility=rev)


def held(rev="IRREVERSIBLE", ph="sha256:p"):
    b, g = gate()
    pr = pend(b, ph, rev)
    g.hold_action(pr, render_from_canonical(pr.proposal, "approval-ui"))
    return b, g, pr


def ack(b, ph, who="op_1121", decision="CONFIRM", key=None, **over):
    a = make_ack(b, ph, who, decision, key or C.KEYS[who], now=NOW)
    a["obj"].update(over)
    if "resign" in over:
        pass
    return a


def resign(b, a, who="op_1121"):
    """Re-sign after mutating the object, so the test isolates the intended
    check rather than being caught by the signature."""
    a["sig"] = sign(C.KEYS[who], h(a["obj"]), a["obj"]["alg"])
    return a


# ------------------------------------------------------------- honest path
def t_honest_signed_ack_releases():
    b, g, pr = held()
    g.confirm(pr.proposal_hash, ack(b, pr.proposal_hash), now=NOW + 1)
    out = g.release(pr.proposal_hash, NOW + 61)
    return out["executed"] and out["human_verified"], \
        "irreversible action releases on a VERIFIED acknowledgement"


def t_honest_repudiation_blocks():
    b, g, pr = held(rev="REVERSIBLE")
    g.repudiate(pr.proposal_hash,
                ack(b, pr.proposal_hash, decision="REPUDIATE"), now=NOW + 1)
    try:
        g.release(pr.proposal_hash, NOW + 61)
        return False, "released after repudiation"
    except CriticalAlert as e:
        return e.rule == "DR-4", f"[{e.rule}]"


# --------------------------------------------------- T-31 inversions
def t_T31_bare_string_refused():
    """The v1.3.11 defect: a claimed name. Must now fail closed."""
    b, g, pr = held()
    try:
        g.confirm(pr.proposal_hash, "attester-1", now=NOW + 1)
        return False, "bare string still accepted"
    except (CriticalAlert, FailClosed) as e:
        return e.rule == "ACK-1", f"bare-string form refused [{e.rule}]"


def t_T31_unregistered_identity_refused():
    """An identity with no key in the signed bundle cannot acknowledge."""
    b, g, pr = held()
    a = make_ack(b, pr.proposal_hash, "mallory", "CONFIRM", b"attacker-key",
                 now=NOW)
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        return False, "unregistered identity accepted"
    except CriticalAlert as e:
        return e.rule == "ACK-2", f"[{e.rule}]"


def t_T31_forged_signature_refused():
    """Right identity, wrong key."""
    b, g, pr = held()
    a = make_ack(b, pr.proposal_hash, "op_1121", "CONFIRM", b"wrong-key",
                 now=NOW)
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        return False, "forged signature accepted"
    except CriticalAlert as e:
        return e.rule == "ACK-2", f"[{e.rule}]"


def t_T31_identity_swap_refused():
    """
    ACK-4: the identity is taken from the signed bytes. Rewriting
    `acknowledger` after signing must not change who the gate thinks signed.
    """
    b, g, pr = held()
    a = ack(b, pr.proposal_hash, who="op_1121")
    a["obj"]["acknowledger"] = "op_3307"      # swap WITHOUT re-signing
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        return False, "identity swap accepted"
    except CriticalAlert as e:
        return e.rule == "ACK-2", f"signature no longer verifies [{e.rule}]"


def t_T31_operator_cannot_self_confirm():
    """AT-2 restated on a signature-covered identity."""
    b, g, pr = held()
    a = make_ack(b, pr.proposal_hash, OP, "CONFIRM", C.KEYS[OP], now=NOW) \
        if OP in C.KEYS else None
    if a is None:
        return True, "operator holds no attester key — cannot acknowledge at all"
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        return False, "operator confirmed their own action"
    except FailClosed as e:
        return e.rule == "DR-9", f"[{e.rule}]"


# ------------------------------------------------- binding / replay / freshness
def t_ACK3_wrong_proposal_refused():
    """An acknowledgement of a DIFFERENT action must not release this one."""
    b, g, pr = held(ph="sha256:this")
    a = ack(b, "sha256:other")
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        return False, "cross-action acknowledgement accepted"
    except CriticalAlert as e:
        return e.rule == "ACK-3", f"[{e.rule}]"


def t_ACK5_replay_refused():
    """A captured acknowledgement is single-use."""
    b, g, pr = held(rev="REVERSIBLE")
    a = ack(b, pr.proposal_hash)
    g.confirm(pr.proposal_hash, a, now=NOW + 1)
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 2)
        return False, "replayed acknowledgement accepted"
    except CriticalAlert as e:
        return e.rule in ("ACK-5", "CL-3"), f"[{e.rule}]"


def t_ACK6_expired_refused():
    b, g, pr = held()
    a = ack(b, pr.proposal_hash)
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 5000)
        return False, "expired acknowledgement accepted"
    except CriticalAlert as e:
        return e.rule == "ACK-6", f"[{e.rule}]"


def t_ACK6_long_window_refused():
    b, g, pr = held()
    a = ack(b, pr.proposal_hash)
    a["obj"]["expires_at"] = a["obj"]["issued_at"] + 99999
    resign(b, a)
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        return False, "over-long window accepted"
    except CriticalAlert as e:
        return e.rule == "ACK-6", f"[{e.rule}]"


def t_ACK1_open_schema_refused():
    """Z4's lesson: an extra field is an encoding split."""
    b, g, pr = held()
    a = ack(b, pr.proposal_hash)
    a["obj"]["note"] = "looks harmless"
    resign(b, a)
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        return False, "open schema accepted"
    except CriticalAlert as e:
        return e.rule == "ACK-1", f"[{e.rule}]"


def t_ACK1_decision_confusion_refused():
    """A REPUDIATE object must not satisfy a CONFIRM call."""
    b, g, pr = held()
    a = ack(b, pr.proposal_hash, decision="REPUDIATE")
    try:
        g.confirm(pr.proposal_hash, a, now=NOW + 1)
        return False, "repudiation accepted as confirmation"
    except FailClosed as e:
        return e.rule == "ACK-1", f"[{e.rule}]"


def t_timeout_still_fails_closed():
    """DR-9 unchanged: silence is still not consent."""
    b, g, pr = held()
    try:
        g.release(pr.proposal_hash, NOW + 61)
        return False, "irreversible released on silence"
    except CriticalAlert as e:
        return e.rule == "DR-9", f"[{e.rule}]"


TESTS = [
    ("honest signed ack releases", t_honest_signed_ack_releases),
    ("honest repudiation blocks", t_honest_repudiation_blocks),
    ("T-31 bare string refused [ACK-1]", t_T31_bare_string_refused),
    ("T-31 unregistered identity refused [ACK-2]", t_T31_unregistered_identity_refused),
    ("T-31 forged signature refused [ACK-2]", t_T31_forged_signature_refused),
    ("T-31 identity swap refused [ACK-4]", t_T31_identity_swap_refused),
    ("T-31 operator cannot self-confirm [DR-9]", t_T31_operator_cannot_self_confirm),
    ("cross-action ack refused [ACK-3]", t_ACK3_wrong_proposal_refused),
    ("ack replay refused [ACK-5]", t_ACK5_replay_refused),
    ("expired ack refused [ACK-6]", t_ACK6_expired_refused),
    ("over-long window refused [ACK-6]", t_ACK6_long_window_refused),
    ("open schema refused [ACK-1]", t_ACK1_open_schema_refused),
    ("decision confusion refused [ACK-1]", t_ACK1_decision_confusion_refused),
    ("silence still fails closed [DR-9]", t_timeout_still_fails_closed),
]

MUTANTS = [
    ("ACK-2 signature verification",
     ('        if not sig_ok(key, aid, ack.get("sig"), obj["alg"]):\n'
      '            raise CriticalAlert("ACK-2", "acknowledgement signature invalid")',
      "        pass"),
     "t_T31_forged_signature_refused"),
    ("ACK-3 binding to this proposal",
     ('        if obj["proposal_hash"] != proposal_hash:\n'
      '            raise CriticalAlert("ACK-3", "acknowledgement bound to a DIFFERENT "\n'
      '                                         "proposal")',
      "        pass"),
     "t_ACK3_wrong_proposal_refused"),
    # NOTE (isolation): the identity-swap attack is caught UPSTREAM by ACK-2,
    # because rewriting `acknowledger` invalidates the signature — the same
    # masking Suite 2 documents for X1/B-1a. ACK-4 is isolated instead by the
    # operator self-confirmation, where the signature is VALID and the returned
    # identity is the only thing that decides the DR-9 outcome.
    ("ACK-4 identity from signed bytes",
     ('        return obj["acknowledger"]', '        return "op_1121"'),
     "t_T31_operator_cannot_self_confirm"),
    ("ACK-5 single-use ledger consumption",
     ("        self.ledger.claim_attestation(aid)", "        pass"),
     "t_ACK5_replay_refused"),
    ("ACK-1 closed schema",
     ('        if set(obj.keys()) != set(ACK1_FIELDS):', "        if False:"),
     "t_ACK1_open_schema_refused"),
    ("ACK-6 freshness window",
     ('        if not (obj["issued_at"] <= now <= obj["expires_at"]):\n'
      '            raise CriticalAlert("ACK-6", "acknowledgement outside validity window")',
      "        pass"),
     "t_ACK6_expired_refused"),
]


def run_tests():
    print("=" * 74)
    print("SUITE 9 — ACK-1..ACK-6 : THE T-31 FIX")
    print("=" * 74)
    fails = 0
    for name, fn in TESTS:
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"unexpected {type(e).__name__}: {e}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<45} {detail}")
        fails += not ok
    print("=" * 74)
    print(f"RESULT: {len(TESTS)-fails}/{len(TESTS)}"
          f"{' — T-31 CLOSED' if not fails else ' — REVIEW REQUIRED'}")
    return 1 if fails else 0


def run_mutants():
    src = open("acp_ack.py").read()
    print("=" * 74)
    print("ACK MUTATION — each new check must be load-bearing")
    print("=" * 74)
    fails = 0
    for label, (old, new), test in MUTANTS:
        if src.count(old) != 1:
            print(f"  ERROR  {label:<34} anchor not found ({src.count(old)})")
            fails += 1
            continue
        with tempfile.TemporaryDirectory() as td:
            open(os.path.join(td, "acp_ack.py"), "w").write(src.replace(old, new))
            for f in ("acp_executor.py", "conformance.py", "ack_suite.py"):
                shutil.copy(f, td)
            r = subprocess.run(
                [sys.executable, "-c",
                 f"import ack_suite as A; a,_=A.{test}(); "
                 f"h,_=A.t_honest_signed_ack_releases(); print(int(a),int(h))"],
                capture_output=True, text=True, cwd=td, timeout=60)
            out = (r.stdout.strip().split() + ["?", "?"])[:2]
            blocked, honest = out[0] == "1", out[1] == "1"
            if not blocked and honest:
                print(f"  KILL   {label:<34} attack succeeds without it "
                      f"(honest path still works)")
            elif not blocked:
                print(f"  WEAK   {label:<34} honest path broke — not clean")
                fails += 1
            else:
                print(f"  SURVIVE {label:<33} attack STILL blocked — redundant "
                      f"or vacuous")
                fails += 1
    print("=" * 74)
    n = len(MUTANTS)
    print(f"RESULT: {n-fails}/{n} killed"
          f"{' — every ACK check is load-bearing' if not fails else ' — REVIEW REQUIRED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run_mutants() if "--mutate" in sys.argv else run_tests())
