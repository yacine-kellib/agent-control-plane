#!/usr/bin/env python3
"""
conformance.py — ACP-SPEC-001 v1.3.5 conformance suite against the reference
Executor.

THE TEST CRITERION. The system works iff:
  (A) the honest floor-HIGH path EXECUTES, and
  (B) every historical finding, replayed as a live attack, FAILS CLOSED with
      the expected rule firing.

(B) without (A) is trivially satisfiable by an Executor that refuses
everything, which is why the positive path is a first-class test. Each attack
below is the actual defect from Annex C, mounted as a single compromised
component against a running implementation.
"""
import copy, sys, time
from dataclasses import replace
# Run-from-anywhere: put the sibling reference/src on the path so
# `python3 reference/suites/<x>.py` works without the caller exporting
# PYTHONPATH. The isdir guard keeps this inert inside the mutation suites'
# temp dirs, where no ../src exists and the mutant module must be found flat in
# the cwd — inserting a real path there would let the true module shadow it.
import os as _os
_SRC = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), _os.pardir, "src")
if _os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)
from acp_executor import (Bundle, Executor, Ledger, FailClosed, CriticalAlert,
                            canon, h, sign, evaluate, DeferredReleaseGate,
                            PendingRelease, RenderedSummary, render_from_canonical)
from acp_crypto import HybridKey

OP, A1, A2 = "op_8842", "op_1121", "op_3307"

# Real asymmetric keys, built ONCE at import. ML-DSA-65 keygen is ~38 ms and a
# signature ~210 ms in pure Python; this module is the fixture library for seven
# suites and the subject of 20 mutants, so per-test keygen would dominate the
# gate. The SIGNING halves stay here, in the fixtures — the fixtures play the
# KMS and the attesters. Only the PUBLIC halves go into the Bundle the Executor
# reads, which is the property the swap exists to establish.
SIGNERS = {A1: HybridKey(b"k1"), A2: HybridKey(b"k2"), OP: HybridKey(b"kop")}
KEYS = {who: k.public() for who, k in SIGNERS.items()}
RECEIPT_SIGNER = HybridKey(b"kms")
RECEIPT_KEY = RECEIPT_SIGNER.public()

# An attacker holding a real, well-formed keypair that the bundle does not
# register. Under HMAC the equivalent was the byte string b"wrong-key", which
# tested only that a wrong secret produces a wrong MAC. This is the stronger
# statement the asymmetric swap makes available: the forgery is cryptographically
# perfect and is refused for the only reason that should matter — the key is not
# in the signed bundle.
FORGER = HybridKey(b"forger")


def make_bundle():
    return Bundle(
        epoch=47,
        quorum_k=2,                       # AT-3: signed, never read from an attestation
        floors={"prod-db": "T3", "sandbox": "T0"},
        risk_functions=[{
            "applies_to": "modify_firewall_rule", "base": "MEDIUM",
            "raise_to": [
                {"if": "resource.effective_tier == T3", "then": "HIGH"},
                {"if": "action == 'allow' && ( port in [ 22 , 3389 ] "
                       "|| resource.effective_tier >= T2 )", "then": "HIGH"}]},
            {"applies_to": "read_metric", "base": "LOW", "raise_to": []},
            {"applies_to": "rotate_cache_key", "base": "MEDIUM", "raise_to": [
                {"if": "resource.effective_tier == T3", "then": "HIGH"}]}],
        adapters={"fw.v1": "F-HIGH", "metric.v1": "F-HIGH", "cache.v1": "F-HIGH"},
        reversibility={"modify_firewall_rule": "IRREVERSIBLE",
                       "read_metric": "REVERSIBLE",
                       "rotate_cache_key": "REVERSIBLE"},
        # DR-13. A COMPLIANT deployment: the one irreversible class names who
        # is told when it runs below floor-HIGH. Omitting it is the attack
        # a_DR13_no_notice_recipients, which pops this exactly as
        # a_RV1_unclassified_action_defaults_irreversible pops reversibility.
        notice_targets={"modify_firewall_rule": ["secops_oncall"]},
        attester_keys=KEYS, receipt_key=RECEIPT_KEY,
        schemas={"fw.v1": "sha256:aaa", "metric.v1": "sha256:bbb",
                 "cache.v1": "sha256:ccc"})


def proposal(task="modify_firewall_rule", target="prod-db", schema="fw.v1"):
    return {"task_type": task, "schema_id": schema, "tenant_id": "t1",
            "targets": [target], "params": {"action": "allow", "port": 22},
            "cidrs": {"source_cidr": 24}}


def att_obj(b, phash, expires, operator=OP, alg="hybrid-ed25519-mldsa65"):
    return {"alg": alg, "proposal_hash": phash, "policy_bundle_hash": b.hash(),
            "bundle_epoch": b.epoch, "context_snapshot_hash": "sha256:ctx",
            "floor_only_risk": "HIGH", "required_roles": ["net_approver"],
            "required_count": 2, "operator": operator,
            "att_nonce": f"n-{expires}-{operator}", "expires_at": expires}


def entry(obj, attester, kind="approval"):
    return {"obj": obj, "kind": kind, "attester": attester,
            "sig": sign(SIGNERS[attester], h(obj), obj["alg"])}


def receipt(b, p, *, now=1000.0, atts=None, nonce="nonce-1", **over):
    r = {"alg": "hybrid-ed25519-mldsa65", "decision": "ALLOW", "proposal_hash": h(p), "policy_bundle_hash": b.hash(),
         "bundle_epoch": b.epoch, "issued_at": now, "expires_at": now + 60,
         "nonce": nonce, "tenant_id": "t1", "operator": OP,
         "attestations": atts or [], "_now": now}
    r.update(over)
    r["sig"] = sign(RECEIPT_SIGNER, canon({k: v for k, v in r.items()
                                           if k != "sig"}).decode(), r["alg"])
    return r


def fresh(context=None):
    b = make_bundle()
    ex = Executor(bundle=b, ledger=Ledger(),
                  context=context if context is not None
                  else {OP: {"modify_firewall_rule:prod-db"}})
    return b, ex


def quorum(b, p, now=1000.0, operator=OP):
    o = att_obj(b, h(p), now + 600, operator)
    return [entry(o, A1), entry(dict(o, att_nonce="n2"), A2),
            entry(dict(o, att_nonce="n3"), OP, "confirmation")]


# ============================================================== POSITIVE
def t_honest_high():
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    out = ex.execute(r, p)
    assert out["executed"] and out["risk"] == "HIGH", out
    return "floor-HIGH executes with a valid bound quorum"


def t_honest_low():
    b, ex = fresh()
    p = proposal("read_metric", "sandbox", "metric.v1")
    out = ex.execute(receipt(b, p), p)
    assert out["risk"] == "LOW"
    return "floor-LOW executes with no attestation required"


def t_honest_redrive():
    b, ex = fresh()
    p = proposal()
    r1 = receipt(b, p, atts=quorum(b, p))
    k1 = ex.execute(r1, p)["idempotency_key"]
    o = att_obj(b, h(p), 1600.0)
    a2 = [entry(dict(o, att_nonce="r1"), A1), entry(dict(o, att_nonce="r2"), A2),
          entry(dict(o, att_nonce="r3"), OP, "confirmation")]
    r2 = receipt(b, p, atts=a2, nonce="nonce-2")
    k2 = ex.execute(r2, p, redrive=True)["idempotency_key"]
    assert k1 == k2, "DS-6: re-drive must present the SAME idempotency key"
    return "DS-6 re-drive is dedupped (stable key, fresh authorization)"


# ============================================================== ATTACKS
def a_Y1_misbinding():
    """Compromised KMS attaches P1's genuine quorum to a receipt for P2."""
    b, ex = fresh({OP: {"modify_firewall_rule:prod-db"}})
    p1, p2 = proposal(), proposal()
    p2["params"]["port"] = 3389                       # different action
    atts = quorum(b, p1)                              # bound to P1, genuine sigs
    r = receipt(b, p2, atts=atts)                     # receipt for P2
    ex.execute(r, p2)


def a_Y1b_garbage_id():
    b, ex = fresh()
    p = proposal()
    atts = quorum(b, p)
    atts[0] = dict(atts[0], attestation_id="sha256:deadbeef")
    ex.execute(receipt(b, p, atts=atts), p)


def a_Y2_long_window():
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p), expires_at=1000.0 + 86400)
    ex.execute(r, p)


def a_Y4_operator_swap():
    """KMS misstates operator so the real operator's own key counts as approver."""
    b, ex = fresh({A1: {"modify_firewall_rule:prod-db"}})
    p = proposal()
    o = att_obj(b, h(p), 1600.0, operator=A1)         # object says operator=A1
    atts = [entry(o, A1), entry(dict(o, att_nonce="x2"), A2),
            entry(dict(o, att_nonce="x3"), OP, "confirmation")]
    ex.execute(receipt(b, p, atts=atts, operator=OP), p)


def a_Z3_origin_substitution():
    """KMS names another consumed nonce as the re-drive origin."""
    b, ex = fresh()
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p)
    o = att_obj(b, h(p), 1600.0)
    a2 = [entry(dict(o, att_nonce="q1"), A1), entry(dict(o, att_nonce="q2"), A2),
          entry(dict(o, att_nonce="q3"), OP, "confirmation")]
    r = receipt(b, p, atts=a2, nonce="nonce-9", origin_nonce="nonce-OTHER")
    ex.execute(r, p, redrive=True)


def a_Z4_optional_field():
    """One attestation, two encodings, two ledger slots."""
    b, ex = fresh()
    p = proposal()
    atts = quorum(b, p)
    obj = dict(atts[0]["obj"]); obj["extension"] = None
    atts[0] = {"obj": obj, "kind": "approval", "attester": A1,
               "sig": sign(SIGNERS[A1], h(obj))}
    ex.execute(receipt(b, p, atts=atts), p)


def a_X1_risk_downgrade():
    """KMS claims floor-LOW for a floor-T3 action and ships no attestations."""
    b, ex = fresh()
    p = proposal()
    ex.execute(receipt(b, p, atts=[], risk_level_floor_only="LOW"), p)


def a_no_attestation():
    b, ex = fresh()
    p = proposal()
    ex.execute(receipt(b, p, atts=[]), p)


def a_epoch_rollback():
    """KMS serves a genuine SUPERSEDED bundle. Step 4 cannot catch this -- the
    receipt is internally consistent with the old bundle -- so the ledger's
    durable high-water mark (RAD-3) is the only thing standing in the way."""
    b, ex = fresh()
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p)
    ex.bundle.epoch = 46
    p2 = proposal()
    ex.execute(receipt(ex.bundle, p2, atts=quorum(ex.bundle, p2), nonce="n2"), p2)


def a_nonce_replay():
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    ex.execute(r, p)
    ex.execute(r, p)


def a_T14_attestation_replay():
    b, ex = fresh()
    p = proposal()
    atts = quorum(b, p)
    ex.execute(receipt(b, p, atts=atts), p)
    ex.execute(receipt(b, p, atts=atts, nonce="nonce-2"), p)


def a_AT2_self_approval():
    b, ex = fresh()
    p = proposal()
    o = att_obj(b, h(p), 1600.0)
    atts = [entry(o, A1), entry(dict(o, att_nonce="s2"), OP),
            entry(dict(o, att_nonce="s3"), OP, "confirmation")]
    ex.execute(receipt(b, p, atts=atts), p)


def a_AT3_partial_quorum():
    """
    ONE GENUINE APPROVAL WHERE THE BUNDLE REQUIRES TWO.

    Nothing is misstated: the object says `required_count: 2`, which is what
    the bundle says, so the AT-9 consent check passes cleanly. The receipt
    simply carries one approval instead of two.

    This is the attack that isolates the AT-3 comparison. Every other quorum
    attack in this file is caught by an earlier check — a misstated count by
    AT-9, a shared key by PB-DISTINCT, a self-approval by AT-2 — so without
    this one the comparison itself is never the thing that refuses, and its
    mutant is masked.
    """
    b, ex = fresh()
    p = proposal()
    o = att_obj(b, h(p), 1600.0, OP)
    atts = [entry(o, A1),
            entry(dict(o, att_nonce="p2"), OP, "confirmation")]
    ex.execute(receipt(b, p, atts=atts), p)


def a_ACP28_single_key_asserts_its_own_quorum():
    """
    ONE COMPROMISED ATTESTER KEY, AND THE QUORUM IS SATISFIED.

    Through v1.3.14 the Executor took the threshold from the object it was
    verifying — `entries[0]["obj"]["required_count"]`. The holder of a single
    registered attester key therefore signs one well-formed, correctly-bound,
    unexpired object that says the quorum required is one, and a floor-HIGH
    action executes on it. Nothing is forged: the signature is genuine, the
    binding to the proposal is genuine, the policy hash and epoch are genuine.
    The Executor asked the party under verification how many signatures to
    demand and believed the answer.

    That is INV-1-HIGH broken by a single component compromise, which is the
    one thing the invariant claims cannot happen.

    Kept as a regression test of the original exploit, verbatim. It now fails
    closed on **AT-9** rather than AT-3, and the reason is worth reading: the
    attacker had to misstate `required_count` to move the threshold, and
    misstating it is exactly what the consent check refuses. The refusal
    arrives one step earlier than the fix that was written for it. Both checks
    are still needed — see `a_AT3_partial_quorum` for what AT-9 cannot see.
    """
    b, ex = fresh()
    p = proposal()
    o = att_obj(b, h(p), 1600.0, OP)
    ex.execute(receipt(b, p, atts=[entry(dict(o, required_count=1), A1)]), p)


def a_AT9_attesters_signed_for_a_larger_quorum():
    """
    THE APPROVERS CONSENTED TO SOMETHING THAT DID NOT HAPPEN.

    Not an attack on INV-1-HIGH — the invariant holds throughout. Both objects
    say `required_count: 3`, so both attesters were shown, and signed for, an
    action three people would review. Only two approvals are presented, and the
    bundle's `quorum_k` is 2, so the recomputed threshold is met and the action
    would execute.

    It executes on a basis nobody agreed to. The third reviewer the approvers
    were relying on never existed, and neither approver can tell from their own
    signature that the policy applied was not the policy displayed.

    AT-9 splits this from the threshold rule deliberately: the threshold check
    catches a quorum being LOWERED and is an INV-1-HIGH control; this catches
    the stated basis diverging from the applied one and is an AT-3 control.
    Delete either and the other does not cover it.
    """
    b, ex = fresh()
    p = proposal()
    o = att_obj(b, h(p), 1600.0, OP)
    o = dict(o, required_count=3)          # what the humans were shown
    atts = [entry(o, A1), entry(dict(o, att_nonce="q2"), A2),
            entry(dict(o, att_nonce="q3"), OP, "confirmation")]
    ex.execute(receipt(b, p, atts=atts), p)


def a_PBDISTINCT_one_key_two_identities():
    """
    A QUORUM OF TWO NAMES AND ONE KEY HOLDER.

    AT-2 and AT-3 count distinct `attester` strings; the registry maps a string
    to a key. Register two identities against ONE public key and the holder of
    that single private key signs two objects with different nonces, labels one
    `op_1121` and the other `op_3307`, and `len(set(approvals))` reads two. Every
    signature is genuine. Every binding is genuine. One compromised key executes
    a floor-HIGH action, which is INV-1-HIGH broken by a single compromise —
    the same break as reading the threshold out of the attestation, arrived at
    through the registry instead.

    The bundle is now refused at construction, so this attack never reaches an
    Executor at all.
    """
    b = replace(make_bundle(),
                attester_keys={A1: KEYS[A1], A2: KEYS[A1], OP: KEYS[OP]})
    # Only reachable with the check deleted. Everything below is the attacker
    # holding exactly one private key, SIGNERS[A1].
    ex = Executor(bundle=b, ledger=Ledger(),
                  context={OP: {"modify_firewall_rule:prod-db"}})
    p = proposal()
    o = att_obj(b, h(p), 1600.0, OP)

    def as_(obj, who):
        return {"obj": obj, "kind": "approval", "attester": who,
                "sig": sign(SIGNERS[A1], h(obj), obj["alg"])}

    atts = [as_(o, A1), as_(dict(o, att_nonce="dup2"), A2),
            entry(dict(o, att_nonce="dup3"), OP, "confirmation")]
    ex.execute(receipt(b, p, atts=atts), p)


def a_capability_revoked():
    b, ex = fresh(context={OP: set()})                # revoked after issuance
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p)


def a_tampered_proposal():
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    p2 = copy.deepcopy(p); p2["params"]["port"] = 443
    ex.execute(r, p2)


def a_tampered_proposal_low():
    """Same tamper, floor-LOW action: no quorum exists to mask a missing rehash."""
    b, ex = fresh()
    p = proposal("read_metric", "sandbox", "metric.v1")
    r = receipt(b, p)
    p2 = copy.deepcopy(p); p2["targets"] = ["prod-db"]
    ex.execute(r, p2)


# ------------------------------------------------ deferred release fixtures
class HonestPresentation:
    """Renders the approval screen from canonical bytes. Path: 'approval-ui'."""
    def render(self, p):
        return render_from_canonical(p, "approval-ui")


class LyingPresentation:
    """COMPROMISED: shows a harmless action while the real bytes say prod-db."""
    def render(self, p):
        return RenderedSummary("modify_firewall_rule on sandbox [action=allow]",
                               "approval-ui", from_canonical=False)


class IndependentNotifier:
    """DR-2 compliant: own code path, renders from canonical bytes."""
    def __init__(self, reachable=None, deliver_to=None):
        self._reachable, self._deliver_to = reachable, deliver_to
    def render(self, p):
        return render_from_canonical(p, "notify-mobile")
    def recipients(self, pr):
        return self._reachable if self._reachable is not None else [OP, A1, A2]
    def deliver(self, rcpts, note):
        return self._deliver_to if self._deliver_to is not None else list(rcpts)


class ProxyNotifier(IndependentNotifier):
    """DR-2 VIOLATION: sources its text from the approval chain. One path
    wearing two hats -- RES-8, fifth recurrence, caught structurally."""
    def render(self, p):
        return RenderedSummary("whatever the approval UI said", "approval-ui",
                               from_canonical=False)


class SharedLibNotifier(IndependentNotifier):
    """The REALISTIC DR-2 trap: renders honestly from canonical bytes, but via
    the SAME shared formatting library as the approval UI. Looks independent,
    is not: one compromise of that library lies to both channels at once."""
    def render(self, p):
        return render_from_canonical(p, "approval-ui")


def fresh_deferred(presentation=None, notifier=None, hold=60, context=None,
                   sampler=None, sample_rate=0.1):
    b = make_bundle()
    gate = DeferredReleaseGate(hold_seconds=hold,
                               notifier=notifier or IndependentNotifier(),
                               sample_rate=sample_rate,
                               sampler=sampler or (lambda: 0.99))
    ex = Executor(bundle=b, ledger=Ledger(), gate=gate,
                  context=context if context is not None
                  else {OP: {"modify_firewall_rule:prod-db",
                             "rotate_cache_key:prod-db"}})
    return b, ex, gate, (presentation or HonestPresentation())


# ============================================== POSITIVE (deferred release)
def t_deferred_holds_then_releases():
    """REVERSIBLE floor-HIGH, unsampled: silence releases, marked unverified."""
    b, ex, gate, pres = fresh_deferred()
    p = proposal("rotate_cache_key", "prod-db", "cache.v1")
    # DR-6: the receipt must outlive the hold. A 60 s hold inside a 60 s
    # receipt window expires mid-hold -- issue at the L-14 maximum instead.
    out = ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
                     approval_summary=pres.render(p))
    assert out["executed"] is False and out["pending_release"], out
    res = gate.release(h(p), now=1061.0)
    assert res["executed"] and res["deferred"]
    assert res["human_verified"] is False and gate.unverified_releases == 1
    return "reversible floor-HIGH released on silence, counted as unverified"


def t_deferred_low_risk_unaffected():
    b, ex, gate, pres = fresh_deferred()
    p = proposal("read_metric", "sandbox", "metric.v1")
    out = ex.execute(receipt(b, p), p, approval_summary=pres.render(p))
    assert out["executed"] is True, "low risk must not be deferred"
    return "floor-LOW executes immediately, no hold, no notification"


def t_lying_screen_is_caught_by_notification():
    """THE A-8 SCENARIO. Presentation service compromised; approver signs a
    prod-db action believing it is sandbox. The independent channel renders the
    canonical bytes, the approver sees prod-db, repudiates, nothing executes."""
    b, ex, gate, pres = fresh_deferred(presentation=LyingPresentation())
    p = proposal()
    approver_saw = pres.render(p)
    out = ex.execute(receipt(b, p, atts=quorum(b, p)), p,
                     approval_summary=approver_saw)
    assert out["pending_release"]
    truth = gate.notifier.render(p)
    assert "prod-db" in truth.text and "sandbox" in approver_saw.text
    gate.repudiate(h(p), OP)
    try:
        gate.release(h(p), now=1061.0)
        raise AssertionError("repudiated action executed")
    except CriticalAlert as e:
        assert e.rule == "DR-4"
    return "compromised screen caught: approver repudiates, action blocked"


# ============================================== ATTACKS (deferred release)
def a_DR_release_before_window():
    """REVERSIBLE + confirmed, so only the hold-window check stands between the
    caller and execution -- DR-9 cannot mask DR-1."""
    b, ex, gate, pres = fresh_deferred()
    p = proposal("rotate_cache_key", "prod-db", "cache.v1")
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
               approval_summary=pres.render(p))
    gate.confirm(h(p), A1)
    gate.release(h(p), now=1005.0)


def a_DR_notification_from_approval_chain():
    """The trap: a notifier that proxies the approval chain is not a second
    channel. Must be refused structurally, not trusted."""
    b, ex, gate, pres = fresh_deferred(notifier=ProxyNotifier())
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p, approval_summary=pres.render(p))


def a_DR_shared_render_library():
    """Isolates the path-independence check from the from-canonical check."""
    b, ex, gate, pres = fresh_deferred(notifier=SharedLibNotifier())
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p, approval_summary=pres.render(p))


def a_DR_notification_undeliverable():
    b, ex, gate, pres = fresh_deferred(
        notifier=IndependentNotifier(reachable=[OP, A1], deliver_to=[OP]))
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p, approval_summary=pres.render(p))


def a_DR_no_recipients():
    b, ex, gate, pres = fresh_deferred(notifier=IndependentNotifier(reachable=[]))
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p, approval_summary=pres.render(p))


def a_DR_repudiation_by_outsider():
    b, ex, gate, pres = fresh_deferred()
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p, approval_summary=pres.render(p))
    gate.repudiate(h(p), "mallory")


def a_DR_hold_exceeds_l14_ceiling():
    """A hold >= the L-14 120 s ceiling can NEVER be satisfied: no legal receipt
    outlives it. Configuration is unsatisfiable and must fail closed, not
    silently never release."""
    b, ex, gate, pres = fresh_deferred(hold=130)
    p = proposal("rotate_cache_key", "prod-db", "cache.v1")
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
               approval_summary=pres.render(p))
    gate.confirm(h(p), A1)
    gate.release(h(p), now=1131.0)


def a_DR_hold_outlives_receipt():
    """DR-6: a hold longer than receipt validity releases an expired
    authorization. Uses a REVERSIBLE, confirmed action so that DR-9 cannot mask
    the DR-6 check."""
    b, ex, gate, pres = fresh_deferred(hold=200)
    p = proposal("rotate_cache_key", "prod-db", "cache.v1")
    ex.execute(receipt(b, p, atts=quorum(b, p)), p, approval_summary=pres.render(p))
    gate.confirm(h(p), A1)
    gate.release(h(p), now=1201.0)


def t_irreversible_requires_confirmation():
    """DR-9: silence is NOT consent for irreversible actions."""
    b, ex, gate, pres = fresh_deferred()
    p = proposal()                                     # IRREVERSIBLE in bundle
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
               approval_summary=pres.render(p))
    gate.confirm(h(p), A1)                             # an attester, not the operator
    res = gate.release(h(p), now=1061.0)
    assert res["executed"] and res["human_verified"] is True
    return "irreversible action executes only after positive acknowledgement"


def t_sampling_forces_confirmation():
    """DR-10: a sampled reversible action inherits the confirmation duty, so an
    approver cannot learn that ignoring notifications is always safe."""
    b, ex, gate, pres = fresh_deferred(sampler=lambda: 0.0, sample_rate=1.0)
    p = proposal("rotate_cache_key", "prod-db", "cache.v1")
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
               approval_summary=pres.render(p))
    gate.confirm(h(p), A1)
    res = gate.release(h(p), now=1061.0)
    assert res["sampled"] and res["human_verified"]
    return "sampled reversible action requires confirmation like an irreversible one"


def a_DR9_irreversible_silent_release():
    b, ex, gate, pres = fresh_deferred()
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
               approval_summary=pres.render(p))
    gate.release(h(p), now=1061.0)


def a_DR9_operator_confirms_own_action():
    b, ex, gate, pres = fresh_deferred()
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
               approval_summary=pres.render(p))
    gate.confirm(h(p), OP)


def a_DR10_sampled_silent_release():
    b, ex, gate, pres = fresh_deferred(sampler=lambda: 0.0, sample_rate=1.0)
    p = proposal("rotate_cache_key", "prod-db", "cache.v1")
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
               approval_summary=pres.render(p))
    gate.release(h(p), now=1061.0)


def a_RV3_receipt_claims_reversible():
    """The X1 pattern applied to reversibility: a compromised KMS asserts
    REVERSIBLE to suppress the DR-9 confirmation requirement."""
    b, ex, gate, pres = fresh_deferred()
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0,
                       reversibility="REVERSIBLE"), p,
               approval_summary=pres.render(p))


# ------------------------------- DR-13: below floor-HIGH (found by the harness)
#
# The deferred gate is scoped to floor-HIGH (DR-1), so everything above this
# line tests a path an IRREVERSIBLE action only reaches when its TARGET happens
# to be floored high. Reversibility is a property of the ACTION and risk is
# recomputed from the RESOURCE, so the two are orthogonal and the gap between
# them was empty until v1.3.15. art_harness.py found it on its first run.
def irreversible_below_high():
    """MEDIUM + IRREVERSIBLE: `modify_firewall_rule` on the T0 sandbox with a
    non-`allow` action clears neither raise condition, so it is graded MEDIUM
    while remaining irreversible. This is `send_email` from a T1 inbox, in this
    bundle's vocabulary."""
    return dict(proposal(target="sandbox"),
                params={"action": "deny", "port": 443})


def t_dr13_irreversible_below_high_is_noticed():
    """DR-13: the action executes -- no acknowledgement is required and the fast
    path stays fast -- but it is no longer invisible."""
    b, ex = fresh(context={OP: {"modify_firewall_rule:sandbox"}})
    p = irreversible_below_high()
    assert ex.recompute_floor_risk(p) == "MEDIUM"
    assert ex.recompute_reversibility(p) == "IRREVERSIBLE"
    out = ex.execute(receipt(b, p), p)
    assert out["executed"], out
    notices = ex.ledger.notices()
    assert len(notices) == 1 and notices[0]["proposal_hash"] == h(p), notices
    assert notices[0]["recipients"] == ["secops_oncall"], notices
    return "irreversible action below floor-HIGH executes, and is noticed"


def a_DR13_no_notice_recipients():
    """The gap as released: an IRREVERSIBLE action graded below HIGH with no
    notice channel named in the signed bundle. Through v1.3.14 this executed
    silently. A notice with no addressee is not a detection channel, so it now
    refuses -- the deployment names recipients or floors the class at T2+."""
    b, ex = fresh(context={OP: {"modify_firewall_rule:sandbox"}})
    b.notice_targets.pop("modify_firewall_rule")
    p = irreversible_below_high()
    ex.execute(receipt(b, p), p)


def a_RV1_unclassified_action_defaults_irreversible():
    """RV-1 fail-safe: an action absent from reversibility.json is IRREVERSIBLE,
    so silence cannot release it."""
    b, ex, gate, pres = fresh_deferred()
    b.reversibility.pop("modify_firewall_rule")
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p), expires_at=1120.0), p,
               approval_summary=pres.render(p))
    gate.release(h(p), now=1061.0)


# ===================================== post-quantum / crypto agility (CR-*)
def a_CR4_receipt_suite_downgrade():
    """A compromised KMS re-signs with classical-only to escape the PQ suite."""
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p), alg="ed25519")
    ex.execute(r, p)


def a_CR4_incomparable_floor():
    """
    THE FLOOR IS MET BY AN ALGORITHM IT DOES NOT NAME.

    A deployment sets its signed floor to `slhdsa128s`: hash-based post-quantum,
    chosen precisely because it rests on no lattice assumption. Nothing is
    forged and nothing is downgraded in the usual sense — an ordinary
    `hybrid-ed25519-mldsa65` receipt arrives, and through v1.3.14 it PASSED,
    because CR-4 compared a rank table (`hybrid` 2, `slhdsa128s` 1) rather than
    the primitive sets. The suite that satisfied the floor carries no SLH-DSA at
    all. The deployment asked for one hardness assumption and got another, with
    the floor check reporting success.

    Suites are sets, not points on a line. CR-4 is containment now.
    """
    b = replace(make_bundle(), min_suite="slhdsa128s")
    ex = Executor(bundle=b, ledger=Ledger(),
                  context={OP: {"modify_firewall_rule:prod-db"}})
    p = proposal()
    ex.execute(receipt(b, p, atts=quorum(b, p)), p)


def a_CR4_attestation_suite_downgrade():
    """Attestation objects downgraded to classical-only."""
    b, ex = fresh()
    p = proposal()
    o = att_obj(b, h(p), 1600.0, alg="ed25519")
    atts = [entry(o, A1), entry(dict(o, att_nonce="d2"), A2),
            entry(dict(o, att_nonce="d3"), OP, "confirmation")]
    ex.execute(receipt(b, p, atts=atts), p)


def a_CR3_pq_signature_stripped():
    """THE HYBRID TEST. Suite still declares hybrid; the post-quantum half is
    removed. A verifier composing with OR would accept -- AND must refuse."""
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    r["sig"] = {"classical": r["sig"]["classical"]}
    ex.execute(r, p)


def a_CR3_classical_signature_stripped():
    """Symmetric case: the classical half removed, PQ half genuine."""
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    r["sig"] = {"pq": r["sig"]["pq"]}
    ex.execute(r, p)


def a_CR3_pq_forged_classical_genuine():
    """Models a future break of ONE primitive: the attacker forges the PQ half
    and holds a genuine classical half. Hybrid AND must still refuse."""
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    r["sig"]["pq"] = "0" * 64
    ex.execute(r, p)


def a_CR3_extra_primitive():
    """Isolates the completeness check from the missing-key crash: the suite's
    two primitives are genuine, plus an unexpected third. A verifier that only
    checks 'all declared primitives verify' accepts this; the suite must be an
    EXACT match, because an accepted extra primitive is an undeclared code path
    an attacker chose."""
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    r["sig"]["experimental"] = "0" * 64
    ex.execute(r, p)


def a_CR2_legacy_scalar_signature():
    """A pre-CR receipt carrying a bare string signature must not be accepted
    by leniency -- format confusion is a downgrade in disguise."""
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    r["sig"] = r["sig"]["classical"]
    ex.execute(r, p)


def a_CR1_unknown_suite():
    b, ex = fresh()
    p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    r["alg"] = "rot13"
    ex.execute(r, p)


def a_PBKEY_swapped_attester_registry():
    """
    PB-KEY: a bundle whose only difference is WHICH KEYS IT TRUSTS must be a
    different bundle.

    Scope, stated precisely, because the honest version of this claim is
    narrower than it first looks -- and narrower than an earlier draft of this
    docstring said. EVERY SIGNATURE BELOW IS GENUINE. Nothing forged is accepted
    and this is not a quorum bypass: an Executor verifies attestations against
    its OWN registry, so swapping one Executor's registry does not push a forged
    quorum through another. What the missing coverage broke is IDENTITY, and
    therefore AUDIT. Two bundles authorising DIFFERENT approvers hashed the
    same, so `policy_bundle_hash` did not determine who was allowed to approve:
    every audit record emitted under either bundle is identical in the field
    that is supposed to name the policy in force, and P-3 -- "Decisions are
    replayable bit-for-bit from audit" -- does not hold. Spec §8.2 already put
    `attesters/` inside the signed bundle tree; the reference simply did not
    hash it.

    What the test asserts is exactly that and no more: two bundles differing
    only in their key registry must be different bundles, so a receipt issued
    under one is refused by an Executor holding the other (9.3-4).
    """
    b, ex = fresh()
    p = proposal()
    # Same policy in every respect except the key registry: `A1`'s slot now
    # holds a key the honest bundle never registered.
    tampered = make_bundle()
    tampered.attester_keys = dict(KEYS, **{A1: FORGER.public()})
    r = receipt(tampered, p, atts=quorum(tampered, p))
    ex.execute(r, p)                     # ex trusts `b`, not `tampered`


ATTACKS = [
    ("Y1  attestation misbinding",      a_Y1_misbinding,        "9.3-7b-ii"),
    ("Y1b garbage attestation_id",      a_Y1b_garbage_id,       "Y1b"),
    ("Y2  over-long validity window",   a_Y2_long_window,       "L-14"),
    ("Y4  operator substitution",       a_Y4_operator_swap,     "AT-2"),
    ("Z3  origin substitution",         a_Z3_origin_substitution, "DS-6f"),
    ("Z4  optional-field encoding",     a_Z4_optional_field,    "AT-8b"),
    ("X1  risk downgrade in receipt",   a_X1_risk_downgrade,    "TR-8"),
    ("--  floor-HIGH, no attestation",  a_no_attestation,       "INV-1-HIGH"),
    ("T15 epoch rollback",              a_epoch_rollback,       "RAD-3"),
    ("T13 receipt nonce replay",        a_nonce_replay,         "CL-2"),
    ("T14 attestation replay",          a_T14_attestation_replay, "CL-3"),
    ("AT-2 operator self-approval",     a_AT2_self_approval,    "AT-2"),
    ("AT-3 partial quorum (1 of 2)",    a_AT3_partial_quorum,         "AT-3"),
    ("ACP-28 one key sets its own k",   a_ACP28_single_key_asserts_its_own_quorum, "AT-9"),
    ("AT-9 signed for a larger quorum", a_AT9_attesters_signed_for_a_larger_quorum, "AT-9"),
    ("PB-DISTINCT one key, two names",  a_PBDISTINCT_one_key_two_identities, "PB-DISTINCT"),
    ("T10 capability revoked in window", a_capability_revoked,  "9.3-9"),
    ("B-1a proposal tampered post-sign", a_tampered_proposal,   "9.3-3"),
    ("B-1a tamper, floor-LOW (unmasked)", a_tampered_proposal_low, "9.3-3"),
    ("DR-1 release before hold elapsed", a_DR_release_before_window,   "DR-1"),
    ("DR-2 notifier proxies approval UI", a_DR_notification_from_approval_chain, "DR-2"),
    ("DR-2 shared render library",       a_DR_shared_render_library,   "DR-2"),
    ("DR-8 notification undeliverable",  a_DR_notification_undeliverable, "DR-8"),
    ("DR-8 no reachable recipients",     a_DR_no_recipients,           "DR-8"),
    ("DR-5 repudiation by non-recipient", a_DR_repudiation_by_outsider, "DR-5"),
    ("DR-6 hold outlives receipt",       a_DR_hold_outlives_receipt,   "DR-6"),
    ("DR-6 hold exceeds L-14 ceiling",   a_DR_hold_exceeds_l14_ceiling, "DR-6"),
    ("DR-9 irreversible silent release", a_DR9_irreversible_silent_release, "DR-9"),
    ("DR-9 operator confirms own action", a_DR9_operator_confirms_own_action, "DR-9"),
    ("DR-10 sampled silent release",     a_DR10_sampled_silent_release, "DR-9"),
    ("RV-3 receipt claims REVERSIBLE",   a_RV3_receipt_claims_reversible, "RV-3"),
    ("RV-1 unclassified defaults irrev.", a_RV1_unclassified_action_defaults_irreversible, "DR-9"),
    ("DR-13 irreversible, no notice ch.", a_DR13_no_notice_recipients,  "DR-13"),
    ("CR-4 receipt suite downgrade",     a_CR4_receipt_suite_downgrade, "CR-4"),
    ("CR-4 attestation suite downgrade", a_CR4_attestation_suite_downgrade, "CR-4"),
    ("CR-4 incomparable suite floor",    a_CR4_incomparable_floor,     "CR-4"),
    ("CR-3 PQ signature stripped",       a_CR3_pq_signature_stripped,  "9.3-1"),
    ("CR-3 classical sig stripped",      a_CR3_classical_signature_stripped, "9.3-1"),
    ("CR-3 PQ forged, classical genuine", a_CR3_pq_forged_classical_genuine, "9.3-1"),
    ("CR-3 extra undeclared primitive",  a_CR3_extra_primitive,        "9.3-1"),
    ("CR-2 legacy scalar signature",     a_CR2_legacy_scalar_signature, "9.3-1"),
    ("CR-1 unknown suite",               a_CR1_unknown_suite,          "CR-4"),
    ("PB-KEY swapped attester registry", a_PBKEY_swapped_attester_registry, "9.3-4"),
]

POSITIVE = [("honest floor-HIGH", t_honest_high),
            ("honest floor-LOW", t_honest_low),
            ("DS-6 re-drive dedup", t_honest_redrive),
            ("deferred hold then release", t_deferred_holds_then_releases),
            ("floor-LOW not deferred", t_deferred_low_risk_unaffected),
            ("A-8 lying screen caught", t_lying_screen_is_caught_by_notification),
            ("irreversible needs confirm", t_irreversible_requires_confirmation),
            ("sampling forces confirm", t_sampling_forces_confirmation),
            ("DR-13 below-HIGH is noticed", t_dr13_irreversible_below_high_is_noticed)]


def main():
    print("=" * 74)
    print("ACP-SPEC-001 v1.3.5 — CONFORMANCE SUITE vs REFERENCE EXECUTOR")
    print("=" * 74)
    fails = 0

    print("\n(A) POSITIVE PATH — must EXECUTE\n" + "-" * 74)
    for name, fn in POSITIVE:
        try:
            print(f"  PASS  {name:<34} {fn()}")
        except Exception as ex:
            print(f"  FAIL  {name:<34} unexpectedly blocked: {ex}"); fails += 1

    print("\n(B) ATTACKS — must FAIL CLOSED\n" + "-" * 74)
    for name, fn, expect in ATTACKS:
        try:
            fn()
            print(f"  FAIL  {name:<34} EXECUTED — invariant broken"); fails += 1
        except FailClosed as ex:
            ok = ex.rule == expect
            crit = "critical" if isinstance(ex, CriticalAlert) else "closed  "
            print(f"  {'PASS' if ok else 'WARN'}  {name:<34} {crit} [{ex.rule}]"
                  f"{'' if ok else f' (expected {expect})'}")
            if not ok:
                fails += 1
        except Exception as ex:
            print(f"  FAIL  {name:<34} wrong exception: {type(ex).__name__}: {ex}")
            fails += 1

    print("\n" + "=" * 74)
    total = len(POSITIVE) + len(ATTACKS)
    if fails:
        print(f"RESULT: {total-fails}/{total} — NOT CONFORMANT")
    else:
        print(f"RESULT: {total}/{total} — CONFORMANT")
        print("Honest path executes; every historical finding fails closed.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
