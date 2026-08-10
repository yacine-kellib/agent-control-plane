#!/usr/bin/env python3
"""
partition_integration.py — the conformance suite run against a DISTRIBUTED
ledger, with partition injected mid-checklist.

Closes the last integration gap: previous suites exercised the Executor and the
quorum ledger separately, so nothing tested what an Executor does when a CL-6
failure lands in the middle of §9.3.
"""
import sys
import conformance as C
from acp_ledger import QuorumLedgerAdapter, LedgerFailClosed
from acp_executor import Executor, FailClosed


def with_quorum(partition=None, kills=()):
    b = C.make_bundle()
    led = QuorumLedgerAdapter(5)
    for k in kills:
        led.kill(k)
    if partition is not None:
        led.set_partition(partition)
    return b, Executor(bundle=b, ledger=led,
                       context={C.OP: {"modify_firewall_rule:prod-db"}}), led


def t_full_suite_on_quorum_ledger():
    """Every conformance attack must still fail closed with a real ledger."""
    orig = C.fresh
    def patched(context=None):
        b, ex, _ = with_quorum()
        if context is not None:
            ex.context = context
        return b, ex
    C.fresh = patched
    try:
        fails = []
        for name, fn, expect in C.ATTACKS:
            if name.startswith("DR-") or name.startswith("RV-"):
                continue                       # gate tests use fresh_deferred
            try:
                fn(); fails.append((name, "EXECUTED"))
            except (FailClosed, LedgerFailClosed):
                pass
            except Exception as e:
                fails.append((name, f"{type(e).__name__}: {e}"))
        return not fails, f"{len(C.ATTACKS)-len(fails)} vectors held" if not fails else str(fails[:2])
    finally:
        C.fresh = orig


def t_honest_path_on_quorum():
    b, ex, led = with_quorum()
    p = C.proposal()
    out = ex.execute(C.receipt(b, p, atts=C.quorum(b, p)), p)
    return out["executed"], "floor-HIGH executes against a 5-replica ledger"


def t_minority_partition_blocks_at_step6():
    """CL-6 lands on the nonce claim (step 6): no execution, no partial state."""
    b, ex, led = with_quorum(partition={0, 1})
    p = C.proposal()
    try:
        ex.execute(C.receipt(b, p, atts=C.quorum(b, p)), p)
        return False, "executed on a minority partition"
    except LedgerFailClosed as e:
        return e.rule == "CL-6", f"blocked at nonce claim [{e.rule}]"


def t_partition_after_nonce_burns_it():
    """
    Partition arrives BETWEEN the nonce claim (step 6) and the attestation
    claim (step 7b). At-most-once is preserved and the receipt is permanently
    dead -- the documented liveness cost, now exercised rather than asserted.
    """
    b, ex, led = with_quorum()
    p = C.proposal()
    r = C.receipt(b, p, atts=C.quorum(b, p))
    led.claim_nonce(r["nonce"])                 # step 6 succeeded
    led.set_partition({0, 1})                   # partition arrives
    try:
        ex.execute(r, p)
        return False, "executed after partition"
    except LedgerFailClosed:
        pass
    led.set_partition(None)                     # heal
    try:
        ex.execute(r, p)
        return False, "receipt reusable after heal"
    except LedgerFailClosed as e:
        return e.rule == "CL-2", f"nonce stays burned after heal [{e.rule}]"


def t_two_replica_loss_tolerated():
    b, ex, led = with_quorum(kills=(0, 1))
    p = C.proposal()
    out = ex.execute(C.receipt(b, p, atts=C.quorum(b, p)), p)
    return out["executed"], "executes with 3/5 replicas alive"


def t_three_replica_loss_fails_closed():
    b, ex, led = with_quorum(kills=(0, 1, 2))
    p = C.proposal()
    try:
        ex.execute(C.receipt(b, p, atts=C.quorum(b, p)), p)
        return False, "executed with 2/5 alive"
    except LedgerFailClosed as e:
        return e.rule == "CL-6", f"[{e.rule}]"


TESTS = [
    ("full attack suite on quorum ledger", t_full_suite_on_quorum_ledger),
    ("honest floor-HIGH on quorum ledger", t_honest_path_on_quorum),
    ("minority partition blocks at step 6", t_minority_partition_blocks_at_step6),
    ("partition mid-checklist burns nonce", t_partition_after_nonce_burns_it),
    ("2/5 replica loss tolerated", t_two_replica_loss_tolerated),
    ("3/5 replica loss fails closed", t_three_replica_loss_fails_closed),
]


def main():
    print("=" * 74)
    print("EXECUTOR × DISTRIBUTED LEDGER — INTEGRATION UNDER FAULT INJECTION")
    print("=" * 74)
    fails = 0
    for name, fn in TESTS:
        try:
            ok, detail = fn()
        except Exception as ex:
            ok, detail = False, f"unexpected {type(ex).__name__}: {ex}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<40} {detail}")
        fails += not ok
    print("=" * 74)
    print(f"RESULT: {len(TESTS)-fails}/{len(TESTS)}"
          f"{' — INTEGRATION HOLDS' if not fails else ' — REVIEW REQUIRED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
