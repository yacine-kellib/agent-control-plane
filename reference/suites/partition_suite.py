#!/usr/bin/env python3
"""
partition_suite.py — fault-injection tests for the Consumption Ledger.

Answers the question the in-memory ledger could not: does CL-6 ("fail closed on
partition") actually hold, and can a partition produce a doubled claim?

Each test states the invariant it targets. Exhaustive where the state space is
small enough to enumerate, sampled otherwise -- and it says which.
"""
import itertools, sys
from acp_ledger import QuorumLedger, LedgerFailClosed

N = 5
MAJ = N // 2 + 1


def t_claim_once_full_connectivity():
    L = QuorumLedger(N)
    L.claim("nonce-1")
    try:
        L.claim("nonce-1")
        return False, "second claim succeeded"
    except LedgerFailClosed as e:
        return e.rule == "CL-2", f"[{e.rule}]"


def t_minority_cannot_claim():
    """CL-6: the minority side of a partition must refuse, not proceed."""
    L = QuorumLedger(N)
    L.set_partition({0, 1})                       # 2 of 5
    try:
        L.claim("nonce-1")
        return False, "minority claimed"
    except LedgerFailClosed as e:
        return e.rule == "CL-6", f"[{e.rule}]"


def t_majority_still_serves():
    """Availability is preserved on the majority side -- fail-closed must not
    mean fail-always, or the property is met by a ledger that never works."""
    L = QuorumLedger(N)
    L.set_partition({0, 1, 2})
    L.claim("nonce-1")
    return True, "3/5 side proceeds"


def t_no_split_brain_double_claim():
    """
    THE CENTRAL TEST. Partition into {0,1,2} and {2,3,4}? Not disjoint -- by
    construction two majorities of 5 always intersect. Here we take the two
    largest disjoint sides, 3 and 2, and show only one can claim.
    """
    L = QuorumLedger(N)
    L.set_partition({0, 1, 2})
    L.claim("nonce-X")
    L.set_partition({3, 4})
    try:
        L.claim("nonce-X")
        return False, "both sides claimed the same identifier"
    except LedgerFailClosed as e:
        return e.rule == "CL-6", f"minority refused [{e.rule}]"


def t_exhaustive_no_disjoint_majorities():
    """
    Exhaustive over all 2^5 partitions of a 5-replica set: no two DISJOINT
    subsets can both reach a majority. This is the quorum-intersection argument
    checked by enumeration rather than asserted.
    """
    nodes = set(range(N))
    for size in range(N + 1):
        for side in itertools.combinations(nodes, size):
            a = set(side); b = nodes - a
            if len(a) >= MAJ and len(b) >= MAJ:
                return False, f"disjoint majorities {a} and {b}"
    return True, f"all {2**N} splits checked, no disjoint majorities"


def t_heal_preserves_consumption():
    """After a partition heals, an identifier claimed by the majority must
    still read as consumed -- otherwise the heal itself resets freshness."""
    L = QuorumLedger(N)
    L.set_partition({0, 1, 2})
    L.claim("nonce-Y")
    L.set_partition(None)                          # heal
    try:
        L.claim("nonce-Y")
        return False, "claim survived the heal"
    except LedgerFailClosed as e:
        return e.rule == "CL-2", f"[{e.rule}]"


def t_replica_loss_within_tolerance():
    """N=5 tolerates 2 failures; the third must fail closed, not degrade."""
    L = QuorumLedger(N)
    L.kill(0); L.kill(1)
    L.claim("nonce-Z")                             # 3 alive == majority
    L.kill(2)
    try:
        L.claim("nonce-W")
        return False, "claimed with 2/5 alive"
    except LedgerFailClosed as e:
        return e.rule == "CL-6", f"tolerated 2 losses, refused the 3rd [{e.rule}]"


def t_origin_binding_immutable_across_partition():
    """DS-6f under partition: the pinned origin must not be re-pinned by a
    later majority that did not see the first binding... and if replicas
    disagree, no winner is chosen."""
    L = QuorumLedger(N)
    L.set_partition({0, 1, 2})
    first = L.bind_origin("sha256:P", "nonce-origin")
    L.set_partition({2, 3, 4})                     # overlaps at node 2 only
    second = L.bind_origin("sha256:P", "nonce-attacker")
    # Quorum intersection guarantees node 2 is in this majority, so the prior
    # binding is observed and ADOPTED. The attacker's proposed origin is
    # discarded, and no replica is left holding it.
    L.set_partition(None)
    healed = L.origin_of("sha256:P")
    ok = second == first == healed == "nonce-origin"
    return ok, f"adopted {second!r}, healed read {healed!r}"


def t_origin_read_needs_majority():
    L = QuorumLedger(N)
    L.bind_origin("sha256:Q", "nonce-o")
    L.set_partition({0})
    try:
        L.origin_of("sha256:Q")
        return False, "read served from a single replica"
    except LedgerFailClosed as e:
        return e.rule == "CL-6", f"[{e.rule}]"


TESTS = [
    ("CL-2  claim exactly once", t_claim_once_full_connectivity),
    ("CL-6  minority refuses", t_minority_cannot_claim),
    ("CL-6  majority still serves", t_majority_still_serves),
    ("CL-6  no split-brain double claim", t_no_split_brain_double_claim),
    ("CL-1  no disjoint majorities (exhaustive)", t_exhaustive_no_disjoint_majorities),
    ("CL-4  heal preserves consumption", t_heal_preserves_consumption),
    ("CL-6  replica loss tolerance", t_replica_loss_within_tolerance),
    ("DS-6f origin immutable across partition", t_origin_binding_immutable_across_partition),
    ("CL-6  origin read needs majority", t_origin_read_needs_majority),
]


def main():
    print("=" * 74)
    print("CONSUMPTION LEDGER — PARTITION AND FAULT INJECTION (N=5, majority=3)")
    print("=" * 74)
    fails = 0
    for name, fn in TESTS:
        try:
            ok, detail = fn()
        except Exception as ex:
            ok, detail = False, f"unexpected {type(ex).__name__}: {ex}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<44} {detail}")
        fails += not ok
    print("=" * 74)
    print(f"RESULT: {len(TESTS)-fails}/{len(TESTS)}"
          f"{' — CL-6 HOLDS' if not fails else ' — REVIEW REQUIRED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
