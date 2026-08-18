#!/usr/bin/env python3
"""
audit_suite.py — Suite 7: AC-5 / AU-6 / AU-7 / AU-8 under attack.

Same criterion as §05: (A) the honest path executes, (B) T-28, T-29 and T-30
replayed as live attacks fail closed or are detected, (C) each new check is
deleted and the corresponding attack must then succeed (mutation section).

Run:  python3 audit_suite.py            # tests
      python3 audit_suite.py --mutate   # mutation harness (4 mutants)
"""
import hashlib, os, shutil, subprocess, sys, tempfile, time

import conformance as C
from acp_executor import (Executor, FailClosed, CriticalAlert,
                            PendingRelease, RenderedSummary,
                            canon, render_from_canonical)
from acp_audit import AnchorService, AuditChain, Accumulators, AuditedReleaseGate


NOW = time.time()


class Notifier:
    """DR-2-compliant notifier: own path, renders from canonical bytes."""
    def render(self, p):
        return render_from_canonical(p, "notify-mobile")
    def recipients(self, pr):
        return ["attester-1", "attester-2"]
    def deliver(self, recipients, note):
        return list(recipients)


def gate(threshold=3, sample_rate=0.0, anchor_up=True):
    anchor = AnchorService()
    chain = AuditChain("tenant-A", 47, "1.3.11", anchor, now=NOW)
    anchor.up = anchor_up
    g = AuditedReleaseGate(chain, Accumulators(threshold),
                           hold_seconds=60, notifier=Notifier(),
                           sample_rate=sample_rate)
    return g, chain, anchor


def pend(phash, operator="op-1", risk="HIGH", rev="REVERSIBLE", aid=None):
    return PendingRelease(
        proposal_hash=phash, proposal={"task_type": "modify_firewall_rule",
                                       "targets": ["prod-db"], "id": phash},
        receipt={"expires_at": NOW + 120}, operator=operator, risk=risk,
        idempotency_key=aid or f"aid-{phash}", fidelity="FAITHFUL",
        verified_at=NOW, release_at=NOW + 60, reversibility=rev)


def approval(p):
    return render_from_canonical(p, "approval-ui")


# ---------------------------------------------------------------- (A) honest
def t_honest_release_counts_once():
    g, chain, anchor = gate()
    pr = pend("sha256:p1")
    g.hold_action(pr, approval(pr.proposal))
    out = g.release("sha256:p1", NOW + 61)
    ok = (out["executed"] and g.acc.counts.get("op-1") == 1
          and anchor.covering("tenant-A", 2) is not None)
    return ok, "executes, anchored before release, one increment"


def t_redrive_increments_once():
    """DS-3: one logical action, two releases, one increment."""
    g, chain, anchor = gate()
    for i, ph in enumerate(("sha256:pA", "sha256:pB")):
        pr = pend(ph, aid="aid-logical-1")
        g.hold_action(pr, approval(pr.proposal))
        g.release(ph, NOW + 61)
    return g.acc.counts.get("op-1") == 1, \
        f"two releases of one action_id -> count={g.acc.counts.get('op-1')}"


# ------------------------------------------------------------- (B) T-28 / W1
def t_T28_repudiated_does_not_increment():
    """Attacker attributes N proposals to the victim, then repudiates each.
    Under AC-5 the deny-effect accumulator must stay at zero."""
    g, chain, anchor = gate(threshold=3)
    for i in range(5):
        ph = f"sha256:v{i}"
        pr = pend(ph, operator="victim")
        g.hold_action(pr, approval(pr.proposal))
        g.repudiate(ph, "attester-1")
        try:
            g.release(ph, NOW + 61)
        except CriticalAlert:
            pass                                    # DR-4, as designed
    if g.acc.counts.get("victim", 0) != 0:
        return False, f"repudiations incremented: {g.acc.counts}"
    # victim must still be able to act
    pr = pend("sha256:legit", operator="victim")
    g.hold_action(pr, approval(pr.proposal))
    out = g.release("sha256:legit", NOW + 61)
    return out["executed"], "5 repudiations, count=0, victim not locked"


def t_T28_timeout_does_not_increment():
    """An irreversible action released on silence fails DR-9 and must not count."""
    g, chain, anchor = gate()
    pr = pend("sha256:irr", rev="IRREVERSIBLE")
    g.hold_action(pr, approval(pr.proposal))
    try:
        g.release("sha256:irr", NOW + 61)
        return False, "irreversible released silently"
    except CriticalAlert:
        pass
    return g.acc.counts.get("op-1", 0) == 0, "DR-9 refusal, no increment"


# ------------------------------------------------------------- (B) T-29 / W3
def t_T29_no_anchor_no_release():
    """Anchoring down: a floor-HIGH release must fail closed [AU-7]."""
    g, chain, anchor = gate(anchor_up=False)
    pr = pend("sha256:t29")
    g.hold_action(pr, approval(pr.proposal))
    try:
        g.release("sha256:t29", NOW + 61)
        return False, "released without an anchored record"
    except CriticalAlert as e:
        return e.rule == "AU-7", f"fail closed [{e.rule}]"


def t_T29_anchor_drops_mid_release():
    """Anchor reachable at the pre-check, then drops before the terminal
    publish. Only the post-decision anchor_now() guard catches this; the
    release must fail closed [AU-7]."""
    g, chain, anchor = gate()

    class _Flaky(AnchorService):
        def __init__(self, real):
            self.__dict__ = real.__dict__
            self._armed = True
        def publish(self, *a, **k):
            if self._armed:                    # first call (genesis) ok
                pass
            return super().publish(*a, **k)

    pr = pend("sha256:t29c")
    g.hold_action(pr, approval(pr.proposal))
    anchor.up = True                            # up at pre-check
    orig = anchor.publish
    def drop(*a, **k):
        anchor.up = False                       # drops now
        anchor.publish = orig
        return False
    anchor.publish = drop
    try:
        g.release("sha256:t29c", NOW + 61)
        return False, "released though terminal anchor failed"
    except CriticalAlert as e:
        return e.rule == "AU-7", f"terminal anchor failure caught [{e.rule}]"


def t_T29_post_anchor_rewrite_detected():
    """The only rewrite AU-7 leaves possible is post-anchor — detectable."""
    g, chain, anchor = gate()
    pr = pend("sha256:t29b")
    g.hold_action(pr, approval(pr.proposal))
    g.release("sha256:t29b", NOW + 61)
    for r in chain.records:                        # compromised audit writer
        if r.get("type") == "release":
            r["operator"] = "someone-else"
    f = chain.reconcile(anchor)
    return any("rewritten" in x for x in f), f"reconcile: {f[:1]}"


# ------------------------------------------------------------- (B) T-30 / W2
def t_T30_outage_suspends_sampling():
    """Anchoring outage with sample_rate=1.0: reversible actions must demand
    ZERO acknowledgements (AU-6(i)); irreversible still demand theirs."""
    g, chain, anchor = gate(sample_rate=1.0)
    anchor.up = False                              # outage begins
    for i in range(10):
        pr = pend(f"sha256:r{i}", rev="REVERSIBLE")
        g.hold_action(pr, approval(pr.proposal))
    rev_demands = g.ack_demands
    pr = pend("sha256:irr2", rev="IRREVERSIBLE")
    g.hold_action(pr, approval(pr.proposal))
    ok = rev_demands == 0 and g.ack_demands == 1
    return ok, f"reversible demands={rev_demands}, irreversible demands=1"


# ------------------------------------------------------------------ AU-8
def t_AU8_genesis_survives_chain_destruction():
    """A tenant chain deleted inside its first window still leaves evidence."""
    anchor = AnchorService()
    chain = AuditChain("tenant-B", 47, "1.3.11", anchor, now=NOW)
    chain.records.clear(); chain.heads[:] = [chain.heads[0]]   # destroy
    return anchor.covering("tenant-B", 0) is not None, \
        "genesis anchor exists independently of the chain"


def t_AU8_genesis_anchor_down_fails_closed():
    anchor = AnchorService(); anchor.up = False
    try:
        AuditChain("tenant-C", 47, "1.3.11", anchor, now=NOW)
        return False, "tenant created without anchored genesis"
    except CriticalAlert as e:
        return e.rule == "AU-8", f"[{e.rule}]"


# ----------------------------------------------------------- reconciliation
def t_reconciliation_clean_on_honest_run():
    g, chain, anchor = gate()
    pr = pend("sha256:rc")
    g.hold_action(pr, approval(pr.proposal))
    g.release("sha256:rc", NOW + 61)
    f = chain.reconcile(anchor) + g.reconcile_accumulators()
    return not f, "checks (g) and (h) hold"


def t_AU1_clause_derives_the_implementation_head():
    """
    ACP-57. The only executable consumer of AU-1, written because there was
    none: the clause specified `SHA-256(chain_hash_{n-1} || canonical(record_n))`
    while acp_audit.py hashed the canonical two-key map {prev, record}. Those
    disagree from record 1, and they disagreed for four releases without one
    suite going red -- the other ten cases here test the chain against ITSELF
    (consistent, tamper-evident, rewrite-detecting), which is consistency
    evidence and never conformance evidence.

    Derived below from the clause text alone. It deliberately does NOT import
    acp_audit._h: re-using the implementation's hash helper would make this
    agree with any formula either side adopts, which is the vacuous check the
    defect already demonstrated. Drift on EITHER side turns it red.
    """
    anchor = AnchorService()
    now = 1_700_000_000.0
    chain = AuditChain("tenant-au1", bundle_epoch=7, schema_version="1.3.15",
                       anchor=anchor, now=now)

    # AU-1 notation: H(x) = "sha256:" + lowercase hex of SHA-256(canonical(x)),
    # fed forward AS THAT STRING -- the type AU-1 left unpinned until v1.3.15.
    def H(x):
        return "sha256:" + hashlib.sha256(canon(x)).hexdigest()

    # AU-8: chain_hash_0 = H({tenant_id, created_at, bundle_epoch, schema_version})
    want = [H({"tenant_id": "tenant-au1", "created_at": now,
               "bundle_epoch": 7, "schema_version": "1.3.15"})]

    for r in ({"seq": 1, "event": "decision", "outcome": "executed"},
              {"seq": 2, "event": "release", "outcome": "executed"},
              {"seq": 3, "event": "decision", "outcome": "refused"}):
        chain.append(r)
        # AU-1: chain_hash_n = H({"prev": chain_hash_{n-1}, "record": record_n})
        want.append(H({"prev": want[-1], "record": r}))

    if chain.heads != want:
        i = next(k for k, (a, b) in enumerate(zip(chain.heads, want)) if a != b)
        return False, f"clause and implementation diverge at head {i}"
    # AU-3a is a claim about an INDEPENDENT party, and the party that verifies
    # an anchor recomputes rather than replays. So the clause must derive the
    # RECONCILER's head too, not only the writer's.
    if chain.recompute_heads() != want:
        return False, "AU-1 matches append() but not recompute_heads()"
    return True, f"{len(want)} heads incl. AU-8 genesis"


TESTS = [
    ("honest release: anchor first, count once", t_honest_release_counts_once),
    ("DS-3 re-drive increments once", t_redrive_increments_once),
    ("T-28 repudiations do not increment [AC-5]", t_T28_repudiated_does_not_increment),
    ("T-28 DR-9 timeout does not increment [AC-5]", t_T28_timeout_does_not_increment),
    ("T-29 no anchor -> no release [AU-7]", t_T29_no_anchor_no_release),
    ("T-29 anchor drops mid-release [AU-7]", t_T29_anchor_drops_mid_release),
    ("T-29 post-anchor rewrite detected [AU-4]", t_T29_post_anchor_rewrite_detected),
    ("T-30 outage suspends sampling [AU-6]", t_T30_outage_suspends_sampling),
    ("AU-8 genesis outlives chain destruction", t_AU8_genesis_survives_chain_destruction),
    ("AU-8 genesis anchor down fails closed", t_AU8_genesis_anchor_down_fails_closed),
    ("reconciliation (g)+(h) clean", t_reconciliation_clean_on_honest_run),
    ("AU-1 clause derives implementation head [AU-3a]",
     t_AU1_clause_derives_the_implementation_head),
]


# ---------------------------------------------------------------- mutation
MUTANTS = [
    # NOTE (isolation, per Suite-2 discipline): the T-28 repudiation attack is
    # blocked UPSTREAM by DR-4 and never reaches record_release, so it cannot
    # isolate the dedup guard — exactly the X1/B-1a masking §05 documents. The
    # guard is instead isolated by the re-drive attack, the only path that
    # calls record_release twice for one logical action.
    ("AC-5 DS-3 dedup guard (re-drive double count)",
     ("        # AC-5-anchor-release (do not move: mutation target)\n"
      "        if action_id in self.counted_actions:      # DS-3: at most once\n"
      "            return\n"
      "        self.counted_actions.add(action_id)\n"
      "        self.counts[operator] = self.counts.get(operator, 0) + 1",
      "        self.counts[operator] = self.counts.get(operator, 0) + 1"),
     "t_redrive_increments_once"),
    ("AC-5 increment moved before DR checks",
     ("        try:\n            out = super().release(proposal_hash, now)   # DR-* unchanged",
      "        self.acc.record_release(action_id, pr.operator)\n"
      "        try:\n            out = super().release(proposal_hash, now)   # DR-* unchanged"),
     "t_T28_timeout_does_not_increment"),
    ("AU-7 terminal anchor (anchor down)",
     ('            # AU-7-anchor-before-release (mutation target). The record is now\n'
      '            # terminal; anchor it before the caller is allowed to execute.\n'
      '            if not self.chain.anchor_now(now):\n'
      '                raise CriticalAlert("AU-7", "floor-HIGH release without an "\n'
      '                                            "anchored audit record — fail closed")',
      "            self.chain.anchor_now(now)"),
     "t_T29_anchor_drops_mid_release"),
    ("AU-6 sampling suspension deleted",
     ("        if self.anchoring_out:\n"
      "            pr.sampled = False     # AU-6-suspend-sampling (mutation target)",
      "        pass"),
     "t_T30_outage_suspends_sampling"),
]


def run_tests() -> int:
    print("=" * 74)
    print("SUITE 7 — AC-5 / AU-6 / AU-7 / AU-8 UNDER ATTACK")
    print("=" * 74)
    fails = 0
    for name, fn in TESTS:
        try:
            ok, detail = fn()
        except Exception as ex:
            ok, detail = False, f"unexpected {type(ex).__name__}: {ex}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<46} {detail}")
        fails += not ok
    print("=" * 74)
    print(f"RESULT: {len(TESTS)-fails}/{len(TESTS)}"
          f"{' — AC-5/AU-6/AU-7/AU-8 HOLD' if not fails else ' — REVIEW REQUIRED'}")
    return 1 if fails else 0


def run_mutants() -> int:
    _HERE = os.path.dirname(os.path.abspath(__file__))
    SRC_DIR = os.path.join(_HERE, os.pardir, "src")
    src = open(os.path.join(SRC_DIR, "acp_audit.py")).read()
    print("=" * 74)
    print("AUDIT MUTATION — each new check must be load-bearing")
    print("=" * 74)
    fails = 0
    for label, (old, new), test in MUTANTS:
        if src.count(old) != 1:
            print(f"  ERROR  {label:<40} anchor not found ({src.count(old)})")
            fails += 1
            continue
        with tempfile.TemporaryDirectory() as td:
            open(os.path.join(td, "acp_audit.py"), "w").write(
                src.replace(old, new))
            shutil.copy(os.path.join(SRC_DIR, "acp_executor.py"), td)
            # acp_crypto is a hard import of acp_executor since v1.3.14.
            # Absent, the mutant dies at import and is reported ERROR,
            # never KILL — an unrun mutant is not a caught one.
            shutil.copy(os.path.join(SRC_DIR, "acp_crypto.py"), td)
            for f in ("conformance.py", "audit_suite.py"):
                shutil.copy(os.path.join(_HERE, f), td)
            # See mutate_executor.run_mutant: PYTHONPATH must not reach the
            # mutant, or a failed copy silently tests the real module.
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            r = subprocess.run(
                [sys.executable, "-c",
                 f"import audit_suite as A; ok,_ = A.{test}(); "
                 f"h,_ = A.t_honest_release_counts_once(); "
                 f"print(int(ok), int(h))"],
                capture_output=True, text=True, cwd=td, timeout=60, env=env)
            out = (r.stdout.strip().split() + ["?", "?"])[:2]
            attack_blocked, honest_ok = out[0] == "1", out[1] == "1"
            if not attack_blocked and honest_ok:
                print(f"  KILL   {label:<40} attack succeeds without it "
                      f"(honest path still works)")
            elif not attack_blocked:
                print(f"  WEAK   {label:<40} honest path broke — mutant not clean")
                fails += 1
            else:
                print(f"  SURVIVE {label:<39} attack STILL blocked — check "
                      f"redundant or test vacuous")
                fails += 1
    print("=" * 74)
    n = len(MUTANTS)
    print(f"RESULT: {n-fails}/{n} killed"
          f"{' — every new check is load-bearing' if not fails else ' — REVIEW REQUIRED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    if "--mutate" in sys.argv:
        sys.exit(run_mutants())
    sys.exit(run_tests())
