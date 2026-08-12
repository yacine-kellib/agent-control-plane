#!/usr/bin/env python3
"""
acp_audit.py — reference implementation of AC-5, AU-6 (revised), AU-7, AU-8.

Closes the "normative text written, mechanism not implemented" row of §06:
these clauses existed in ACP-SPEC-001 v1.3.10 as text only. This module
mechanizes them WITHOUT modifying the frozen v1.3.5 reference Executor:
AuditedReleaseGate extends DeferredReleaseGate, so every DR-* property already
proven load-bearing by mutation is inherited unchanged.

STATUS DISCLOSURE (per §06 discipline): this is the NEWEST machinery in the
dossier. The document's own defect pattern (C2 -> X1 -> Y1 -> Z3 -> W1)
predicts the next defect lives here. Mechanized and mutation-tested is not
independently reviewed; this module is inside residual R1 like everything
after DS-6.

Clauses implemented:

  AU-8   Chain genesis is the SHA-256 of the canonical tenant-creation record,
         anchored IMMEDIATELY on tenant creation, not on the batch schedule.
         Rationale: a chain destroyed inside its first anchoring window must
         still leave evidence it existed.

  AU-7   A floor-HIGH action's release record MUST be covered by an external
         anchor BEFORE the action is released. Release fails closed otherwise.
         This removes the pre-anchor rewrite gap (T-29 / W3) at zero latency
         cost: the DR-1 hold window was already there.

  AC-5   Accumulators count EXECUTIONS, not Decisions. Increment is committed
         at release, after every DR-* check has passed; repudiated, timed-out
         and fail-closed Decisions increment nothing; a DS-3 re-drive of one
         logical action increments at most once, keyed on the DS-6 action_id.
         (T-28 / W1: decision-counting lets an attacker inflate a deny-effect
         accumulator with actions that never ran, locking out the victim.)

  AU-6   (revised) During an anchoring outage the system continues chaining
         internally, caps new Decisions at ATTEST, and — the W2 fix — MUST NOT
         let that cap compound with DR-9 into unbounded human load: DR-10
         sampling is suspended, so only genuinely irreversible actions demand
         acknowledgement while the outage lasts. Floor-HIGH releases are
         blocked outright by AU-7 for the duration.

  §11.3 (g)/(h)  Reconciliation checks: every executed floor-HIGH record is
         covered by an anchor dated at or before its release; every
         accumulator increment corresponds to exactly one released execution.
"""
from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field

from acp_executor import (canon, FailClosed, CriticalAlert,
                            DeferredReleaseGate)


def _h(obj) -> str:
    return "sha256:" + hashlib.sha256(canon(obj)).hexdigest()


# ================================================================ anchor store
class AnchorService:
    """
    External anchor, OUTSIDE the production trust domain (AU-4). Reachability
    is injectable, because AU-6/AU-7 are claims about its absence.
    The store is append-only from the chain's point of view: a compromised
    audit writer can rewrite the chain, never the anchors.
    """
    def __init__(self):
        self.up = True
        self.anchors: list[dict] = []          # {tenant, seq, head, at}

    def publish(self, tenant: str, seq: int, head: str, now: float) -> bool:
        if not self.up:
            return False
        self.anchors.append({"tenant": tenant, "seq": seq,
                             "head": head, "at": now})
        return True

    def covering(self, tenant: str, seq: int):
        """Earliest anchor covering record `seq`, or None."""
        for a in self.anchors:
            if a["tenant"] == tenant and a["seq"] >= seq:
                return a
        return None


# ================================================================= audit chain
class PublishOnly:
    """
    ANCHOR-SWAP. The AU-4 trust boundary, modelled — the writer is handed the
    ability to PUBLISH an anchor and nothing else: no read, no rewrite, and no
    attribute path back to the store.

    Why this exists. AU-7's guarantee is that a compromised writer can rewrite
    the chain but never an anchor already published. Until this class, the
    reference handed the writer the AnchorService itself, so `chain.anchor.
    anchors.clear()` defeated the property the docstring three lines below was
    asserting. Suite 7 stayed green throughout, because deleting a check is not
    the same test as reaching around one — the same reason all 44 conformance
    cases passed while the Executor held every signing key before v1.3.14.
    Custody, not control flow.

    What this is NOT. Python cannot *enforce* this: a determined caller walks
    `__self__` or `__closure__` and reaches the store anyway. The enforcement
    lives in the process split — `services/anchor` is a separate service, and
    from there "reach into the anchor store" is not expressible. This is a
    faithful model of that boundary, in exactly the sense the HMAC primitives
    were a faithful model of signing before v1.3.14, and it carries a swap
    marker for the same reason.

    Two members, and only two. `publish` is the write path. `up` is
    REACHABILITY, which AU-6 requires the writer to know — an outage caps new
    Decisions at ATTEST and suspends DR-10 sampling, so a writer that could not
    see the outage could not implement the clause. Reachability is not anchor
    CONTENT: knowing the store is unreachable tells you nothing about what is
    in it, and lets you rewrite none of it.
    """
    __slots__ = ("_anchor",)

    def __init__(self, anchor: AnchorService):
        self._anchor = anchor

    def publish(self, tenant: str, seq: int, head: str, now: float) -> bool:
        return self._anchor.publish(tenant, seq, head, now)

    @property
    def up(self) -> bool:
        return self._anchor.up


class AuditChain:
    """
    Per-tenant hash chain (AU-3), genesis per AU-8.

    Chaining: head_0 = H(tenant-creation record); head_n = H({prev, record}).
    The chain lives inside the production trust domain and is therefore
    rewritable by a compromised writer — which is exactly why AU-7 exists:
    what cannot be rewritten is an anchor already published.

    So the chain holds a PublishOnly capability, never the store. Reading
    anchors is the reconciler's job, and the reconciler is a DIFFERENT
    principal running outside this trust domain (AU-4) — which is why
    `reconcile()` takes the store as an argument instead of reaching for one.
    """
    def __init__(self, tenant_id: str, bundle_epoch: int, schema_version: str,
                 anchor: AnchorService, now: float | None = None):
        now = time.time() if now is None else now
        self.tenant = tenant_id
        genesis = {"tenant_id": tenant_id, "created_at": now,
                   "bundle_epoch": bundle_epoch,
                   "schema_version": schema_version}
        self.records: list[dict] = []
        self.heads: list[str] = [_h(genesis)]          # heads[seq] covers seq
        # AU-8: genesis is anchored IMMEDIATELY, not on the <=10 min schedule.
        # A tenant whose genesis cannot be anchored does not exist yet.
        if not anchor.publish(tenant_id, 0, self.heads[0], now):
            raise CriticalAlert("AU-8", "genesis anchor unreachable — "
                                        "tenant creation fails closed")
        # The writer gets a publish capability, never the store (AU-4).
        # Constructed here rather than requested from `anchor`, so anything
        # that duck-types the service works — including sim's AnchorClient,
        # which is already a real process boundary.
        self.anchor = PublishOnly(anchor)

    @property
    def seq(self) -> int:
        return len(self.records)

    def append(self, record: dict) -> int:
        self.records.append(dict(record))
        self.heads.append(_h({"prev": self.heads[-1], "record": record}))
        return self.seq

    def anchor_now(self, now: float) -> bool:
        return self.anchor.publish(self.tenant, self.seq, self.heads[-1], now)

    # ---- reconciliation (AU-4: runs outside the production trust domain) ----
    def recompute_heads(self) -> list[str]:
        """Recompute the chain from the records as currently stored."""
        heads = [self.heads[0]]
        for r in self.records:
            heads.append(_h({"prev": heads[-1], "record": r}))
        return heads

    def reconcile(self, anchor: AnchorService) -> list[str]:
        """
        Compare recomputed heads against published anchors. A mismatch means
        the chain was rewritten AFTER anchoring — the only rewrite AU-7
        leaves possible, and it is detectable, not silent.
        Also enforces §11.3 (g): every record with outcome=executed at
        floor-HIGH is covered by an anchor dated at or before its release.

        The store is an ARGUMENT, not `self.anchor`. Reconciliation is a
        different principal from the writer and runs outside the production
        trust domain; a chain that could read the anchors on its own would be
        the audited party supplying its own evidence (RES-8).
        """
        findings = []
        heads = self.recompute_heads()
        for a in anchor.anchors:
            if a["tenant"] != self.tenant:
                continue
            if a["seq"] >= len(heads) or heads[a["seq"]] != a["head"]:
                findings.append(
                    f"chain rewritten: anchor seq={a['seq']} head mismatch")
        for i, r in enumerate(self.records, start=1):
            if r.get("type") == "release" and r.get("risk") == "HIGH" \
                    and r.get("outcome") == "executed":
                a = anchor.covering(self.tenant, i)
                if a is None or a["at"] > r["at"]:
                    findings.append(
                        f"(g) executed floor-HIGH record seq={i} not covered "
                        f"by an anchor dated at or before release")
        return findings


# ================================================================ accumulators
class Accumulators:
    """
    AC-5. One counter per (accumulator, operator). An increment is legal only
    at release; the ONLY caller is AuditedReleaseGate after super().release()
    has returned — i.e. after DR-1/4/5/6/9 all passed and the action executed.
    Re-drives dedup on the DS-6 action_id (at most one increment per logical
    action). A deny-effect accumulator at threshold locks the operator out.
    """
    def __init__(self, threshold: int = 3):
        self.threshold = threshold
        self.counts: dict[str, int] = {}
        self.counted_actions: set[str] = set()

    def locked(self, operator: str) -> bool:
        return self.counts.get(operator, 0) >= self.threshold

    def record_release(self, action_id: str, operator: str):
        # AC-5-anchor-release (do not move: mutation target)
        if action_id in self.counted_actions:      # DS-3: at most once
            return
        self.counted_actions.add(action_id)
        self.counts[operator] = self.counts.get(operator, 0) + 1


# ============================================================== audited gate
class AuditedReleaseGate(DeferredReleaseGate):
    """
    DeferredReleaseGate (DR-1..DR-12, unchanged and already mutation-proven)
    + AU-7 anchor-before-release, AC-5 count-at-release, AU-6 outage semantics.
    """
    def __init__(self, chain: AuditChain, accumulators: Accumulators,
                 **kw):
        super().__init__(**kw)
        self.chain = chain
        self.acc = accumulators
        self.ack_demands = 0        # W2 instrumentation: human acks demanded

    # ---- AU-6: outage state is read from the anchor service itself ---------
    @property
    def anchoring_out(self) -> bool:
        return not self.chain.anchor.up

    def hold_action(self, pr, approval_summary):
        if self.acc.locked(pr.operator):
            # deny-effect accumulator: the LEGITIMATE consequence of real
            # executions. T-28 is about reaching this state with fake ones.
            raise FailClosed("AC-5", f"operator {pr.operator} locked by "
                                     f"accumulator threshold")
        super().hold_action(pr, approval_summary)
        # AU-6(i): during an anchoring outage, DR-10 sampling is SUSPENDED so
        # the ATTEST cap cannot compound with DR-9 acknowledgement demands
        # (W2/T-30). Only genuinely irreversible actions demand a human ack.
        if self.anchoring_out:
            pr.sampled = False     # AU-6-suspend-sampling (mutation target)
        if pr.reversibility == "IRREVERSIBLE" or pr.sampled:
            self.ack_demands += 1
        self.chain.append({"type": "hold", "proposal_hash": pr.proposal_hash,
                           "operator": pr.operator, "risk": pr.risk,
                           "at": pr.verified_at})

    def release(self, proposal_hash: str, now: float):
        pr = self.pending.get(proposal_hash)
        if pr is None:
            raise FailClosed("DR-1", "no pending action for that proposal")
        action_id = self.chain.records and next(
            (r.get("action_id") for r in reversed(self.chain.records)
             if r.get("proposal_hash") == proposal_hash
             and r.get("action_id")), None) or pr.idempotency_key

        # AU-7 is enforced at a SINGLE point: the terminal anchor_now() below.
        # An earlier draft added an up-front reachability pre-check for
        # hygiene (fail before the DR decision runs). Mutation testing showed
        # it SURVIVES — deleting it changes no attack outcome, because the
        # terminal guard already fails closed on an unreachable anchor. A check
        # that stops no attack is not a security control, so it was removed
        # rather than kept as decorative defence-in-depth. The cost is that a
        # HIGH release which fails at the anchor has already run its DR
        # decision (pending state consumed); since super().release() performs
        # no external effect and the caller executes only on a returned value,
        # no action escapes — the receipt is simply burned, the documented
        # liveness cost, not a safety gap.
        #
        # The anchored record must be the TERMINAL one — anchoring a "pending"
        # record then mutating it to "executed" is the mutate-after-anchor shape
        # CL-7 forbids, one layer up. Run the DR-* decision first (it performs
        # no external effect — the executor's side effects happen AFTER this
        # gate returns), settle the outcome, append the terminal record, anchor.
        try:
            out = super().release(proposal_hash, now)   # DR-* unchanged
        except FailClosed:
            # DR refusal: record it, but a refused action never executed, so it
            # is not an AU-7 subject and needs no anchor to proceed (it doesn't).
            self.chain.append({"type": "release", "proposal_hash": proposal_hash,
                               "action_id": action_id, "operator": pr.operator,
                               "risk": pr.risk, "outcome": "refused", "at": now})
            raise

        self.chain.append({"type": "release", "proposal_hash": proposal_hash,
                           "action_id": action_id, "operator": pr.operator,
                           "risk": pr.risk, "outcome": "executed", "at": now})
        if pr.risk == "HIGH":
            # AU-7-anchor-before-release (mutation target). The record is now
            # terminal; anchor it before the caller is allowed to execute.
            if not self.chain.anchor_now(now):
                raise CriticalAlert("AU-7", "floor-HIGH release without an "
                                            "anchored audit record — fail closed")

        # AC-5: the increment happens HERE and only here — after execution,
        # never at Decision commit, never on repudiation or timeout.
        self.acc.record_release(action_id, pr.operator)
        out["action_id"] = action_id
        return out

    # §11.3 (h): every accumulator increment <-> one released execution.
    def reconcile_accumulators(self) -> list[str]:
        executed = {r["action_id"] for r in self.chain.records
                    if r.get("type") == "release"
                    and r.get("outcome") == "executed"}
        findings = []
        for aid in self.acc.counted_actions:
            if aid not in executed:
                findings.append(f"(h) accumulator increment for {aid} has no "
                                f"released execution")
        return findings
