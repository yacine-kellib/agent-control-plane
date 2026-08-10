#!/usr/bin/env python3
"""
acp_ledger.py — distributed Consumption Ledger with fault injection.

CLOSES the largest untested claim in the specification: CL-6, "fail closed on
partition". The reference Executor's in-memory ledger is linearizable by
construction, so it could not exercise the claim at all. This module implements
a quorum-replicated ledger and injects the faults CL-1/CL-2/CL-6 are about.

MODEL. N replicas; a claim succeeds only on acknowledgement from a strict
majority. A partition splits the replica set; a side holding no majority cannot
claim. This is the standard quorum-intersection argument, and the property that
matters follows from it: two disjoint majorities cannot exist, so the same
identifier cannot be claimed on both sides of any partition.

WHAT THIS IS NOT. Not a consensus implementation — no leader election, no log
replication, no recovery protocol. Replicas here are honest-but-unreachable,
never Byzantine. What is tested is the CLAIM PROTOCOL's failure semantics under
partition and replica loss, which is what CL-6 asserts and what an in-memory
map cannot show. A production deployment on Raft or a database still owes its
own test; this one demonstrates the property is achievable and pins the
semantics an implementation must reproduce.
"""
from __future__ import annotations
from dataclasses import dataclass, field


class LedgerFailClosed(Exception):
    def __init__(self, rule: str, detail: str):
        self.rule, self.detail = rule, detail
        super().__init__(f"[{rule}] {detail}")


@dataclass
class Replica:
    node_id: int
    claimed: set = field(default_factory=set)
    origins: dict = field(default_factory=dict)
    up: bool = True

    def try_claim(self, key: str) -> bool:
        if not self.up:
            raise ConnectionError(f"replica {self.node_id} unreachable")
        if key in self.claimed:
            return False
        self.claimed.add(key)
        return True

    def has(self, key: str) -> bool:
        if not self.up:
            raise ConnectionError(f"replica {self.node_id} unreachable")
        return key in self.claimed

    def read_origin(self, phash: str):
        if not self.up:
            raise ConnectionError(f"replica {self.node_id} unreachable")
        return self.origins.get(phash)

    def write_origin(self, phash: str, nonce: str):
        if not self.up:
            raise ConnectionError(f"replica {self.node_id} unreachable")
        self.origins[phash] = nonce


class QuorumLedger:
    """
    CL-1: linearizable claims via majority quorum.
    CL-2/CL-3: at-most-once per identifier.
    CL-6: no reachable majority => fail closed, never assume success.
    DS-6f: origin binding is claimed once and read back from the quorum.
    """
    def __init__(self, n: int = 5):
        assert n % 2 == 1, "odd replica count so majorities are unambiguous"
        self.replicas = [Replica(i) for i in range(n)]
        self.n = n
        self.partition: set | None = None   # node ids visible to this client

    # ---- fault injection -------------------------------------------------
    def set_partition(self, visible: set | None):
        """Restrict this client's view. None = full connectivity."""
        self.partition = visible

    def kill(self, node_id: int):
        self.replicas[node_id].up = False

    def revive(self, node_id: int):
        self.replicas[node_id].up = True

    def _reachable(self):
        out = []
        for r in self.replicas:
            if self.partition is not None and r.node_id not in self.partition:
                continue
            if not r.up:
                continue
            out.append(r)
        return out

    @property
    def majority(self) -> int:
        return self.n // 2 + 1

    # ---- protocol --------------------------------------------------------
    def claim(self, key: str):
        """
        Claim `key` exactly once. Returns on success; raises otherwise.

        Ordering matters: reachability is checked BEFORE any replica is
        mutated. Claiming on a minority and hoping to reconcile later is the
        split-brain bug CL-6 exists to forbid.
        """
        reachable = self._reachable()
        if len(reachable) < self.majority:
            raise LedgerFailClosed(
                "CL-6", f"no reachable majority ({len(reachable)}/{self.n}, "
                        f"need {self.majority}) — refusing to claim")

        # Read phase: if any reachable replica already holds it, it is consumed.
        for r in reachable:
            if r.has(key):
                raise LedgerFailClosed("CL-2", f"already consumed: {key[:24]}")

        # Write phase: a strict majority must accept.
        accepted = [r for r in reachable if r.try_claim(key)]
        if len(accepted) < self.majority:
            raise LedgerFailClosed(
                "CL-2", f"claim not accepted by a majority "
                        f"({len(accepted)}/{self.majority})")
        return True

    def bind_origin(self, phash: str, nonce: str) -> str:
        """
        DS-6f: claim the origin binding once, immutably.

        TWO-PHASE, and the ordering is the whole point. A first version of this
        method wrote the proposed nonce to each replica and then compared the
        returned values. On a partition whose members had not seen a prior
        binding, that MUTATED them before discovering the disagreement, leaving
        the binding permanently split across the replica set: every later read
        saw two values and failed closed forever. One partitioned bind attempt
        produced a durable denial of service on that Proposal, and no attacker
        was required -- an ordinary network event sufficed.

        The defect is the same shape as the one CL-6 guards against in `claim`:
        mutate-then-check instead of check-then-mutate. Fixed here by reading
        the quorum first, adopting any existing binding, and writing only when
        none exists. Because any two majorities intersect, a majority always
        observes a binding a prior majority wrote -- so adoption is total, not
        best-effort.
        """
        reachable = self._reachable()
        if len(reachable) < self.majority:
            raise LedgerFailClosed("CL-6", "no reachable majority for origin binding")

        # Phase 1 -- read. No writes yet.
        seen = {}
        for r in reachable:
            v = r.read_origin(phash)
            if v is not None:
                seen[r.node_id] = v
        distinct = set(seen.values())
        if len(distinct) > 1:
            raise LedgerFailClosed(
                "DS-6f", f"replicas disagree on origin: {distinct} — refusing to "
                         f"resolve a security value by vote")

        # Phase 2 -- adopt or write.
        value = distinct.pop() if distinct else nonce
        for r in reachable:
            if r.read_origin(phash) != value:
                r.write_origin(phash, value)      # read-repair / first write
        return value

    def origin_of(self, phash: str) -> str:
        reachable = self._reachable()
        if len(reachable) < self.majority:
            raise LedgerFailClosed("CL-6", "no reachable majority for origin read")
        vals = {r.origins.get(phash) for r in reachable}
        vals.discard(None)
        if len(vals) != 1:
            raise LedgerFailClosed("DS-6f", "origin not pinned on a majority")
        return vals.pop()


class QuorumLedgerAdapter:
    """
    Drop-in replacement for the in-memory Ledger, backed by QuorumLedger.

    Exists so the conformance suite can run UNCHANGED against a distributed
    ledger under fault injection: the previous suites tested the Executor and
    the ledger separately, so no test exercised an Executor meeting a CL-6
    failure mid-checklist.
    """
    def __init__(self, n: int = 5):
        self.q = QuorumLedger(n)
        self._epoch_hwm = 0

    def set_partition(self, visible): self.q.set_partition(visible)
    def kill(self, node): self.q.kill(node)

    def claim_nonce(self, nonce): self.q.claim(f"nonce:{nonce}")
    def claim_attestation(self, aid): self.q.claim(f"att:{aid}")

    def check_epoch(self, epoch):
        if epoch < self._epoch_hwm:
            raise LedgerFailClosed("RAD-3", f"epoch rollback {epoch} < {self._epoch_hwm}")
        self._epoch_hwm = max(self._epoch_hwm, epoch)

    def bind_origin(self, phash, nonce): return self.q.bind_origin(phash, nonce)
    def origin_of(self, phash): return self.q.origin_of(phash)
