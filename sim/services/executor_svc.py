#!/usr/bin/env python3
"""
executor_svc.py — the Executor, as its own process.

Holds NO signing key. It verifies receipts, attestations and acknowledgements
against keys the bundle registers, recomputes every value it acts on, holds
floor-HIGH actions, and releases them. It cannot manufacture any of the things
it checks, which is the entire point of it being a separate process from
`policy_svc` (which signs receipts) and `approval_svc` (where humans sign).

SIGNATURES ARE REAL as of v1.3.14 (Ed25519 + ML-DSA-65, asymmetric), and the
sentence above is now literally true rather than a statement about control flow.
Until then the "verification keys" this process held were HMAC secrets: it could
in principle have signed everything it verified, so "holds no signing key" was a
claim about how the code was written, not about what the key material allowed.
The bundle now carries public keys only.

It parents three children of its own — ledger, anchor, notifier — because those
are the components it consults rather than trusts.
"""
from __future__ import annotations

import os

import sim  # noqa: F401
from acp_audit import Accumulators, AuditChain
from acp_executor import Executor, RenderedSummary

from sim.bundle import make_bundle
from sim.release import (ACCUMULATOR_THRESHOLD, ResearchGate,
                         assert_render_paths_distinct)
from sim.services._rpc import Service, serve
from sim.world import capabilities

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ------------------------------------------------- proxies over the pipes
class LedgerClient:
    """Duck-types the ledger interface the reference Executor expects."""

    def __init__(self, svc: Service):
        self.svc = svc

    def claim_nonce(self, nonce):        return self.svc.call("claim_nonce", nonce=nonce)
    def claim_attestation(self, aid):    return self.svc.call("claim_attestation", aid=aid)
    def check_epoch(self, epoch):        return self.svc.call("check_epoch", epoch=epoch)
    def bind_origin(self, phash, nonce): return self.svc.call("bind_origin", phash=phash, nonce=nonce)
    def origin_of(self, phash):          return self.svc.call("origin_of", phash=phash)


class AnchorClient:
    """Duck-types AnchorService. `up` is a live question, not a cached flag."""

    def __init__(self, svc: Service):
        self.svc = svc

    @property
    def up(self) -> bool:
        return bool(self.svc.call("is_up"))

    def publish(self, tenant, seq, head, now):
        return bool(self.svc.call("publish", tenant=tenant, seq=seq, head=head, now=now))

    def covering(self, tenant, seq):
        return self.svc.call("covering", tenant=tenant, seq=seq)

    @property
    def anchors(self):
        return self.svc.call("anchors")


class NotifierClient:
    """
    Duck-types the notifier the release gate calls.

    The `source_path` in the returned summary is computed IN THE NOTIFIER
    PROCESS from its own module. That is what keeps DR-2's comparison
    meaningful across the boundary: this process is comparing two identities it
    did not author.
    """

    def __init__(self, svc: Service):
        self.svc = svc

    def render(self, proposal):
        r = self.svc.call("render", proposal=proposal)
        return RenderedSummary(r["text"], r["source_path"], r["from_canonical"])

    def recipients(self, pr):
        attesters = [e.get("attester") for e in (pr.receipt.get("attestations") or [])]
        return self.svc.call("recipients", operator=pr.operator, attesters=attesters)

    def deliver(self, recipients, note):
        return self.svc.call("deliver", recipients=recipients, text=note.text)


# ------------------------------------------------------------------ state
_bundle = make_bundle()
_ledger_svc = Service("ledger", "sim.services.ledger_svc", REPO)
_anchor_svc = Service("anchor", "sim.services.anchor_svc", REPO)
_notifier_svc = Service("notifier", "sim.services.notifier_svc", REPO)

_ledger = LedgerClient(_ledger_svc)
_anchor = AnchorClient(_anchor_svc)
_notifier = NotifierClient(_notifier_svc)

# Criterion 11, enforced before this process serves anything at all.
_render_paths = assert_render_paths_distinct()

_chain = AuditChain("t1", _bundle.epoch, "1.0.0", _anchor, now=0.0)
_acc = Accumulators(threshold=ACCUMULATOR_THRESHOLD)
_gate = ResearchGate(chain=_chain, accumulators=_acc, bundle=_bundle,
                     ledger=_ledger, hold_seconds=60, notifier=_notifier,
                     sample_rate=0.10)
_executor = Executor(bundle=_bundle, ledger=_ledger,
                     context=capabilities(_bundle.permitted_targets), gate=_gate)


# ---------------------------------------------------------------- methods
def execute(receipt: dict, proposal: dict, approval_summary: dict) -> dict:
    s = RenderedSummary(approval_summary["text"], approval_summary["source_path"],
                        approval_summary["from_canonical"])
    out = _executor.execute(receipt, proposal, approval_summary=s)
    ph = receipt.get("proposal_hash")
    pr = _gate.pending.get(ph)
    if pr is not None:
        out = dict(out, notified=sorted(pr.notified), sampled=bool(pr.sampled))
    return out


def confirm(proposal_hash: str, ack: dict, now: float) -> str:
    return _gate.confirm(proposal_hash, ack, now)


def repudiate(proposal_hash: str, ack: dict, now: float) -> str:
    return _gate.repudiate(proposal_hash, ack, now)


def release(proposal_hash: str, now: float) -> dict:
    return _gate.release(proposal_hash, now)


def stats() -> dict:
    return {"bundle_hash": _bundle.hash(),
            "unverified_releases": _gate.unverified_releases,
            "accumulators": dict(_acc.counts),
            "ack_demands": _gate.ack_demands,
            "pending": sorted(_gate.pending),
            "chain_len": _chain.seq,
            "render_paths": _render_paths,
            "reconcile": _chain.reconcile(),
            "reconcile_accumulators": _gate.reconcile_accumulators(),
            "accumulator_threshold": _acc.threshold,
            "pids": {"ledger": _ledger_svc.pid, "anchor": _anchor_svc.pid,
                     "notifier": _notifier_svc.pid}}


def fault(kind: str, **kw):
    """Inject a fault into a child service. Used by the acceptance checks."""
    if kind == "anchor_down":
        return _anchor_svc.call("set_up", up=False)
    if kind == "anchor_up":
        return _anchor_svc.call("set_up", up=True)
    if kind == "ledger_kill":
        return _ledger_svc.call("kill", node=kw.get("node", 0))
    if kind == "unreachable":
        return _notifier_svc.call("set_unreachable", who=kw.get("who", []))
    raise ValueError(f"unknown fault {kind!r}")


if __name__ == "__main__":
    serve({"execute": execute, "confirm": confirm, "repudiate": repudiate,
           "release": release, "stats": stats, "fault": fault})
