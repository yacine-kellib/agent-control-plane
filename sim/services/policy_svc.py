#!/usr/bin/env python3
"""
policy_svc.py — the policy engine and the signing substrate, as their own process.

Holds the receipt signing key. Holds no attester key: it can sign a Decision, and
it cannot manufacture a human. That is EX-4's key-class separation expressed as
process boundaries rather than as a paragraph.

It builds its own bundle rather than receiving one. Every service in this system
does, and the bundle hash they independently arrive at is what binds them
together — a service handed a bundle by a peer would be trusting the peer
(RAD-4: the KMS verifies the bundle itself, it does not accept metadata from the
Policy Engine runtime).
"""
from __future__ import annotations

from sim.bundle import make_bundle
from sim.policy import PolicyEngine
from sim.receipts import make_quorum, make_receipt
from sim.services._rpc import serve
from sim.world import capabilities

_bundle = make_bundle()
_engine = PolicyEngine(_bundle, capabilities(_bundle.permitted_targets))


def evaluate(proposal: dict) -> dict:
    d = _engine.evaluate(proposal)
    return {"disposition": d.disposition, "risk": d.risk,
            "reversibility": d.reversibility, "rule": d.rule,
            "reason": d.reason, "required_count": d.required_count,
            "required_roles": sorted(d.required_roles), "program": d.program}


def issue_receipt(proposal: dict, operator: str, now: float,
                  atts: list | None = None) -> dict:
    return make_receipt(_bundle, proposal, operator=operator, now=now,
                        atts=atts or [])


def bundle_hash() -> str:
    return _bundle.hash()


if __name__ == "__main__":
    serve({"evaluate": evaluate, "issue_receipt": issue_receipt,
           "bundle_hash": bundle_hash})
