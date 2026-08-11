#!/usr/bin/env python3
"""
approval_svc.py — the Attestation Presentation Service, as its own process.

This is the screen approvers sign on, and per A-8 it is TCB: compromise it and
quorum becomes a signature over a screen nobody understood. It holds the
attester keys, because this is where humans act.

It imports `sim.approve.render` and NOTHING from `sim.notify`. The separation
from the notifier is a build-input separation, not a runtime check — different
process, different module tree, different code. `executor_svc` refuses to start
if the two render paths ever converge, but that check is a lint over a property
this file's imports are what actually establish.
"""
from __future__ import annotations

from sim.approve import render as approve_render
from sim.bundle import make_bundle
from sim.receipts import make_quorum
from sim.release import sign_ack
from sim.services._rpc import serve

_bundle = make_bundle()


def render(proposal: dict) -> dict:
    s = approve_render.render(proposal)
    return {"text": s.text, "source_path": s.source_path,
            "from_canonical": s.from_canonical}


def attest(proposal: dict, operator: str, approvers: list, now: float,
           risk: str = "HIGH", roles: list | None = None) -> list:
    """Humans sign here. The signature covers the canonical Attestation Object."""
    return make_quorum(_bundle, proposal, operator=operator,
                       approvers=approvers, risk=risk, now=now,
                       required_roles=roles)


def acknowledge(proposal_hash: str, who: str, decision: str, now: float) -> dict:
    """A signed Acknowledgement Object (ACK-1..6). Never a bare name."""
    return sign_ack(_bundle, proposal_hash, who, decision, now)


if __name__ == "__main__":
    serve({"render": render, "attest": attest, "acknowledge": acknowledge})
