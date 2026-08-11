#!/usr/bin/env python3
"""
anchor_svc.py — external audit anchoring, as its own process.

AU-4 requires anchors to be verified by a process OUTSIDE the production trust
domain, and AU-3 requires the anchor store to be something a compromised audit
writer cannot rewrite. Both are why this is a separate process rather than a
list inside the executor: an anchor held by the party it audits is a note to
self.

Reachability is injectable. AU-7 says a floor-HIGH action must be anchored
BEFORE it releases, so "the anchor is down" has to be a state the simulation can
actually enter.
"""
from __future__ import annotations

from acp_audit import AnchorService
from sim.services._rpc import serve

_anchor = AnchorService()


def publish(tenant: str, seq: int, head: str, now: float) -> bool:
    return _anchor.publish(tenant, seq, head, now)


def covering(tenant: str, seq: int):
    return _anchor.covering(tenant, seq)


def is_up() -> bool:
    return _anchor.up


def set_up(up: bool) -> bool:
    _anchor.up = bool(up)
    return _anchor.up


def anchors() -> list:
    return list(_anchor.anchors)


if __name__ == "__main__":
    serve({"publish": publish, "covering": covering, "is_up": is_up,
           "set_up": set_up, "anchors": anchors})
