#!/usr/bin/env python3
"""
notifier_svc.py — the out-of-band notification service, as its own process.

Imports `sim.notify.render` and NOTHING from `sim.approve`. It never asks the
approval chain what it displayed; it re-derives the summary from the canonical
Proposal itself. A summary obtained from the party under verification is that
party's claim about what it showed, which is not evidence of what it showed.

Delivery failure is injectable, because DR-8 is a claim about what happens when
the veto channel is absent, and a claim like that needs the absence to be
producible on demand.
"""
from __future__ import annotations

from sim.notify import render as notify_render
from sim.services._rpc import serve

_unreachable: set = set()
_sent: list = []


def render(proposal: dict) -> dict:
    s = notify_render.render(proposal)
    return {"text": s.text, "source_path": s.source_path,
            "from_canonical": s.from_canonical}


def recipients(operator: str, attesters: list) -> list:
    return notify_render.recipients_for(operator, attesters)


def deliver(recipients: list, text: str) -> list:
    delivered = [r for r in recipients if r not in _unreachable]
    for r in delivered:
        _sent.append({"to": r, "text": text})
    return delivered


def set_unreachable(who: list) -> list:
    _unreachable.clear()
    _unreachable.update(who)
    return sorted(_unreachable)


def sent() -> list:
    return list(_sent)


if __name__ == "__main__":
    serve({"render": render, "recipients": recipients, "deliver": deliver,
           "set_unreachable": set_unreachable, "sent": sent})
