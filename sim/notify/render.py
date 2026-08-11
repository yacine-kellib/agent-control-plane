#!/usr/bin/env python3
"""
sim/notify/render.py — the NOTIFIER's rendering path.

DR-2 requires the out-of-band summary to be rendered from the canonical
Proposal bytes by a service sharing NO rendering code path with the Attestation
Presentation Service. This module and `sim/approve/render.py` are that
separation, and they are deliberately kept as two files that do the same job
differently rather than one file called twice.

WHY THE DUPLICATION IS THE POINT. A shared formatting library used by both is a
conformance failure *even when it renders honestly from canonical bytes*,
because independence has to hold under compromise rather than in the nominal
case. Two channels sourced from one renderer are one channel wearing two hats:
a single compromise of that renderer lies to both simultaneously, and the
approver's veto — the entire mechanism deferred release exists to provide —
disappears without any signature failing.

So: if you are tempted to factor these two modules together, that refactor is
the vulnerability. `sim/release.py` refuses to start if they ever converge.
"""
from __future__ import annotations

import sim  # noqa: F401
from acp_executor import RenderedSummary

#: This module's identity as a render path. Computed in `path_id()` from the
#: real code object rather than written as a constant, so a module that
#: re-exports the other one cannot claim to be distinct.
PATH_NAME = "notifier"


def path_id() -> str:
    """
    Structural identity of this render path.

    Derived from the *code object's* filename, not from `__file__` or a
    declared string. That distinction matters: a module that does
    `from sim.approve.render import render` has its own `__file__` but its
    function still points at the other file, and this catches it.
    """
    return f"{PATH_NAME}:{render.__code__.co_filename}"


def render(proposal: dict) -> RenderedSummary:
    """
    Render for out-of-band notification, from canonical bytes only.

    Prose style is intentionally unlike the approval screen's: this is a short
    line meant for a phone at the wrong hour, in the reader's own words, so
    that a lie on the approval screen does not read as the same sentence here.
    """
    task = proposal.get("task_type", "?")
    target = ", ".join(proposal.get("targets", []))
    params = proposal.get("params", {}) or {}
    who = proposal.get("operator", "?")

    detail = ""
    if "cost_eur" in params:
        detail = f" committing EUR {params['cost_eur']:,}"
    elif "quantity_mg" in params:
        detail = f" consuming {params['quantity_mg']} mg of {params.get('reagent','?')}"
    elif "dataset" in params:
        detail = f" disclosing {params['dataset']}"
    elif "dossier" in params:
        detail = f" filing {params['dossier']}"

    text = (f"{who} is about to {task.replace('_', ' ')} on {target}{detail}. "
            f"Reply STOP to veto.")
    return RenderedSummary(text, path_id(), from_canonical=True)


def recipients_for(operator: str, attesters: list) -> list:
    """
    DR-3: every attester recorded in the verified Attestation Objects, plus the
    operator. The operator is included not because their acknowledgement counts
    — DR-9 forbids that — but because they are the one party certain to notice
    an action they did not initiate.
    """
    seen, out = set(), []
    for who in list(attesters) + [operator]:
        if who not in seen:
            seen.add(who)
            out.append(who)
    return out
