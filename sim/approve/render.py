#!/usr/bin/env python3
"""
sim/approve/render.py — the ATTESTATION PRESENTATION SERVICE's rendering path.

This is the screen an approver signs on. Per A-8 it is TCB: if it is
compromised, quorum becomes a signature over a screen the humans did not
understand, and no cryptographic control in the specification reaches that —
the lie happens upstream of the signature.

The simulation therefore treats this module as the thing that CAN lie. What
constrains it is not its own honesty but `sim/notify/render.py` existing
separately: a compromised presentation service can still obtain an approval, and
still cannot reach execution, because it does not control the notification path.
That raises the bar from one compromised component to two independent ones,
which is exactly the threshold INV-1-HIGH defines.

Read the sibling module's docstring for why these two files must never be
factored together.
"""
from __future__ import annotations

import sim  # noqa: F401
from acp_executor import RenderedSummary

PATH_NAME = "approval"


def path_id() -> str:
    """Structural identity of this render path. See notify/render.py:path_id."""
    return f"{PATH_NAME}:{render.__code__.co_filename}"


def render(proposal: dict) -> RenderedSummary:
    """
    Render the full approval screen from canonical bytes.

    AT-3: the attester is shown the full parameter list, the floor tiers and
    the rule ids that raised the risk, the computed risk, the fidelity class,
    and the `proposal_hash` being signed. They sign a hash-identified Proposal,
    never a paraphrase — which is why the hash is on the screen and not in a
    tooltip.
    """
    lines = [
        "ACTION REQUIRING ATTESTATION",
        f"  action      : {proposal.get('task_type')}",
        f"  target      : {', '.join(proposal.get('targets', []))}",
        f"  operator    : {proposal.get('operator')}",
        f"  program     : {proposal.get('program')}",
    ]
    for k, v in sorted((proposal.get("params") or {}).items()):
        lines.append(f"  {k:<12}: {v}")
    return RenderedSummary("\n".join(lines), path_id(), from_canonical=True)
