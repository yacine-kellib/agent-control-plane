#!/usr/bin/env python3
"""
agent.py — the AI agent (brief §6.1, `agent` service).

Responsibility: consume inbound content, emit typed proposals.

MUST NOT: hold any key, reach any tool, have network egress.

Those three prohibitions are the entire containment story on this side, and
none of them is a filter. The agent is assumed manipulable — by the 11:30
document, by a poisoned corpus, by a backdoored checkpoint — and the
architecture takes no position on how often that happens. It is safe to be
wrong here because being wrong produces a *proposal*, and a proposal is not an
action.

Note what this module does NOT contain: no scoring of its own output, no
refusal logic, no injection detection. Adding any of those would be a
conformance failure dressed as diligence (Door B MUST NOT be relied on for a
security property), and would also make the demo dishonest — the point at 11:30
is that the model complies fully and it does not matter.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sim.bundle import SCHEMA_OF


@dataclass
class Agent:
    """
    Emits typed proposals. Holds nothing else.

    `read` is the model's view of inbound content, INCLUDING text a human reader
    cannot see. Keeping it on the object is what lets the UI show the viewer
    what the model saw, which is the demo's whole claim at 11:30: the injection
    succeeded and the action did not happen are two different facts.
    """
    id: str = "agent-01"
    key: None = None                    # not a placeholder — the design
    read: list = field(default_factory=list)

    def __post_init__(self):
        # Fail loudly rather than quietly acquire authority. If a future edit
        # gives this object a key, the simulation stops being a model of the
        # architecture and should refuse to run.
        assert self.key is None, "the agent must never hold key material"

    def ingest(self, inbound: dict, hidden: str | None = None) -> None:
        """Record what the model saw, visible portion and hidden portion alike."""
        self.read.append({"summary": inbound.get("summary", ""),
                          "hidden": hidden, "kind": inbound.get("kind", "")})

    def propose(self, spec: dict) -> list[dict]:
        """
        Expand one timeline proposal spec into N canonical Proposals.

        The agent chooses task, target, operator and parameters freely — that
        is exactly the authority a compromised model would have. What it cannot
        do is choose the risk, the reversibility, the owning program, or
        whether a human is required: every one of those is recomputed
        downstream from bytes this component never sees.
        """
        out = []
        for i in range(spec.get("repeat", 1)):
            params = {}
            for k, v in (spec.get("params") or {}).items():
                params[k] = v.replace("{i}", f"{i:04d}") if isinstance(v, str) else v
            out.append({
                "task_type": spec["task"],
                "schema_id": SCHEMA_OF.get(spec["task"], "unknown.v1"),
                "tenant_id": "t1",
                "targets": [spec["target"]],
                "operator": spec["operator"],
                "program": spec.get("program"),
                "params": params,
            })
        return out
