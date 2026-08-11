#!/usr/bin/env python3
"""
agent_svc.py — the agent, as its own process.

Holds no key. Opens no socket. Its only channel to the rest of the system is a
stdin/stdout pipe carrying typed proposals. Those are not policy statements
about how the agent should behave — they are facts about this process, and they
stay true if the model inside it is fully compromised.
"""
from __future__ import annotations

from sim.agent import Agent
from sim.services._rpc import serve

_agent = Agent()


def propose(spec: dict) -> list:
    return _agent.propose(spec)


def ingest(inbound: dict, hidden: str | None = None) -> dict:
    _agent.ingest(inbound, hidden)
    return {"read": len(_agent.read)}


def holds_key() -> bool:
    """Asked by the supervisor at startup. The answer must be False, forever."""
    return _agent.key is not None


if __name__ == "__main__":
    serve({"propose": propose, "ingest": ingest, "holds_key": holds_key})
