#!/usr/bin/env python3
"""
ledger_svc.py — the Consumption Ledger, as its own process.

Five replicas, quorum-replicated, with injectable partitions. Single-use is a
property across the whole deployment or it is not a property, so this process is
the one authority every Executor consults — CL-1's linearizability is why it
cannot be a local set in each executor.

Faults are injectable (`kill`, `partition`) because CL-6 says the Executor MUST
fail closed when the ledger cannot confirm absence, and asserting that without
producing the condition is how a suite comes to test nothing.
"""
from __future__ import annotations

from acp_ledger import QuorumLedgerAdapter
from sim.services._rpc import serve

_ledger = QuorumLedgerAdapter(n=5)


def claim_nonce(nonce: str) -> bool:
    _ledger.claim_nonce(nonce)
    return True


def claim_attestation(aid: str) -> bool:
    _ledger.claim_attestation(aid)
    return True


def check_epoch(epoch: int) -> bool:
    _ledger.check_epoch(epoch)
    return True


def bind_origin(phash: str, nonce: str) -> str:
    return _ledger.bind_origin(phash, nonce)


def origin_of(phash: str) -> str:
    return _ledger.origin_of(phash)


def kill(node: int) -> int:
    _ledger.kill(node)
    return node


def partition(visible: list | None = None) -> list:
    _ledger.set_partition(set(visible) if visible is not None else None)
    return visible or []


if __name__ == "__main__":
    serve({"claim_nonce": claim_nonce, "claim_attestation": claim_attestation,
           "check_epoch": check_epoch, "bind_origin": bind_origin,
           "origin_of": origin_of, "kill": kill, "partition": partition})
