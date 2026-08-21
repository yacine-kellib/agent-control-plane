#!/usr/bin/env python3
"""
receipts.py — the KMS side: Decision Receipts and Attestation Objects.

This module is the *signing substrate*, and the simulation treats it as
compromisable. Everything it emits is checked downstream by an Executor that
recomputes rather than reads:

  - it can put any `risk_level_floor_only` it likes in a receipt (TR-8 catches it)
  - it can put any `reversibility` it likes (RV-3 catches it)
  - it can attach a genuine quorum raised for one proposal to a receipt for
    another (AT-8 step 7b(ii) catches it)

None of that is defended against here, on purpose. A signing substrate that
policed itself would be proving the wrong thing.

CRYPTO DISCLOSURE inherited from acp_executor: primitives are real and
asymmetric (Ed25519 + ML-DSA-65), and the hybrid COMPOSITION (CR-1..CR-5) is
conjunctive. This module holds SIGNING keys because it plays the KMS and the
attesters; the Executor it feeds holds none of them.
"""
from __future__ import annotations

import base64
import hashlib
import itertools

import sim  # noqa: F401
from acp_crypto import HybridKey
from acp_executor import canon, h, sign

from sim.world import PEOPLE

#: The research KMS keypair. It lives HERE, in the signing substrate, and not in
#: `sim/bundle.py`: the bundle's defining property since v1.3.14 is that it holds
#: public keys only, so a private key declared in it would contradict the thing
#: the module exists to demonstrate. `make_bundle` registers `.public()`.
RECEIPT_SIGNER = HybridKey(b"kms-research")

ALG = "hybrid-ed25519-mldsa65"          # CR-6: the ANSSI hybridation floor
_nonce = itertools.count(1)


def fresh_nonce(prefix: str = "n") -> str:
    """A WE-4 conforming, AT-1 sized nonce, unique per call.

    This returned a bare `att-000264` until ACP-88, and the sim's attestations
    were non-conformant from the moment WE-4 landed in v1.3.18 -- `sim.acceptance`
    went from 11 pass / 0 fail to 5 pass / 6 fail, every failure a WE-4 refusal.
    It was not caught locally by either gate a session normally runs, because
    NEITHER `verify.sh --suites` NOR `selftest.sh` EXECUTES `sim/`. CI does, and
    CI is where it surfaced -- two commits after the clause landed.

    The lesson is the one this repository keeps relearning one artifact at a
    time: a new normative clause invalidates every fixture written before it,
    including the fixtures in the places you did not think of as fixtures. The
    conformance corpus was migrated with the clause, and the ACP-80 probe twice;
    the simulation builds its own Attestation Objects and was migrated by
    neither.

    Still a counter, so a run stays reproducible and two calls stay distinct --
    the only properties any caller relies on. `prefix` survives into the seed
    rather than the value, so `att` and `rcpt` remain different sequences.

    The receipt nonce is given the same treatment even though nothing checks it
    yet (ACP-89): WE-4 governs it too, and a demonstration that emits a value
    its own specification forbids is arguing against itself.
    """
    seed = f"{prefix}-{next(_nonce):06d}".encode()
    return "b64:" + base64.b64encode(hashlib.sha256(seed).digest()[:16]).decode()


def att_obj(bundle, proposal_hash: str, operator: str, risk: str,
            expires_at: float, required_count: int = 2,
            required_roles: list | None = None, nonce: str | None = None) -> dict:
    """
    An AT-1 Attestation Object. The schema is CLOSED (AT-8b): exactly these
    fields, never more, never fewer. An optional field would admit two canonical
    encodings of one object, therefore two ids, therefore two ledger slots —
    which is T-14 amplification reopening through the mechanism built to close
    it.
    """
    return {
        "alg": ALG,
        "proposal_hash": proposal_hash,
        "policy_bundle_hash": bundle.hash(),
        "bundle_epoch": bundle.epoch,
        "context_snapshot_hash": "sha256:ctx",
        "floor_only_risk": risk,
        "required_roles": sorted(required_roles or []),
        "required_count": required_count,
        "operator": operator,
        "att_nonce": nonce or fresh_nonce("att"),
        "expires_at": expires_at,
    }


def entry(obj: dict, attester: str, kind: str = "approval") -> dict:
    """One signed attestation. The signature is over the canonical object."""
    key = PEOPLE[attester].key
    if key is None:
        # Reachable only if someone tries to have the agent attest. It cannot:
        # there is no key to sign with, which is the containment stated as code.
        raise ValueError(f"{attester} holds no key and cannot attest")
    return {"obj": obj, "kind": kind, "attester": attester,
            "sig": sign(key, h(obj), obj["alg"])}


def make_quorum(bundle, proposal: dict, operator: str, approvers: list,
                risk: str = "HIGH", now: float = 0.0, ttl: float = 3600.0,
                required_roles: list | None = None) -> list:
    """
    A quorum bound to THIS proposal's canonical hash.

    Every object carries the same `proposal_hash`, so the Executor can verify
    the binding from the signed bytes rather than take the receipt's word for
    which action these signatures belong to (TR-10: a transmitted identifier is
    a name for a binding, not evidence of one).
    """
    phash = h(proposal)
    base = att_obj(bundle, phash, operator, risk, now + ttl,
                   required_count=len(approvers),
                   required_roles=required_roles)
    out = [entry(dict(base, att_nonce=fresh_nonce("att")), a) for a in approvers]
    # The operator's own first-party confirmation. It never counts toward the
    # approval quorum (AT-2) — it closes the gap between what was meant and
    # what was proposed, which is a different question from whether it is
    # allowed.
    out.append(entry(dict(base, att_nonce=fresh_nonce("att")), operator,
                     "confirmation"))
    return out


def make_receipt(bundle, proposal: dict, *, operator: str, now: float,
                 atts: list | None = None, ttl: float = 110.0,
                 nonce: str | None = None, **override) -> dict:
    """
    A signed Decision Receipt.

    `ttl` defaults to 110 s, inside L-14's 120 s ceiling and — critically —
    longer than the 60 s DR-1 hold it has to outlive (DR-6). A hold configured
    at or above the receipt window is an unsatisfiable configuration: no legal
    receipt can survive it, so the honest path would never release. That
    interaction was found by testing rather than by reading, which is why the
    margin is written down here instead of assumed.
    """
    r = {"alg": ALG, "decision": "ALLOW",
         "proposal_hash": h(proposal),
         "policy_bundle_hash": bundle.hash(), "bundle_epoch": bundle.epoch,
         "issued_at": now, "expires_at": now + ttl,
         "nonce": nonce or fresh_nonce("rcpt"),
         "tenant_id": proposal.get("tenant_id", "t1"),
         "operator": operator,                 # diagnostic only (Y4)
         "attestations": atts or [],
         "_now": now}
    r.update(override)
    r["sig"] = sign(RECEIPT_SIGNER,
                    canon({k: v for k, v in r.items() if k != "sig"}).decode(),
                    r["alg"])
    return r
