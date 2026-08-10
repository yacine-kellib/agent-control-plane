#!/usr/bin/env python3
"""
acp_ack.py — v1.3.12 fix for T-31 (unauthenticated acknowledgement identity).

THE DEFECT. DR-9 requires positive acknowledgement from a non-operator before
an IRREVERSIBLE action releases. Through v1.3.11 the acknowledging identity was
a bare string, checked only for set membership and inequality with the
operator. No signature, no key, no credential: the release gate held no key
material at all. `class_findings.py` demonstrates an irreversible action
releasing with human_verified=True and zero signatures verified.

Y4 RESTATED. Y4 was "the operator identity was trusted", fixed by making
`operator` a signature-covered AT-1 field. Attestations became signed objects
verified against bundle-registered keys. Acknowledgements never received the
same treatment -- the same defect, one layer up, in machinery a later fix
introduced. This module applies the AT-8 pattern to the surface that missed it.

THE FIX -- ACK-1..ACK-6, mirroring AT-8/TR-10 clause for clause:

  ACK-1  An acknowledgement is an OBJECT with a CLOSED schema (no optional
         fields, exactly ACK1_FIELDS), canonically encoded. Closed because an
         optional field is an encoding split, which is Z4.
  ACK-2  The signature is verified over the canonical object against the
         acknowledger's key from the SIGNED BUNDLE -- the same attester key
         registry the quorum uses. An identity with no registered key cannot
         acknowledge anything.
  ACK-3  BINDING. obj.proposal_hash MUST equal the hash the Executor
         recomputed for the action it is about to release. An acknowledgement
         of a different action is not an acknowledgement of this one.
  ACK-4  The identity used for the DR-9 non-operator test and the DR-5
         recipient-membership test is taken FROM THE SIGNED BYTES, never from
         the call. Y4's actual lesson.
  ACK-5  SINGLE USE. The acknowledgement id is recomputed as h(obj), never
         read from the message, and consumed in the ledger -- so a captured
         acknowledgement cannot be replayed onto a later hold. (Y1b's lesson.)
  ACK-6  Freshness. `issued_at`/`expires_at` are enforced by the Executor,
         window length included, and the acknowledgement must fall inside the
         hold window it is acknowledging. (Y2's lesson.)

The suite floor (CR-4) applies: `alg` is a signed field, so an acknowledger
cannot downgrade its own suite.

WHAT IS STILL NOT FIXED. This authenticates the acknowledgement. It does not
prove a human read anything -- A-8 is untouched, and §04's modelling note
stands: acknowledgement remains an input to the model, never evidence of
comprehension. What changes is that the input is now bound to a key the bundle
registered, instead of being a name anyone could type.
"""
from __future__ import annotations
import time

from acp_executor import (h, sign, sig_ok, canon, FailClosed, CriticalAlert,
                            DeferredReleaseGate)

# ACK-1: CLOSED schema. Exact field set, no more, no less.
ACK1_FIELDS = ("proposal_hash", "policy_bundle_hash", "bundle_epoch",
               "acknowledger", "decision", "ack_nonce", "issued_at",
               "expires_at", "alg")

ACK_WINDOW_MAX = 120          # ACK-6, mirrors L-14
VALID_DECISIONS = ("CONFIRM", "REPUDIATE")


def make_ack(bundle, proposal_hash: str, acknowledger: str, decision: str,
             key: bytes, now: float | None = None, ttl: int = 60,
             alg: str = "hybrid-ed25519-mldsa65") -> dict:
    """Construct a signed Acknowledgement Object. Used by attester clients."""
    now = time.time() if now is None else now
    obj = {"proposal_hash": proposal_hash,
           "policy_bundle_hash": bundle.hash(),
           "bundle_epoch": bundle.epoch,
           "acknowledger": acknowledger,
           "decision": decision,
           "ack_nonce": f"ack-{acknowledger}-{int(now*1000)}",
           "issued_at": now,
           "expires_at": now + ttl,
           "alg": alg}
    return {"obj": obj, "sig": sign(key, h(obj), alg)}


class AuthenticatedReleaseGate(DeferredReleaseGate):
    """
    DeferredReleaseGate with ACK-1..ACK-6 enforced.

    Extends rather than edits: every DR-* property already proven load-bearing
    by Suite 2 mutation testing is inherited unchanged. Only the identity
    handling changes.
    """

    def __init__(self, bundle, ledger, **kw):
        super().__init__(**kw)
        self.bundle = bundle
        # ACK-5: the Consumption Ledger is the single-use AUTHORITY and is
        # REQUIRED. An earlier draft also kept a gate-local `_consumed` set;
        # mutation testing showed it SURVIVES -- the ledger already refuses the
        # replay, so the local set stopped nothing. A check that kills no
        # mutant is not a control, so it was removed rather than retained as
        # decorative defence in depth. Making the ledger mandatory is what
        # actually carries the property: a gate without one cannot be built.
        if ledger is None:
            raise FailClosed("ACK-5", "acknowledgement gate requires a "
                                      "consumption ledger — single-use is not "
                                      "enforceable without one")
        self.ledger = ledger

    # ------------------------------------------------------------------
    def _verify_ack(self, ack: dict, proposal_hash: str, now: float) -> str:
        """
        Verify a signed acknowledgement and return the identity FROM THE SIGNED
        BYTES. Every failure is fail-closed; no path returns an unverified
        identity.
        """
        if not isinstance(ack, dict) or "obj" not in ack:
            raise CriticalAlert("ACK-1", "acknowledgement carries no object "
                                         "(v1.3.11 bare-string form)")
        obj = ack["obj"]
        if not isinstance(obj, dict):
            raise CriticalAlert("ACK-1", "acknowledgement object is not a map")

        # ACK-1: closed schema, exact field set
        if set(obj.keys()) != set(ACK1_FIELDS):
            missing = set(ACK1_FIELDS) - set(obj)
            extra = set(obj) - set(ACK1_FIELDS)
            raise CriticalAlert("ACK-1", f"object schema violation "
                                         f"missing={missing} extra={extra}")

        if obj["decision"] not in VALID_DECISIONS:
            raise CriticalAlert("ACK-1", f"unknown decision {obj['decision']!r}")

        # ACK-2: suite floor, then signature over the canonical object against
        # the key the SIGNED BUNDLE registers for this identity.
        if not self.bundle.suite_ok(obj.get("alg")):
            raise CriticalAlert("CR-4", f"acknowledgement suite {obj.get('alg')} "
                                        f"below bundle floor")
        key = self.bundle.attester_keys.get(obj["acknowledger"])
        if key is None:
            raise CriticalAlert("ACK-2", f"no registered key for "
                                         f"{obj['acknowledger']!r}")
        aid = h(obj)                                   # ACK-5: recomputed
        if not sig_ok(key, aid, ack.get("sig"), obj["alg"]):
            raise CriticalAlert("ACK-2", "acknowledgement signature invalid")

        # ACK-3: THE BINDING. This acknowledgement must name THIS action.
        if obj["proposal_hash"] != proposal_hash:
            raise CriticalAlert("ACK-3", "acknowledgement bound to a DIFFERENT "
                                         "proposal")
        if obj["policy_bundle_hash"] != self.bundle.hash() or \
                obj["bundle_epoch"] != self.bundle.epoch:
            raise CriticalAlert("ACK-3", "acknowledgement policy basis mismatch")

        # ACK-6: freshness, window length enforced by the consumer
        if obj["expires_at"] - obj["issued_at"] > ACK_WINDOW_MAX:
            raise CriticalAlert("ACK-6", f"validity window "
                                         f"{obj['expires_at']-obj['issued_at']}s "
                                         f"exceeds {ACK_WINDOW_MAX}s")
        if not (obj["issued_at"] <= now <= obj["expires_at"]):
            raise CriticalAlert("ACK-6", "acknowledgement outside validity window")

        # ACK-5: single use. The id is RECOMPUTED as h(obj) (never read from
        # the message -- Y1b's lesson) and consumed in the ledger, which is the
        # linearizable authority under CL-2/CL-3.
        self.ledger.claim_attestation(aid)

        # ACK-4: the identity comes from the signed bytes, never the call.
        return obj["acknowledger"]

    # ------------------------------------------------------------------
    def confirm(self, proposal_hash: str, ack: dict, now: float | None = None):
        """DR-9 confirmation. `ack` is a signed object, not a name."""
        now = time.time() if now is None else now
        pr = self.pending.get(proposal_hash)
        if pr is None:
            raise FailClosed("DR-9", "no pending action for that proposal")

        who = self._verify_ack(ack, proposal_hash, now)     # ACK-2..6

        if ack["obj"]["decision"] != "CONFIRM":
            raise FailClosed("ACK-1", "decision field is not CONFIRM")
        # DR-5 and DR-9, now decided on a signature-covered identity
        if who not in pr.notified:
            raise FailClosed("DR-5", "confirmation from a non-notified party")
        if who == pr.operator:
            raise FailClosed("DR-9", "operator cannot confirm their own action")
        pr.confirmed_by.add(who)
        return who

    def repudiate(self, proposal_hash: str, ack: dict, now: float | None = None):
        now = time.time() if now is None else now
        pr = self.pending.get(proposal_hash)
        if pr is None:
            raise FailClosed("DR-4", "no pending action for that proposal")

        who = self._verify_ack(ack, proposal_hash, now)

        if ack["obj"]["decision"] != "REPUDIATE":
            raise FailClosed("ACK-1", "decision field is not REPUDIATE")
        if who not in pr.notified:
            raise FailClosed("DR-5", "repudiation from a non-notified party")
        pr.repudiated_by = who
        return who
