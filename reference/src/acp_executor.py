#!/usr/bin/env python3
"""
acp_executor.py — reference Executor for ACP-SPEC-001 v1.3.5 §9.3.

SCOPE. Implements the Executor verification checklist (steps 1-10), deferred
release for floor-HIGH (DR-1..DR-8, the A-8 mitigation), the DR-13 notice that
covers irreversible actions BELOW floor-HIGH, the
Consumption Ledger (CL-1..CL-6, plus the DS-6f origin binding), the EL-1
expression evaluator, TR-8 risk recomputation, and AT-8/AT-8a/AT-8b
attestation object verification.

CRYPTO DISCLOSURE. Signature primitives are REAL and ASYMMETRIC: Ed25519
(RFC 8032) for the classical leg, ML-DSA-65 (FIPS 204) for the post-quantum
leg, via `acp_crypto`. The HYBRID COMPOSITION (CR-1..CR-5) is conjunctive --
two independent signatures, both required -- because composition is protocol
logic and the downgrade attack it prevents is a control-flow property this
suite can test.

WHY THIS STOPPED BEING A MODELLING DETAIL (v1.3.14). Through v1.3.13 the
primitives were HMAC-SHA256, on the stated ground that substituting real COSE
changes no control flow. That ground was sound for every property except one.
HMAC is symmetric, so verifying a signature requires holding the key that made
it: the Executor held `Bundle.receipt_key` and every entry of
`Bundle.attester_keys`, and a compromised Executor could therefore mint its own
quorum. INV-1-HIGH -- no floor-HIGH action without k independent attestations --
did not hold against the very adversary it names, and no amount of protocol
testing could have found it, because the defect was key CUSTODY, not control
flow. The Bundle now carries PUBLIC keys only (`HybridPub`); no signing key is
reachable from the verifier. Remaining gaps: COSE_Sign1 envelope encoding
(structures here are canonical JSON via `canon`, canonical CBOR is implemented
and tested in `acp_crypto` but not yet the carrier), and SLH-DSA (FIPS 205),
declared in SUITES but not implemented -- see `_PRIMS_IMPLEMENTED`.

FAIL-CLOSED CONTRACT. Every check raises FailClosed. There is no path that
logs-and-continues. `execute()` returns only when every check passed.
"""
from __future__ import annotations
import hashlib, json, time
from dataclasses import dataclass, field
from typing import Any

from acp_crypto import (HybridKey as SigningKey, HybridPub as VerifyingKey,
                        sign_prim, verify_prim)

RISK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
RANK = {v: k for k, v in RISK.items()}
TIER = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}

# AT-8b: the Attestation Object schema is CLOSED. Exact field set, no more.
AT1_FIELDS = ("proposal_hash", "policy_bundle_hash", "bundle_epoch",
              "context_snapshot_hash", "floor_only_risk", "required_roles",
              "required_count", "operator", "att_nonce", "expires_at", "alg")

# CR-1: signature suites. A suite is a SET of primitives, all of which must
# verify. `hybrid` is classical AND post-quantum -- never OR: an OR composition
# is only as strong as its weakest member, which defeats the purpose.
SUITES = {
    "ed25519":            ("classical",),                  # legacy, pre-2027
    "hybrid-ed25519-mldsa65": ("classical", "pq"),          # ANSSI hybridation
    "slhdsa128s":         ("pq-slh",),                      # hash-based, no
                                                            # hybridation needed
}
# There is deliberately NO suite RANK table any more. Through v1.3.14 CR-4 was
# `SUITE_RANK[alg] >= SUITE_RANK[min_suite]` with
# {"ed25519": 0, "slhdsa128s": 1, "hybrid-ed25519-mldsa65": 2} — a TOTAL ORDER
# over sets of primitives that are not comparable. `hybrid` does not contain
# `pq-slh`, and it outranked `slhdsa128s` anyway, so a deployment whose signed
# floor said "hash-based post-quantum, no lattice assumption" silently accepted
# a signature whose post-quantum leg was ML-DSA. Not a stronger suite accepted:
# a DIFFERENT hardness assumption substituted, with the floor check reporting
# satisfaction. CR-4 is containment now — see Bundle.suite_ok.

# `pq-slh` (SLH-DSA, FIPS 205) is DECLARED and NOT IMPLEMENTED. It gets its own
# primitive name rather than sharing `pq` with ML-DSA, because sharing would
# mean a receipt claiming suite `slhdsa128s` was in fact verified against an
# ML-DSA key -- the suite label would name one algorithm and the bytes another,
# which is the encoding-split defect wearing a cryptographic hat. Unimplemented
# fails CLOSED: `verify_prim` returns False and step 9.3-1 refuses.
_PRIMS_IMPLEMENTED = {"classical", "pq"}


class FailClosed(Exception):
    """Any verification failure. Carries the spec rule that fired."""
    def __init__(self, rule: str, detail: str):
        self.rule, self.detail = rule, detail
        super().__init__(f"[{rule}] {detail}")


class CriticalAlert(FailClosed):
    """Fail-closed AND raise a critical alert (compromise-indicating)."""


# ---------------------------------------------------------------- encoding
def canon(obj: Any) -> bytes:
    """
    AT-8a: one canonical encoding, used for BOTH signing and id derivation.
    Deterministic: sorted keys, no whitespace, no floats, UTF-8.
    (A real deployment uses canonical CBOR per RFC 8949 4.2; the property that
    matters here is that exactly one byte string represents one object.)
    """
    if isinstance(obj, float):
        raise FailClosed("AT-8a", "float in canonical structure: not deterministic")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def h(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canon(obj)).hexdigest()


def _sign_prim(key: SigningKey, payload: str, prim: str) -> str:
    # classical -> Ed25519 (RFC 8032), pq -> ML-DSA-65 (FIPS 204).
    # Hex on the wire: signatures travel through JSON (canon, the stdio RPC in
    # sim/services/_rpc.py, the HTTP ingress), and raw bytes do not.
    return sign_prim(key, payload.encode(), prim).hex()


def sign(key: SigningKey, payload: str, alg: str = "hybrid-ed25519-mldsa65") -> dict:
    """CR-2: produce one signature per primitive in the suite."""
    if alg not in SUITES:
        raise FailClosed("CR-1", f"unknown signature suite {alg}")
    missing = set(SUITES[alg]) - _PRIMS_IMPLEMENTED
    if missing:
        raise FailClosed("CR-1", f"suite {alg} needs unimplemented {sorted(missing)}")
    return {p: _sign_prim(key, payload, p) for p in SUITES[alg]}


def sig_ok(pub: VerifyingKey, payload: str, sig: Any, alg: str) -> bool:
    """
    CR-3: EVERY primitive in the declared suite MUST verify. Composition is AND.

    A hybrid verifier that accepts when *either* signature checks out is weaker
    than the weaker primitive, since an attacker who breaks one is unconstrained
    by the other. This is the same shape as INV-1-HIGH's quorum: the security
    comes from requiring all of them, not any of them.

    `pub` is a PUBLIC key. That is the whole point of the swap away from HMAC:
    under a symmetric primitive this argument was the signing key, so an
    Executor able to verify a quorum was also able to mint one, and INV-1-HIGH
    reduced to trusting the Executor. See the CRYPTO DISCLOSURE at the top.
    """
    if alg not in SUITES:
        return False
    if not isinstance(sig, dict):
        return False                       # legacy scalar signature: refuse
    required = set(SUITES[alg])
    if set(sig.keys()) != required:        # no extra, no missing primitives
        return False
    return all(verify_prim(pub, payload.encode(), sig[p], p) for p in required)


# ------------------------------------------------------- EL-1 evaluator
class _P:
    """§8.3.1 parser under EL-1: && binds tighter than ||, both left-assoc."""
    def __init__(self, src: str):
        self.t, self.i = self._lex(src), 0

    @staticmethod
    def _lex(s):
        toks, i, two = [], 0, {"&&", "||", "==", "!=", "<=", ">="}
        while i < len(s):
            c = s[i]
            if c == " ":
                i += 1; continue
            if s[i:i+2] in two:
                toks.append(s[i:i+2]); i += 2; continue
            if c in "()[],<>":
                toks.append(c); i += 1; continue
            if c == "'":
                j = s.index("'", i+1); toks.append(("S", s[i+1:j])); i = j+1; continue
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] in "._"):
                j += 1
            if j == i:
                raise FailClosed("8.3.1", f"illegal character {c!r}")
            toks.append(s[i:j]); i = j
        return toks

    def peek(self): return self.t[self.i] if self.i < len(self.t) else None
    def take(self): v = self.t[self.i]; self.i += 1; return v

    def parse(self):
        e = self.expr()
        if self.i != len(self.t):
            raise FailClosed("8.3.1", "trailing tokens")
        return e

    def expr(self):                       # EL-1: || is the loose level
        n = self.and_expr()
        while self.peek() == "||":
            self.take(); n = ("||", n, self.and_expr())
        return n

    def and_expr(self):                   # EL-1: && is the tight level
        n = self.cmp()
        while self.peek() == "&&":
            self.take(); n = ("&&", n, self.cmp())
        return n

    def value(self):
        tk = self.take()
        if isinstance(tk, tuple): return ("str", tk[1])
        if tk in TIER: return ("tier", TIER[tk])
        if tk.lstrip("-").isdigit(): return ("num", int(tk))
        return ("ref", tk)

    def cmp(self):
        if self.peek() == "(":
            self.take(); e = self.expr()
            if self.take() != ")":
                raise FailClosed("8.3.1", "unbalanced parenthesis")
            return e
        lhs = self.value(); op = self.take()
        if op == "in":
            if self.take() != "[":
                raise FailClosed("8.3.1", "set literal expected")
            items = []
            while True:
                items.append(self.value())
                n = self.take()
                if n == "]": break
                if n != ",": raise FailClosed("8.3.1", "malformed set")
            if not items:
                raise FailClosed("8.3.1", "empty set literal")
            return ("in", lhs, items)
        if op == "<=" and lhs[0] == "ref" and lhs[1].endswith(".prefixlen"):
            return ("plen", lhs[1][:-10], self.value())
        if op not in ("==", "!=", "<", "<=", ">", ">="):
            raise FailClosed("8.3.1", f"unknown operator {op}")
        return ("cmp", op, lhs, self.value())


def _val(v, env):
    return env.get(v[1], ("absent",)) if v[0] == "ref" else v


def _ev(n, env):
    k = n[0]
    if k == "&&": return _ev(n[1], env) and _ev(n[2], env)
    if k == "||": return _ev(n[1], env) or _ev(n[2], env)
    if k == "in":
        a = _val(n[1], env)
        return False if a[0] == "absent" else any(_val(x, env) == a for x in n[2])
    if k == "plen":
        a = env.get(n[1], ("absent",))
        return a[1] <= _val(n[2], env)[1] if a[0] == "cidr" else False
    _, op, l, r = n
    l, r = _val(l, env), _val(r, env)
    if l[0] == "absent" or r[0] == "absent" or l[0] != r[0]:
        return False                                  # totality; type mismatch
    a, b = l[1], r[1]
    return {"==": a == b, "!=": a != b, "<": a < b,
            "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def evaluate(src: str, env: dict) -> bool:
    return _ev(_P(src).parse(), env)


# ------------------------------------------------------- consumption ledger
class Ledger:
    """CL-1..CL-6 plus the DS-6f origin binding. Linearizable by construction."""
    def __init__(self):
        self._nonces: set[str] = set()
        self._attestations: set[str] = set()
        self._epoch_hwm: int = 0
        self._origin: dict[str, str] = {}      # DS-6f: proposal_hash -> nonce
        self._notices: list[dict] = []         # DR-13: committed before execution

    def claim_nonce(self, nonce: str):
        if nonce in self._nonces:
            raise CriticalAlert("CL-2", f"nonce already consumed: {nonce[:16]}")
        self._nonces.add(nonce)

    def claim_attestation(self, aid: str):
        if aid in self._attestations:
            raise CriticalAlert("CL-3", f"attestation already consumed: {aid[:16]}")
        self._attestations.add(aid)

    def check_epoch(self, epoch: int):
        if epoch < self._epoch_hwm:
            raise CriticalAlert("RAD-3", f"epoch rollback {epoch} < {self._epoch_hwm}")
        self._epoch_hwm = max(self._epoch_hwm, epoch)

    # DS-6f: claimed once at first issuance, immutable thereafter.
    def bind_origin(self, proposal_hash: str, nonce: str):
        cur = self._origin.get(proposal_hash)
        if cur is None:
            self._origin[proposal_hash] = nonce
        elif cur != nonce:
            raise CriticalAlert("DS-6f", "origin rebind attempted")

    def origin_of(self, proposal_hash: str) -> str:
        if proposal_hash not in self._origin:
            raise CriticalAlert("DS-6f", "no pinned origin for this proposal")
        return self._origin[proposal_hash]

    # DR-13. The Executor's OWN durable state, deliberately: what the clause
    # makes a precondition of execution is the local commit, not the delivery.
    # Delivery is a network round-trip and EO-2 budgets 25 ms p99 end-to-end for
    # LOW and MEDIUM, so a synchronous confirmed delivery here would be the DR-6
    # defect again -- two normative requirements that cannot both hold. What is
    # bought is weaker than DR-8 and is stated as weaker: a notice committed and
    # never delivered leaves an audit record and no human. The reconciliation
    # obligation that closes that gap is on the deployment (DR-13), not here.
    def record_notice(self, notice: dict) -> None:
        self._notices.append(notice)

    def notices(self) -> list[dict]:
        return list(self._notices)


# ------------------------------------------------------------------ bundle
@dataclass
class Bundle:
    epoch: int
    floors: dict[str, str]
    risk_functions: list[dict]
    adapters: dict[str, str]
    # PUBLIC verification keys. Nothing in this dataclass can sign. That is a
    # property the type now carries: before v1.3.14 these were HMAC secrets, so
    # possession of the bundle was possession of the quorum (see the module
    # CRYPTO DISCLOSURE).
    attester_keys: dict[str, VerifyingKey]
    receipt_key: VerifyingKey
    schemas: dict[str, str]
    # AT-3 quorum threshold. SIGNED POLICY, and deliberately NOT defaulted:
    # a bundle that forgot to say how many approvers a floor-HIGH action needs
    # must fail to construct, not quietly acquire a number this file chose.
    # Through v1.3.14 there was no such field at all and the Executor read the
    # threshold out of the attestation it was verifying — see _verify_quorum.
    quorum_k: int
    reversibility: dict[str, str] = field(default_factory=dict)
    # DR-13: who is told when an IRREVERSIBLE action runs BELOW floor-HIGH.
    # In the bundle rather than in the notifier's own configuration because a
    # notification service that picks its own audience is certifying its own
    # coverage -- RES-8, and the shape T-32 is still open on. Signed policy
    # means "who would have found out" is readable off the bundle instead of
    # being a question you have to ask the party under verification.
    notice_targets: dict[str, list[str]] = field(default_factory=dict)
    min_suite: str = "hybrid-ed25519-mldsa65"      # CR-4: signed floor

    def __post_init__(self):
        # PB-DISTINCT: k signatures must come from k KEY HOLDERS, not from k
        # names.                                (PB-DISTINCT-keys mutation target)
        #
        # AT-2 and AT-3 count distinct `attester` strings, and the registry maps
        # a string to a key. Register two identities against ONE public key and
        # the holder of that one private key signs two objects with different
        # nonces, labels them with the two names, and `len(set(approvals))`
        # reads 2. A floor-HIGH action executes on a single compromised key.
        # Same break as reading `required_count` from the object, reached
        # through the registry instead of through the threshold.
        #
        # Enforced here rather than in the schema because JSON Schema cannot
        # express uniqueness across the VALUES of a map — `uniqueItems` applies
        # to arrays. The schema says so and points here; a normative rule with
        # no enforcement point is a comment.
        #
        # Fail at CONSTRUCTION, not at quorum time: a bundle whose registry
        # cannot support its own quorum is malformed everywhere it is used, and
        # a check on the quorum path would leave every other reader of the
        # bundle believing the registry is sound.
        #
        # Over fingerprints, which cover BOTH halves of the hybrid key. A
        # comparison of the classical halves alone would miss two identities
        # sharing an ML-DSA key, which is CR-3 undone at the registry.
        fingerprints = [k.fingerprint() for k in self.attester_keys.values()]
        if len(set(fingerprints)) != len(fingerprints):
            raise CriticalAlert("PB-DISTINCT",
                                "two attester identities share one verification key")

    # A matching bar on `receipt_key` appearing in the registry was considered
    # and NOT added. At any k >= 2 it removes no compromise: a KMS that also
    # holds one attester key still needs a second approver, so INV-1-HIGH is not
    # broken by that component alone, and the attack demonstrating it would need
    # two compromises to run. The real property — that attesters are humans
    # reading a rendered proposal (A-8) — is not checkable from key material at
    # all, and singling out the one machine key we happen to know about would
    # dress an arbitrary rule as a control.

    def hash(self) -> str:
        return h({"epoch": self.epoch, "floors": self.floors,
                  "risk_functions": self.risk_functions,
                  "adapters": self.adapters, "schemas": self.schemas,
                  "reversibility": self.reversibility,
                  # DR-13. Inside the hash for the same reason as the threshold
                  # below: the recipient set is policy, and two Executors that
                  # would notify different people must not be able to agree
                  # that they hold the same policy.
                  "notice_targets": self.notice_targets,
                  "min_suite": self.min_suite,
                  # AT-3 threshold, inside the hash for the same reason as the
                  # key registry below: two Executors running different quorum
                  # thresholds must not be able to agree that they hold the
                  # same policy. It also makes every attester's signature cover
                  # the threshold transitively, since the Attestation Object
                  # carries policy_bundle_hash — so the quorum an attester was
                  # shown is the quorum that gets enforced, without the
                  # Executor reading a count out of the object.
                  "quorum_k": self.quorum_k,
                  # PB-KEY (v1.3.14). The key registry is INSIDE the hash.
                  # Spec §8.2 puts `attesters/` in the signed bundle tree and
                  # signs "SHA-256 of canonical bundle tree", so this is what
                  # the specification always required; the reference omitted it.
                  # It did no visible harm while primitives were symmetric,
                  # because an Executor holding the signing keys was already
                  # unconstrained. With asymmetric keys the registry becomes the
                  # thing every downstream check ultimately rests on, and a
                  # `policy_bundle_hash` that does not cover it lets two
                  # Executors trusting DIFFERENT attesters agree that they hold
                  # the same policy. RES-8 class: a claimed binding must be
                  # verifiable from the signed bytes of both artifacts.
                  "attesters": {who: k.fingerprint()
                                for who, k in sorted(self.attester_keys.items())},
                  "receipt_key": self.receipt_key.fingerprint()})

    def floor_of(self, resource: str) -> str:
        return self.floors.get(resource, "T3")        # RK-1: absent => T3

    def suite_ok(self, alg: str) -> bool:
        # CR-4: the accepted suite floor lives in the SIGNED bundle, so a
        # compromised issuer cannot negotiate downward. Same shape as RK-1's
        # tier floor: downgrade requires an offline-key policy change.
        #
        # CONTAINMENT, NOT RANK.        (CR-4-containment mutation target)
        # A suite is a SET of primitives, and those sets are not totally
        # ordered — see the note where SUITE_RANK used to be. The offered suite
        # satisfies the floor iff it carries EVERY primitive the floor names.
        # Extra primitives are permitted; a missing one never is, whatever else
        # is offered in its place.
        #
        # An unknown floor returns False rather than raising. Nothing an
        # attacker controls reaches it — `min_suite` comes from the offline
        # signed bundle — so it carries no mutant and is not claimed as a
        # control; it is here so a typo fails closed at the check instead of
        # raising KeyError halfway through a verification.
        if alg not in SUITES or self.min_suite not in SUITES:
            return False
        return set(SUITES[self.min_suite]) <= set(SUITES[alg])

    def reversibility_of(self, task_type: str) -> str:
        # RV-1: absent => IRREVERSIBLE. Same fail-safe default as RK-1's T3:
        # an unclassified action is treated as the most dangerous kind.
        return self.reversibility.get(task_type, "IRREVERSIBLE")


# ------------------------------------------------- deferred release (DR-*)
class RenderedSummary:
    """
    A human-readable summary of an action, plus the identity of the code path
    that produced it. `source_path` is what makes independence checkable: two
    summaries produced by the same path are ONE channel wearing two hats.
    """
    def __init__(self, text: str, source_path: str, from_canonical: bool):
        self.text, self.source_path = text, source_path
        self.from_canonical = from_canonical


def render_from_canonical(proposal: dict, source_path: str) -> RenderedSummary:
    """DR-2: derive the summary from the canonical bytes, with own formatting."""
    t = (f"{proposal['task_type']} on {', '.join(proposal.get('targets', []))} "
         f"[{', '.join(f'{k}={v}' for k, v in sorted(proposal.get('params', {}).items()))}]")
    return RenderedSummary(t, source_path, from_canonical=True)


@dataclass
class PendingRelease:
    proposal_hash: str
    proposal: dict
    receipt: dict
    operator: str
    risk: str
    idempotency_key: str
    fidelity: str
    verified_at: float
    release_at: float
    reversibility: str = "IRREVERSIBLE"
    notified: set = field(default_factory=set)
    confirmed_by: set = field(default_factory=set)
    repudiated_by: str | None = None
    sampled: bool = False


class DeferredReleaseGate:
    """
    DR-1..DR-8. Floor-HIGH actions are verified, then HELD. During the hold an
    independently rendered summary is delivered out-of-band to every attester
    and the operator. Any recipient may repudiate; silence releases.

    This does not prove the approver understood anything (A-8 stays open). It
    raises the bar from ONE compromised component to TWO independent ones:
    the presentation path AND the notification path.
    """
    def __init__(self, hold_seconds: int = 60, notifier=None,
                 sample_rate: float = 0.1, sampler=None):
        self.hold = hold_seconds
        self.notifier = notifier
        self.sample_rate = sample_rate
        # DR-11: the draw MUST NOT be predictable or influenceable by the
        # requester. A draw derived from the Proposal lets an attacker grind
        # inputs until an action is unsampled. Executor-local CSPRNG by default.
        self.sampler = sampler or (lambda: __import__("secrets").randbelow(10**6) / 10**6)
        self.pending: dict[str, PendingRelease] = {}
        self.unverified_releases: int = 0

    def hold_action(self, pr: PendingRelease, approval_summary: RenderedSummary):
        # DR-2: the notification MUST come from the canonical bytes via a path
        # that shares no code with the approval chain. A summary obtained FROM
        # the party under verification is not evidence -- RES-8 restated.
        note = self.notifier.render(pr.proposal)
        if not note.from_canonical:
            raise CriticalAlert("DR-2", "notification not derived from canonical bytes")
        if note.source_path == approval_summary.source_path:
            raise CriticalAlert("DR-2", "notification shares the approval render path")

        recipients = self.notifier.recipients(pr)
        if not recipients:
            raise CriticalAlert("DR-8", "no out-of-band recipients reachable")
        delivered = self.notifier.deliver(recipients, note)
        if set(delivered) != set(recipients):
            # DR-8: undeliverable notification means the detection channel is
            # absent. Fail closed rather than execute unwatched.
            raise CriticalAlert("DR-8", "notification delivery incomplete")
        pr.notified = set(delivered)
        # DR-10: reversible actions are sampled for mandatory confirmation, so
        # a recipient cannot learn that ignoring notifications is always safe.
        if pr.reversibility == "REVERSIBLE":
            pr.sampled = self.sampler() < self.sample_rate
        self.pending[pr.proposal_hash] = pr

    def confirm(self, proposal_hash: str, who: str):
        pr = self.pending.get(proposal_hash)
        if pr is None:
            raise FailClosed("DR-9", "no pending action for that proposal")
        if who not in pr.notified:
            raise FailClosed("DR-5", "confirmation from a non-notified party")
        if who == pr.operator:
            # The operator initiated the action; their acknowledgement carries
            # no independent information. AT-2 distinctness, restated.
            raise FailClosed("DR-9", "operator cannot confirm their own action")
        pr.confirmed_by.add(who)

    def repudiate(self, proposal_hash: str, who: str):
        pr = self.pending.get(proposal_hash)
        if pr is None:
            raise FailClosed("DR-4", "no pending action for that proposal")
        if who not in pr.notified:
            raise FailClosed("DR-5", "repudiation from a non-notified party")
        pr.repudiated_by = who

    def release(self, proposal_hash: str, now: float):
        pr = self.pending.get(proposal_hash)
        if pr is None:
            raise FailClosed("DR-1", "no pending action for that proposal")
        if pr.repudiated_by is not None:
            del self.pending[proposal_hash]
            raise CriticalAlert("DR-4", f"repudiated by {pr.repudiated_by}")
        if now < pr.release_at:
            raise FailClosed("DR-1", "hold window has not elapsed")
        # DR-6: the receipt must still be valid at release, or the hold has
        # outlived its authorization.
        if now > pr.receipt["expires_at"]:
            raise CriticalAlert("DR-6", "receipt expired during hold window")

        # DR-9: irreversible actions require POSITIVE acknowledgement. Silence
        # is not consent here -- timeout fails closed. DR-10: sampled
        # reversible actions inherit the same requirement.
        needs_confirmation = pr.reversibility == "IRREVERSIBLE" or pr.sampled
        if needs_confirmation and not pr.confirmed_by:
            del self.pending[proposal_hash]
            raise CriticalAlert(
                "DR-9", f"{'irreversible' if pr.reversibility == 'IRREVERSIBLE' else 'sampled'}"
                        " action released without confirmation")

        del self.pending[proposal_hash]
        verified = bool(pr.confirmed_by)
        if not verified:
            # DR-12: silent releases are counted and audited. Silence is a
            # measurable debt, not an invisible acknowledgement.
            self.unverified_releases += 1
        return {"executed": True, "risk": pr.risk, "operator": pr.operator,
                "idempotency_key": pr.idempotency_key, "fidelity": pr.fidelity,
                "deferred": True, "reversibility": pr.reversibility,
                "human_verified": verified, "sampled": pr.sampled}


# ---------------------------------------------------------------- executor
@dataclass
class Executor:
    bundle: Bundle
    ledger: Ledger
    context: dict = field(default_factory=dict)
    alerts: list = field(default_factory=list)
    gate: Any = None                      # DeferredReleaseGate, or None

    # --- TR-8: recompute floor-only risk from bundle + canonical proposal ---
    def recompute_floor_risk(self, proposal: dict) -> str:
        rf = next((r for r in self.bundle.risk_functions
                   if r["applies_to"] == proposal["task_type"]), None)
        if rf is None:
            raise FailClosed("8.4-3", "no risk function for task_type")
        env = {}
        for k, v in proposal.get("params", {}).items():
            env[k] = ("num", v) if isinstance(v, int) else ("str", v)
        for res in proposal.get("targets", []):
            # FLOOR ONLY (TR-5): context raises are deliberately ignored here.
            env[f"{res}.effective_tier"] = ("tier", TIER[self.bundle.floor_of(res)])
        env["resource.effective_tier"] = ("tier", max(
            (TIER[self.bundle.floor_of(r)] for r in proposal.get("targets", [])),
            default=TIER["T3"]))
        for k, v in proposal.get("cidrs", {}).items():
            env[k] = ("cidr", v)
        env["fidelity"] = ("str", self.recompute_fidelity(proposal))
        lvl = RISK[rf.get("base", "LOW")]
        for cond in rf.get("raise_to", []):
            if evaluate(cond["if"], env):
                lvl = max(lvl, RISK[cond["then"]])     # RK-3 monotone max
        return RANK[lvl]

    def recompute_reversibility(self, proposal: dict) -> str:
        """RV-3 / TR-8: recomputed from the signed bundle, NEVER read from the
        receipt. A receipt-asserted 'REVERSIBLE' would suppress the DR-9
        confirmation requirement exactly as X1's forged risk suppressed
        attestation."""
        rv = self.bundle.reversibility_of(proposal["task_type"])
        if rv not in ("REVERSIBLE", "IRREVERSIBLE"):
            raise FailClosed("RV-1", f"illegal reversibility class {rv}")
        return rv

    def recompute_fidelity(self, proposal: dict) -> str:
        sid = proposal.get("schema_id")
        if sid not in self.bundle.adapters:
            raise FailClosed("TR-8", "schema_id not bound to a registered adapter")
        return self.bundle.adapters[sid]

    # --------------------------------------------------------- §9.3 steps
    def execute(self, receipt: dict, proposal: dict, *, redrive: bool = False,
                approval_summary=None):
        b = self.bundle

        # step 1-2: signature over the receipt body, then decision
        body = {k: v for k, v in receipt.items() if k != "sig"}
        alg = receipt.get("alg")
        if not b.suite_ok(alg):
            # CR-4: downgrade fails closed. The floor is bundle-signed, so this
            # cannot be negotiated by the party under verification.
            raise CriticalAlert("CR-4", f"receipt suite {alg} below bundle floor "
                                        f"{b.min_suite}")
        if not sig_ok(b.receipt_key, canon(body).decode(), receipt.get("sig"), alg):
            raise CriticalAlert("9.3-1", "receipt signature invalid")
        if receipt.get("decision") != "ALLOW":
            raise FailClosed("9.3-2", f"decision is {receipt.get('decision')}")

        # step 3: R -- hash the proposal WE received (B-1a), never trust the field
        phash = h(proposal)
        if receipt.get("proposal_hash") != phash:
            raise CriticalAlert("9.3-3", "receipt not bound to this proposal")

        # step 4: B -- policy basis
        if receipt.get("policy_bundle_hash") != b.hash():
            raise CriticalAlert("9.3-4", "policy bundle hash mismatch")
        if receipt.get("bundle_epoch") != b.epoch:
            raise CriticalAlert("9.3-4", "bundle epoch mismatch")
        self.ledger.check_epoch(receipt["bundle_epoch"])

        # step 5: temporal -- position AND window length (Y2)
        now = receipt.get("_now", time.time())
        iat, exp = receipt.get("issued_at"), receipt.get("expires_at")
        if iat is None or exp is None:
            raise FailClosed("9.3-5", "missing temporal fields")
        if now > exp:
            raise FailClosed("9.3-5", "receipt expired")
        if iat > now + 5:
            raise FailClosed("9.3-5", "issued in the future beyond skew")
        if exp - iat > 120:
            raise CriticalAlert("L-14", f"validity window {exp-iat}s exceeds 120s")

        # step 6: nonce single-use (CL-2)
        self.ledger.claim_nonce(receipt["nonce"])

        # step 7: TR-8 recomputation -- never read from the receipt
        risk = self.recompute_floor_risk(proposal)
        fidelity = self.recompute_fidelity(proposal)
        if receipt.get("risk_level_floor_only") not in (None, risk):
            raise CriticalAlert("TR-8", f"receipt claims risk "
                                f"{receipt['risk_level_floor_only']}, recomputed {risk}")
        if receipt.get("fidelity") not in (None, fidelity):
            raise CriticalAlert("TR-8", "receipt fidelity disagrees with adapter binding")
        reversibility = self.recompute_reversibility(proposal)
        if receipt.get("reversibility") not in (None, reversibility):
            raise CriticalAlert("RV-3", "receipt asserts a different reversibility class")

        operator = None
        if risk == "HIGH":
            operator = self._verify_quorum(receipt, phash, risk)
        else:
            operator = receipt.get("operator")

        # step 8: tenant scoping
        if receipt.get("tenant_id") != proposal.get("tenant_id"):
            raise FailClosed("9.3-8", "tenant mismatch")

        # step 9: live capability recheck for floor-HIGH, on the VERIFIED operator
        if risk == "HIGH":
            caps = self.context.get(operator, set())
            need = f"{proposal['task_type']}:{proposal.get('targets',[''])[0]}"
            if need not in caps:
                raise CriticalAlert("9.3-9", f"operator {operator} lacks {need}")

        # step 10 / DS-6: delivery identity
        if redrive:
            origin = self.ledger.origin_of(phash)          # DS-6f: from LEDGER
            claimed = receipt.get("origin_nonce")
            if claimed is not None and claimed != origin:
                raise CriticalAlert("DS-6f", "claimed origin != pinned origin")
        else:
            self.ledger.bind_origin(phash, receipt["nonce"])
            origin = receipt["nonce"]
        idem = h({"proposal_hash": phash, "origin_nonce": origin})
        if receipt.get("idempotency_key") not in (None, idem):
            raise CriticalAlert("DS-6b", "receipt idempotency_key disagrees")

        # DR-13: an IRREVERSIBLE action graded below HIGH never reaches the
        # deferred gate, because DR-1 scopes that gate to floor-HIGH. Until
        # v1.3.15 that meant `reversibility` was computed here, compared against
        # the receipt for RV-3, and then DROPPED -- so RV-1's fail-safe default
        # set a value nothing on this path read, and an irreversible action on a
        # T0/T1 target executed with no notification, no acknowledgement and no
        # record that a human existed. Found by art_harness.py, case fx-04, on
        # its first run; the shape is mail exfiltration.
        #
        # Notice BEFORE execution, for AU-7's reason: a record written after the
        # action can be suppressed by whatever the action enabled, and detection
        # that can be erased is not detection.
        #
        # No acknowledgement is required here and that is the deliberate half.
        # DR-9's friction is affordable at floor-HIGH because a human quorum has
        # already been paid for. Below HIGH there is no quorum and the traffic is
        # the bulk of the deployment, so requiring acknowledgement would page a
        # human for routine work at volume -- T-26 habituation and AT-7
        # rubber-stamping, which W2 already showed is what saturation produces.
        # Detection instead of prevention, and weaker on purpose.
        if risk != "HIGH" and reversibility == "IRREVERSIBLE":
            # DR-13-notice-before-execute (mutation target)
            targets = b.notice_targets.get(proposal["task_type"]) or []
            if not targets:
                # A notice with no addressee is not a detection channel. DR-8's
                # rule does not become false because the risk grade is lower, so
                # this refuses rather than executing unwatched. It is a POLICY
                # gap, not an attack, hence FailClosed and not CriticalAlert:
                # the deployment either names recipients or floors the class at
                # T2+ and moves it onto the deferred path under DR-9.
                raise FailClosed("DR-13",
                                 f"{proposal['task_type']} is IRREVERSIBLE at "
                                 f"risk {risk} and the bundle names no notice "
                                 f"recipients for it")
            self.ledger.record_notice({
                "proposal_hash": phash, "task_type": proposal["task_type"],
                "targets": proposal.get("targets", []), "operator": operator,
                "risk": risk, "reversibility": reversibility,
                "recipients": list(targets), "at": now})

        result = {"executed": True, "risk": risk, "operator": operator,
                  "idempotency_key": idem, "fidelity": fidelity}

        # DR-1: floor-HIGH does not execute here. It is held, notified, and
        # released only if nobody repudiates during the window.
        if risk == "HIGH" and self.gate is not None:
            if approval_summary is None:
                raise CriticalAlert("DR-2", "no approval summary supplied to compare paths")
            pr = PendingRelease(
                proposal_hash=phash, proposal=proposal, receipt=receipt,
                operator=operator, risk=risk, idempotency_key=idem,
                fidelity=fidelity, verified_at=now,
                release_at=now + self.gate.hold,
                reversibility=reversibility)
            self.gate.hold_action(pr, approval_summary)
            return {"executed": False, "pending_release": True,
                    "release_at": pr.release_at, "risk": risk,
                    "operator": operator, "idempotency_key": idem}
        return result

    # --------------------------------------------- step 7b: AT-8 quorum
    def _verify_quorum(self, receipt, phash, risk) -> str:
        b = self.bundle
        entries = receipt.get("attestations") or []
        if not entries:
            raise CriticalAlert("INV-1-HIGH", "floor-HIGH with no attestations")

        approvals, confirmations, operators = [], [], set()
        for e in entries:
            obj = e.get("obj")
            if obj is None:
                raise CriticalAlert("AT-8", "attestation carries no object (v1.3.2 form)")

            # AT-8b: CLOSED schema -- exact field set, never normalize
            if set(obj.keys()) != set(AT1_FIELDS):
                missing = set(AT1_FIELDS) - set(obj)
                extra = set(obj) - set(AT1_FIELDS)
                raise CriticalAlert("AT-8b",
                                    f"object schema violation missing={missing} extra={extra}")

            # (i) signature over the canonical object -- CRYPTO-SWAP
            aid = h(obj)
            # CR-5: `alg` is an AT-1 field, so it is signature-covered -- an
            # issuer cannot rewrite the suite without invalidating the object.
            if not b.suite_ok(obj.get("alg")):
                raise CriticalAlert("CR-4", f"attestation suite {obj.get('alg')} "
                                            f"below bundle floor {b.min_suite}")
            key = b.attester_keys.get(e.get("attester"))
            if key is None or not sig_ok(key, aid, e.get("sig"), obj["alg"]):
                raise CriticalAlert("9.3-7b-i", "attester signature invalid")

            # (ii) THE BINDING
            if obj["proposal_hash"] != phash:
                raise CriticalAlert("9.3-7b-ii",
                                    "attestation bound to a DIFFERENT proposal")
            # (iii) policy basis and recomputed risk
            if obj["policy_bundle_hash"] != b.hash() or obj["bundle_epoch"] != b.epoch:
                raise CriticalAlert("9.3-7b-iii", "attestation policy basis mismatch")
            if obj["floor_only_risk"] != risk:
                raise CriticalAlert("9.3-7b-iii", "attestation risk != recomputed risk")
            # (iii) AT-9 CONSENT, not threshold.       (AT-9-consent mutation target)
            #
            # This is NOT how the quorum size is obtained -- see the AT-9 note
            # further down, where it is recomputed from b.quorum_k and this
            # field is never consulted. Deleting this line cannot lower a
            # quorum.
            #
            # What it catches is different and is an AT-3 failure, not an
            # INV-1-HIGH one: `required_count` is part of what the attester was
            # SHOWN and signed, so a mismatch means the humans approved under a
            # policy the engine did not apply. An attester shown "3 approvals
            # required" consented to an action three people would review.
            # Executing it after two is a real loss of the basis their
            # signature rested on, even though the count enforced was the
            # bundle's and the invariant held throughout.
            #
            # A FIRST PASS AT THIS FIX DELETED THIS CHECK, on the argument that
            # the threshold is already bound transitively through
            # policy_bundle_hash and so an equality test kills no mutant. The
            # argument was sound and the conclusion was wrong, because it only
            # considered attacks that LOWER the threshold. Raising the stated
            # count is not an attack on the invariant at all -- it is an attack
            # on consent, and it has its own mutant.
            if obj["required_count"] != b.quorum_k:
                raise CriticalAlert("AT-9",
                                    f"attester signed for quorum {obj['required_count']}, "
                                    f"bundle requires {b.quorum_k}")
            # (iii) freshness of the object itself
            if obj["expires_at"] < receipt["issued_at"]:
                raise FailClosed("9.3-7b-iii", "attestation expired before issuance")

            # (iii-a) operator from the VERIFIED object (Y4)
            operators.add(obj["operator"])

            # (v) recompute id, never read it; claim the RECOMPUTED id
            if e.get("attestation_id") not in (None, aid):
                raise CriticalAlert("Y1b", "transmitted attestation_id != derived id")
            self.ledger.claim_attestation(aid)

            (approvals if e.get("kind") == "approval" else confirmations).append(
                e["attester"])

        if len(operators) != 1:
            raise CriticalAlert("9.3-7b-iii-a", "attestations disagree on operator")
        operator = operators.pop()

        # AT-3: the threshold is RECOMPUTED from the signed bundle. Never read
        # from the attestation.                    (AT-3-quorum-k mutation target)
        #
        # Through v1.3.14 this line was:
        #     need_roles = entries[0]["obj"]["required_count"]
        # — the Executor asking the party under verification how many signatures
        # it should demand. One compromised attester key signed a well-formed,
        # correctly-bound object carrying `required_count: 1`, and a quorum of
        # ONE satisfied a floor-HIGH action. INV-1-HIGH did not hold. Sixth
        # recurrence of the RES-8 class (C2 → X1 → Y1 → Z3 → W1 → this). What
        # made it survive so long is worth recording: this line sat four lines
        # below `operators` — a field that IS cross-checked — inside a loop that
        # verifies every other member of the object meticulously. Density of
        # nearby checking reads as coverage. It is not.
        #
        # `required_count` STAYS in AT1_FIELDS. It is what the attester was
        # shown (AT-3) and it is signature-covered evidence of that — but it is
        # no longer an input to a control decision, so by the §14 suite 12
        # method it has no class at all rather than a class of T.
        #
        # The per-entry equality check lives in the loop above and is AT-9's
        # SECOND requirement. It is not this one and cannot substitute for it:
        # the two fail closed on disjoint inputs. Deleting the equality check
        # cannot lower a quorum; deleting this line cannot detect an attester
        # who signed under a different stated threshold. Keeping only this one
        # satisfies INV-1-HIGH while silently executing actions no attester
        # agreed to.
        need_roles = b.quorum_k
        if len(set(approvals)) < need_roles:
            raise CriticalAlert("AT-3", f"quorum {len(set(approvals))} < {need_roles}")
        if operator in approvals:                       # AT-2 distinctness
            raise CriticalAlert("AT-2", "operator counted toward own quorum")
        return operator
