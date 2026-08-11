# 06 — Residual risk and limits

The most important section for a CISO. It is written to be defensible, so it names what is wrong before what is right.

## The two open residuals

### RR-1 — Independent adversarial review: absent

**This is the most important gap in the dossier.** Conformance suite 11 requires review by a party with **no authorship or revision history** on the document. Only one partially independent review exists (`04b-INDEPENDENT-REVIEW.md`), and it covers neither §§6–7 nor any subsequent fix.

Everything after DS-6 — DS-6f, AT-8b, DR-\*, RV-\*, CR-\*, CL-7, AC-5, AU-7/8, and the v1.3.11 audit module — is mechanized and tested, **unconfirmed**.

*Identifier note:* residual risks are **RR-n** in this section. The **R1–R10** in `02b` are claimed *relations*, a different series; the collision was removed in v1.3.11.

The document's own history makes this non-theoretical: five iterations produced a defect every time a fresh surface was examined, **always in machinery the previous fix introduced**. The reasonable inference is not that no defects remain; it is that they are in AC-5, AU-7 and CL-7, the newest.

*Disposition:* engage a qualified party before any production deployment. The brief exists (`ACP-REVIEW-BRIEF`). The reviewer must be able to read Dafny proof artifacts, not only run a penetration test: the central claims are protocol-level, and §07 names where to start.

### RR-2 — A-7, label honesty: unprovable

The system guarantees that a resource labelled critical triggers attestation. It cannot know whether the label matches reality. A production database labelled "sandbox" defeats the whole design — with no attack: the screen is honest and faithfully displays an action the system believes carries no risk.

**Why this is structurally unclosable:** verification is closed under what is computable from trusted bytes. This property relates a label to a real-world sensitivity; there is no trusted source to consult, and any description of the world would itself be an assertion requiring verification.

Since v1.3.7, A-7 also covers **reversibility**: an irreversible action labelled `REVERSIBLE` defeats DR-9 exactly as a false floor defeats INV-1-HIGH.

*Disposition:* RK-5 (two-person rule, offline key) for any label downgrade, plus drift detection between the declared label and observed behaviour. This converts prevention into detection — a real reduction in severity, not a closure.

## New residuals from the v1.3.11 classification regeneration

### T-31 — the acknowledgement identity was unauthenticated — **CLOSED in v1.3.12**

DR-9 is the strongest guarantee in the deferred-release design: an irreversible action must not release without positive acknowledgement from a non-operator. **The acknowledging identity is an unauthenticated string.** No signature, no key, no credential — the release gate holds no key material at all. An irreversible action releases with `human_verified: true` on the strength of a claimed name.

The Dafny theorem is not wrong: §04 states that acknowledgement enters the model as an input, never as evidence a human read anything. The theorem proves the protocol *given an authentic acknowledgement*. **Nothing ever discharged that assumption.**

This is **Y4 restated one layer up** — Y4 was "the operator identity was trusted", fixed by making `operator` a signature-covered field. Attestations are signed; acknowledgements never were. The dossier's own defect signature, recurring in machinery a later fix introduced.

*Disposition — closed.* v1.3.12 adds **ACK-1..ACK-6** (`reference/src/acp_ack.py`): the acknowledgement is a signed object with a closed schema, verified against the acknowledger's key in the signed bundle; the identity used for the DR-9 and DR-5 tests is taken **from the signed bytes**; the object is bound to the recomputed proposal hash; its id is recomputed as `h(obj)` and consumed single-use in the ledger; and its validity window is enforced, length included. Suite 9: **14/14, mutants 6/6**. The T-31 tests in `class_findings.py` are inverted in `ack_suite.py` and now fail closed.

**Still not fixed by this.** Authenticating an acknowledgement is not evidence a human read anything. A-8 is untouched, and §04's modelling note stands: acknowledgement remains an *input* to the model. What changed is that the input is now bound to a registered key rather than being a name anyone could type.

### T-32 — the notifier self-certifies its own independence

`from_canonical`, `source_path` and the delivered-recipient set are produced by the notification service and consumed as evidence *about that service*. A compromised notifier that renders through the approval path, labels itself otherwise, and reports full delivery passes every DR-2 and DR-8 check. RES-8 verbatim.

That DR-2 independence is an architectural property was already disclosed. What was not: **the runtime check provides no assurance against a compromised notifier.** It is a lint against honest misconfiguration. The A-8 two-compromise claim rests entirely on build-time and organisational checks.

*Disposition:* relabel the runtime check as hygiene, not control; move the DR-2 assurance claim onto conformance suite 3 with attested separate build provenance.

## Reduced but non-zero residuals

### A-8 — display fidelity

A compromised presentation service gets an approver to sign, in good faith, an action they never intended. No cryptographic check reaches this: the lie precedes the signature.

**Reduced** by deferred release (§9.6): a summary rendered independently from canonical bytes, a veto window, and for **irreversible** actions the absence of acknowledgement blocks. A display lie now requires **two** independent compromises.

**Not closed:** for reversible actions an ignored notification releases the action. And an attacker holding both services wins.

**A necessary concession about that "two".** The independence of the two paths is DR-2, an *organisational and code-structure* property: two services, two repositories, no shared formatting library. Nothing in the trusted bytes proves it. It is auditable (conformance suite 3) but not provable, and Suite 2 already caught one implementation that looked independent and was not. So the A-8 reduction is **conditional on a property of the same kind as A-7** — weaker than a mechanised guarantee, and it should not be read as one.

### RES-2 — denial composing into safety

Documented, and a new instance was found (T-30): denying anchoring forces the ATTEST cap to compound with DR-9 acknowledgement until approvers saturate. The predictable outcome of saturation is not refusal but rubber-stamping. **An availability attack becomes a safety attack with one extra step.**

AU-6 (revised, now implemented) breaks that specific composition by suspending DR-10 sampling during an outage. What it does not break is the **third composition**: on the reversible path the only human control is notification, T-26 says notification degrades through its own use, and A-7 now covers reversibility labels — so an action mislabelled `REVERSIBLE` inherits the weakest control in the system, with no attack required. Disclosed, not closed.

## New residuals from the polyglot restructure

The repository now holds a second implementation surface (Rust, TypeScript) alongside the Python reference. That changes what the green numbers mean, and the changes are disclosed here before the positive claims are made elsewhere.

### RES-P1 — passing the shared corpus is a partial claim

Conformance vectors express *input → verdict*. They do not express the 30 mutants (which work by deleting a check from source and re-running), ordering properties such as AU-7 anchor-before-release, partition behaviour, or render-path distinctness. A second implementation can therefore pass every vector while none of its checks are load-bearing and none of its orderings are correct. Those properties are **per-implementation obligations**, enumerated separately; an implementation that ships a vector runner and no mutation suite has demonstrated agreement on inputs, not soundness.

### RES-P2 — notifier/approval independence is monorepo-structural

`services/notifier` and `services/approval` are separate codebases with separate dependency trees and separate builds, and may share nothing above the wire format. Separate organisations with separate release keys would be stronger. A monorepo was chosen because separate repositories would break *one clone, one command, every claim replays*, which is what this dossier is for. That is a trade, disclosed as one, not an equivalent.

**This does not close T-32.** Splitting the codebases improves *build-time* provenance, which R12 already credited. At run time the Executor still reads `note.source_path`, `note.from_canonical` and `delivered` from the notifier — the party it is verifying — so those rows remain **T**. Closing T-32 requires the Executor to establish independence from two distinct signed service identities named in the signed bundle: values the notifier does not mint. Recording this is the point; RES-8 has now recurred a sixth time, in the machinery a fix introduced.

### RES-P3 — generated types are a shared dependency of two "independent" services

Both surfaces consume types generated from the signed schemas. The justification is that generated wire types *are* the wire format, not rendering. It remains a shared artifact, and a compromise of the code generator reaches both services at once.

### RES-P4 — integrity is unverified between releases

Splitting the gate makes `--suites` achievable per commit, at the cost that a working tree may diverge from signed bytes for the length of a migration. Behaviour is continuously checked; provenance is checked only at a tagged release.

### RES-P5 — the two implementations are not comparable at the primitive layer

Both implementations now use the same real primitives (Ed25519, ML-DSA-65), so the original reason for this residual — Python modelling signatures with HMAC-SHA256 — no longer applies. The constraint survives for two narrower reasons: ML-DSA signing is hedged (randomised) unless a deployment pins deterministic signing, so two conformant signers produce different bytes over the same message; and a vector carrying a signature must carry key material to be checkable at all. Vectors must therefore still be defined over canonical bytes and declared mutations. This is a live constraint on the corpus, not merely a disclosure: get it wrong and the shared corpus silently stops being shared.

## New residuals from the v1.3.14 crypto swap

### RES-C1 — the signature carrier is not COSE

Signed structures travel as canonical JSON (`acp_executor.canon`), not COSE_Sign1. Canonical CBOR per RFC 8949 §4.2.1 **is** implemented, and its validating decoder is tested by Suite 5 (8/8) — it refuses non-canonical input rather than normalising it — but it is not yet the envelope the primitives sign over. The properties that matter for the protocol (one byte string per object, refusal rather than renormalisation) are exercised; interoperability with a COSE verifier is not, and must not be assumed from these results.

*Disposition:* move the carrier to COSE_Sign1 with the algorithm identifiers registered for Ed25519 and ML-DSA-65. Control flow does not move — this is the same argument that was true of the primitive swap, and it was true there for everything except key custody.

### RES-C2 — SLH-DSA is declared and not implemented

`SUITES` names `slhdsa128s` (SLH-DSA, FIPS 205) and no code implements it. It is given its own primitive name, `pq-slh`, rather than sharing `pq` with ML-DSA: sharing would mean a receipt claiming one algorithm was verified against a key for another, which is the encoding-split defect in cryptographic dress. Signing refuses at CR-1; verification returns false and the Executor refuses at 9.3-1. The failure is closed, but a deployment that reads the suite table as a menu of available options will be wrong.

*Disposition:* implement it or delete the entry. A declared-but-absent suite is a claim the code does not back, which is the thing this dossier exists to argue against.

## What is "closed on paper" and not exercised

Essential distinction, so the green results are not over-read:

| Item | Actual status |
|------|---------------|
| Bindings, action identity, origin pinning, encoding, release mode, hybrid composition | **Mechanically proven** + mutants + non-vacuity |
| 45 vectors, partition, integration | **Empirically verified** — covers attacks that were conceived of |
| **AC-5, AU-7, AU-8, revised AU-6** | **Implemented and tested in v1.3.11** (`acp_audit.py`, Suite 7: 11/11, 4/4 mutants). T-28/29/30 replayed as live attacks. Newest machinery in the dossier and therefore the most likely site of the next defect; inside RR-1 like everything after DS-6. |
| Production cryptography | Real Ed25519 and ML-DSA-65 in both implementations since v1.3.14, but the Python one is a reference implementation — **forbidden in production** (§8.4). Carrier is not COSE (RES-C1); SLH-DSA is declared and absent (RES-C2). |

## Deployment constraints derived from measurement

- **13.2 kB of signatures per floor-HIGH receipt** (53×). Algorithm-bound; size transport and storage for it.
- **Differentiated EO-2**: 25 ms for LOW/MEDIUM, 250 ms for floor-HIGH. Each deployment **must** publish its own measurement.
- **Distributed ledger required**, with quorum and fail-closed semantics — a single-node ledger does not satisfy CL-6.
- **Physical separation** of the notification service and the approval UI (DR-2): two services, two repositories. A monolith with a shared formatting library violates the rule from the first commit.

## Honest position

This dossier describes an architecture whose central properties are proven and tested, whose defect signature is identified and named, and whose limits are stated rather than dressed up. It does not describe a safe system: it describes a system where it is precisely known what is guaranteed, what is detected, and what cannot be known.
