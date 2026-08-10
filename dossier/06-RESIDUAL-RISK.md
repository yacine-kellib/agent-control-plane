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

## What is "closed on paper" and not exercised

Essential distinction, so the green results are not over-read:

| Item | Actual status |
|------|---------------|
| Bindings, action identity, origin pinning, encoding, release mode, hybrid composition | **Mechanically proven** + mutants + non-vacuity |
| 44 vectors, partition, integration | **Empirically verified** — covers attacks that were conceived of |
| **AC-5, AU-7, AU-8, revised AU-6** | **Implemented and tested in v1.3.11** (`acp_audit.py`, Suite 7: 11/11, 4/4 mutants). T-28/29/30 replayed as live attacks. Newest machinery in the dossier and therefore the most likely site of the next defect; inside RR-1 like everything after DS-6. |
| Production cryptography | Real Ed25519 and ML-DSA-65, but a Python reference implementation — **forbidden in production** (§8.4) |

## Deployment constraints derived from measurement

- **13.2 kB of signatures per floor-HIGH receipt** (53×). Algorithm-bound; size transport and storage for it.
- **Differentiated EO-2**: 25 ms for LOW/MEDIUM, 250 ms for floor-HIGH. Each deployment **must** publish its own measurement.
- **Distributed ledger required**, with quorum and fail-closed semantics — a single-node ledger does not satisfy CL-6.
- **Physical separation** of the notification service and the approval UI (DR-2): two services, two repositories. A monolith with a shared formatting library violates the rule from the first commit.

## Honest position

This dossier describes an architecture whose central properties are proven and tested, whose defect signature is identified and named, and whose limits are stated rather than dressed up. It does not describe a safe system: it describes a system where it is precisely known what is guaranteed, what is detected, and what cannot be known.
