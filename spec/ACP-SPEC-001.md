# Door A: Structured-Input Security Pipeline

## Technical Architecture Specification

**Document ID:** ACP-SPEC-001
**Version:** 1.3.15
**Status:** Draft — all closable items closed. Remaining open: A-7 (conceded unprovable) and independent confirmation (§14 suite 11, structurally unavailable to the authoring parties); hybrid post-quantum signature suites (CR-1..CR-7) per ANSSI hybridation doctrine; deferred release (DR-1..DR-13) with reversibility-keyed confirmation (RV-1..RV-4), mitigating the A-8 presentation residual; all prior findings dispositioned; DS-6f/AT-8b/DR-*/PB-6/PB-7 unconfirmed
**Date:** August 2026
**Supersedes:** v1.3.13, v1.3.12, v1.3.11, v1.3.10, v1.3.4, v1.3.3, v1.3.2, v1.3.1, v1.3.0, v1.2.0 (2026-08)

> **Why 1.3.15 and not 1.3.14.** There is no specification v1.3.14 and there never will be. The *package* release v1.3.14 shipped with this document unchanged at v1.3.13 and says so in `RELEASE.md`; minting a specification v1.3.14 now would put two different artifacts behind one version string, which is precisely the X5 collision this document added a release-integrity rule to prevent. The number is skipped deliberately, and this note exists so that a reader who notices the gap does not go looking for a missing revision.
**Intended Audience:** Security architects, platform engineers, policy engine implementers, formal-methods practitioners

---

## 1. Status of This Document

> **⚠ NORMATIVE ALERT (v1.3.15). Four defects in released code, and three of them were reachable *because this document did not say enough*.** The reference implementation shipped in package v1.3.14 contained a working single-key defeat of INV-1-HIGH by two routes, a suite-floor comparison that accepted an algorithm the floor did not name, and a class of irreversible action that executed with no human notified by any route. The implementation fixes are recorded in `RELEASE.md`; what follows is the normative half, without which a second implementation reproduces them and is conformant while doing so.
>
> **(a) The quorum threshold had no named source.** §9.3 step 7b(iii) required the object's "required roles/counts" to equal "the bundle rule's", but no clause named a bundle field to hold the count, and step 7b(vi) said only "quorum satisfied" without saying *satisfied against what*. The reference therefore took the threshold from `entries[0]` — the artifact under verification — and one compromised attester key, signing one object asserting that one approval sufficed, executed a floor-HIGH action. **PB-6** now puts `quorum_k` in the signed bundle, **AT-9** makes the threshold recomputed-only, and step 7b is rewritten to say which side is authoritative. Sixth recurrence of the RES-8 class (C2 → X1 → Y1 → Z3 → W1 → this) and the first *not* found in machinery a previous fix introduced: it was in the receipt-consumption path from v1.3.4 onward.
>
> **(b) Quorum counted names, not key holders.** AT-2 requires attesters "mutually distinct" and no clause said what distinguishes them. Two registry identities sharing one public key let one key holder sign twice under two names and satisfy k=2 alone. **PB-7** requires attester verification keys to be pairwise distinct over the full suite, and makes a registry violating it an invalid bundle rather than a runtime failure.
>
> **(c) CR-4 ordered suites that are not ordered.** "Ranks below" presumed a total order over suites, but a suite is a *set of primitives* (CR-1) and those sets are incomparable: `hybrid-ed25519-mldsa65` does not contain SLH-DSA, yet outranked `slhdsa128s` under every natural reading. A deployment whose signed floor named hash-based post-quantum accepted a lattice signature with the floor check reporting satisfaction — not a stronger suite accepted, a *different hardness assumption substituted*. **CR-4 is restated as containment.**
>
> **(d) The deferred-release clauses never said what happens below floor-HIGH.** DR-1 scopes the deferred path to floor-HIGH, and DR-9's acknowledgement requirement is reachable only through it. But reversibility is a property of the *action class* while risk is recomputed from the *target's tier floor*, so an action can be `IRREVERSIBLE` and `LOW` at once — and for that action every clause in §9.6 was silent. It executed with no notification, no acknowledgement, and no record that a human existed, while **RV-1's fail-safe default set a value nothing on that path read**. Mail exfiltration has exactly this shape: floor an inbox at T1, which is the natural choice because reading mail is routine, and an injected `send_email` goes out unseen. **DR-13** now requires a durable notice, addressed from the signed bundle, committed before execution — detection, not prevention, and stated as the weaker guarantee it is. **This one was not found by reading.** It was found by `reference/suites/art_harness.py` on its first run, from a fixture written in the shape of an external adversarial corpus rather than from this document's own attack list — which is the argument for building that harness, made by the harness.
>
> **PB-6, PB-7, AT-9 and DR-13 are NEW and UNCONFIRMED** and require independent confirmation per §14 suite 11 before they are relied upon. **A note on how (c) survived:** the ranking was implemented identically in two independent implementations and a differential test asserted their agreement. It agreed. Agreement between implementations is evidence about consistency and never about correctness — particularly when the second was written by reading the first. **A note on how (d) survived:** every suite in the repository was written by the party being defended, so the attack list and the clause list had the same blind spot. Mutation testing cannot find a check that was never written, and §14's differential tests compare two readings of a document that does not mention the case.
>
> **⚠ NORMATIVE ALERT (v1.3.5).** An adversarial pass over v1.3.4's own newest machinery found **two defects in the fixes themselves**: **Z3** (DS-6b's origin check was a membership test, not a pinning test — a compromised KMS moves the idempotency key and a floor-HIGH action doubles) and **Z4** (AT-8a pinned the canonicalizer but not the schema — an optional field yields two ids for one attestation, reopening T-14). Both are closed here by **DS-6f** and **AT-8b** and mechanized in Annex D Part III. Z3 is the **fourth** recurrence of the RES-8 class (C2 → X1 → Y1 → Z3), again in machinery the previous fix introduced. **DS-6f and AT-8b are NEW and UNCONFIRMED** and require independent confirmation per §14 suite 11 before they are relied upon; Part I (Y1/Y1b/Y4) remains confirmed and normative. Two conformance artifacts now ship alongside this document: **ACP-CLASS-001** (the suite-12 classification table) and **`el1_migrate.py`** (the Z1 bundle migration checker), closing two obligations v1.3.4 created without satisfying.
>
> **⚠ HISTORICAL ALERT (v1.3.4).** The v1.3.3 alert is retained below for history. **Status change:** an independent adversarial review (ACP-REVIEW-002) by a party with no authorship or revision history **confirmed Y1 and Y2–Y4**, independently reproduced the Annex D artifact at its published hash, and re-ran the mutation control. AT-8 / TR-10 / step 7b are therefore promoted from PROPOSED to **NORMATIVE** in this revision. That review also produced **three new results**: (a) the published `Y1_AttackBlocked` premise was too strong and has been replaced by `Y1_AttackBlocked_Generalized`; (b) **Y3 now has normative text (DS-6)** and is mechanized; (c) a **new finding Z1** — the §8.3.1 expression grammar states no precedence for `&&`/`||`, so two faithful readings of the prose disagree on 4.9% of mixed-connective expressions (10,000-case prose-derived differential run, `diff_prose.py`). Z1 is fixed by EL-1 below. Deployments **MUST** re-run conformance suite 8 with the parser vectors.
>
> **⚠ HISTORICAL ALERT (v1.3.3).** A partial-independence review (ACP-AUDIT-001, finding **Y1**) identifies a **single-component compromise of the KMS that causes an unauthorized floor-HIGH execution**, violating INV-1-HIGH as the pipeline is written in v1.3.2 and earlier. The receipt transmits attestation *ids and signatures* but not the signed Attestation Object, so the Executor cannot verify that the quorum is **bound to the executed proposal** (§9.3 step 7b as written checks signature validity, not binding). The break is the third recurrence of the RES-8 class (C2 → X1 → Y1), each in machinery a prior fix introduced.
>
> This revision carries the fix — AT-8, TR-10, and a rewritten step 7b (§8.6 / §9.3) — and a **mechanized binding model** (Annex D) proving the fix blocks the Y1 attack and that the current check accepts it. **As of v1.3.4 the fix is NORMATIVE**, following independent confirmation (ACP-REVIEW-002). Suite 11 is **partially satisfied**: the confirmation covered §§8.6, 9, 11 and the Annex D artifact, and explicitly did **not** cover §§6–7 ingress or the Annex B expression-language proof beyond the parser layer. Those surfaces remain unreviewed by a qualified party.

This revision responds to an adversarial peer review of v1.2.0 that identified five internal contradictions, four hidden assumptions, four threat-model gaps, seven formal gaps, and five unacknowledged residual risks. Annex C maps every finding to its disposition.

Three things changed structurally, and everything else follows from them:

1. **The Door A / Door B binary is retired.** What actually varied between the two "doors" was *intent fidelity*, which is a property of an ingress adapter, not a separate architecture. There is now one pipeline, one enforcement core, and a fidelity class stamped on every Proposal that policy can rule on.
2. **Resource tier is split into a signed floor and a runtime raise.** Only cryptographically read-only inputs may lower risk. This makes the headline invariant well-defined and true, rather than ambiguous and false.
3. **Every once-valid artifact is consumed against one linearizable ledger.** Receipt nonces, human attestations, and bundle epochs share a single freshness and single-use mechanism.

**This version claims less than v1.2.0 did.** Claims of universal structural injection-immunity, exactly-once execution, and constant-time evaluation have been retired — each was either false, unachievable, or contradicted elsewhere in the document. The specification is shorter and more correct for that reason. Readers comparing versions should expect deletions, not only additions.

**What v1.3.10 changes.** Every item this document could close is closed.

**CR-6 / EO-2 resolved** by differentiating the latency budget per risk class (EO-2, §8.4), not by weakening either requirement. Hybrid suites stay mandatory everywhere; the 25 ms bound is retained for the LOW/MEDIUM hot path and raised to 250 ms for floor-HIGH, where the action has already waited on a human quorum and a 60 s hold. Optimising 15 ms on a path containing minutes of deliberate human latency was a category error in the original bound.

**Three previously unattacked surfaces were attacked, and each yielded a defect** — §8.5 accumulators, §11 anchoring, and the §8.5 × §9.6 interaction. **W1:** accumulators counted Decisions, but deferred release broke the decision-equals-execution identity, so counters inflate with actions that never ran — attacker-controllable into a targeted lockout of a legitimate operator via a `deny`-effect accumulator. Closed by AC-5 (count at release). **W3:** a floor-HIGH action executes up to ten minutes before its audit record is anchored, so a compromised audit writer can erase the record of an executed action inside the gap — and detection that can be erased is not detection. Closed by AU-7 (anchor before release), at no latency cost, because DR-1's 60 s hold was already there and idle. **W2:** AU-6's ATTEST cap compounds with DR-9's acknowledgement requirement, so denying the anchoring service saturates approvers into rubber-stamping — an availability attack that becomes a safety attack with one extra step. Closed by AU-6 (suspend sampling or fail closed during outage).

**The Executor now runs against a distributed ledger under fault injection.** Previous suites exercised the Executor and the quorum ledger separately, so nothing tested a CL-6 failure landing mid-checklist. Integration now covers it: the full attack suite holds against a 5-replica ledger, minority partitions block at step 6, a partition arriving between the nonce claim and the attestation claim burns the receipt permanently — the documented liveness cost, exercised rather than asserted — and replica loss is tolerated to the quorum bound and refused past it.

**Y5's four minors are closed:** genesis specified (AU-8), canonicalization unified on validated CBOR, reconciliation trust domain stated, nonce-claim liveness tested.

**What remains open, and why it cannot be closed here.** Two items, both structural. **A-7** (honesty of tier and reversibility labels) is conceded unprovable: no mechanism decides whether a label matches the world, and RV-2/RK-5 place label changes under two-person offline control precisely because that is the only available answer. **§14 suite 11 independent confirmation** is unavailable to any party in this document's revision history; every fix from DS-6 onward — DS-6f, AT-8b, DR-*, RV-*, CR-*, CL-7, AC-5, AU-7/8 — is mechanized and tested but unconfirmed, and this document's own pattern (C2 → X1 → Y1 → Z3 → W1) predicts the next defect lives in whichever of them is newest.

**What v1.3.15 changes.** Four clauses that were exploitable *as written*, and a correction to how this document reads its own evidence.

**PB-6, PB-7, PB-8, AT-9 and DR-13 are new; CR-4 and §9.3 step 7b are revised.** The quorum threshold now has a named home in the signed bundle and a normative rule that it is recomputed and never read from an attestation; attester identity is now resolved over keys rather than names; the `SIGNATURE` file's contents are specified as a suite plus one value per primitive, verified conjunctively; the suite floor is satisfied by containment rather than by rank; and an irreversible action graded below floor-HIGH must now commit a notice, addressed from the signed bundle, before it executes. Each closes a defect that was live in released code or in this document, and in nearly every case the implementation defect was **downstream of a gap here**: a threshold comparison whose right-hand side named no field, a distinctness requirement that never said what distinguishes, an ordering over a set that has none, and a set of release clauses that scoped themselves to floor-HIGH without saying what governed the rest. See the v1.3.15 alert in §1.

PB-8 is the one that was a defect *only* here. §8.2's file listing described the bundle signature as "Ed25519 over SHA-256 of canonical bundle tree" while Part V required hybrid composition — an implementer reading the listing while building a bundle emits a classical-only signature over the highest-leverage artifact in the system, and is CR-3 non-conformant while conforming to the sentence they read. Nothing downstream can detect it, because the post-quantum leg is absent rather than wrong. It was found while writing the offline signing tool, at the moment the format stopped being a diagram and became bytes.

**A correction worth recording, and it is PB-8's own aftermath.** Fixing the prose left the schema behind. `spec/schemas/bundle/bundle.schema.json` had described this artifact as a *tree index* — a `members` array of path and digest pairs, plus a `signature` object with two fixed base64 fields named `classical` and `pq`. Neither part survives contact with what exists. §8.2's file listing contains no index file, because the covered set is established by the canonical walk rather than by a shipped list; and PB-8 specifies one value per primitive, which is a map keyed by primitive name, hex-encoded, not a fixed pair. So this document held two descriptions of one object and they disagreed — the encoding-split defect, in the normative source, introduced by the revision that fixed the same defect one paragraph away. The file is now `spec/schemas/bundle/signature.schema.json` and describes the artifact both implementations write.

It survived a full release cycle for a reason worth stating plainly: **nothing read the schemas.** Seven normative files with no consumer, no validator, and no gate line. They were found by `tools/codegen.sh`, which generates the Rust and TypeScript types from them and was the first thing ever to open them — the defect and its detector arrived in the same commit, which is the least reassuring way for either to arrive. That codegen exists does not make the schemas validated; nothing yet checks a real bundle against them, and that gap is disclosed rather than closed.

**A second correction, and it is the same shape as the first.** §11.2's **AU-1** specified the audit chain as `SHA-256(chain_hash_{n-1} ‖ canonical(record_n))`; `reference/src/acp_audit.py` has always hashed the canonical encoding of the two-key map `{prev, record}`. Different preimage, different chain from record 1 onward. The consequence is not that an implementer fails to match — it is that **AU-3a does not hold as written**. AU-3a requires every anchor to be independently verifiable by any party holding the anchor public keys; a third party implementing AU-1 literally recomputes a different head on an **honest, untampered** chain, and AU-4 classifies a head that fails to extend a previously anchored head as a *critical integrity alert*. So the normative text routed an honest verifier into this system's own critical-alert channel, with no attacker present. A second ambiguity sat inside the first: AU-1 never typed `chain_hash_{n-1}`, and the reference feeds forward the 71-character `"sha256:…"` string where `‖` invites raw bytes. **AU-1 is restated over the single canonicaliser and both types are now pinned** — see the rationale at AU-1 for why the clause moved and the code did not.

**Both corrections survived for the same reason, and it is worth naming twice.** Neither clause had an executable consumer. `audit_suite.py` passes 11 of 11 and kills 4 mutants, but every one of those cases tests the chain against **itself** — that it is consistent, that it is tamper-evident, that reconciliation catches a rewrite. Not one compared it to AU-1's formula, and `spec/vectors/CLASSIFICATION.md` recorded the audit suite as **0 of 11 vector-expressible**, so the one suite with no shared-corpus path was the one whose formula drifted. It now reads **1 of 12** — the new case is the only pure function in that suite — and the file records why it is expressible but not yet extractable. Consistency evidence is not conformance evidence. AU-1 now has a case that derives a head from the clause as written and asserts equality with the implementation's, because an edit closes this instance and only an executing check closes the class.

**A third correction: `CL-7` named two different normative rules.** §9.3.1's consumption-ledger list defined **CL-7** twice — "ledger writes are check-then-mutate" (added in v1.3.9) and "every claim operation MUST be audited" (older) — because the v1.3.9 insertion landed *above* CL-6 and took an id that was already in use two lines below it. The list read CL-5, CL-7, CL-6, CL-7. **Both meanings were already live in this document**: §1 above cites CL-7 as check-then-mutate twice, while §10's threat table cited "CL-7 auditing" meaning the other rule — so a reader resolving the id from one place got the wrong clause in the other, and a conformance claim of "CL-7 satisfied" was unfalsifiable, since an implementation could satisfy either and cite the clause honestly. **The audit rule is renumbered CL-8** and the list is reordered. The *older* rule moved, not the v1.3.9 one, because the v1.3.9 id is cited in released prose and in `RELEASE.md`, and an id already published is the one that must not move. No code was affected — `reference/src/acp_ledger.py` implements check-then-mutate and Suites 3 and 4 cover it. What was damaged is the **citation graph**, which `spec/vectors/OBLIGATIONS.md` keys per-implementation obligations to, and which cannot express "passes CL-7" while CL-7 names two rules. `tools/selftest.sh` now asserts that clause ids are unique across every family in this document, because this was found by reading and nothing in the repository could have found it by running.

**The lesson is about a claim this document makes, not only about three clauses.** §14 rests substantially on differential testing — two implementations, one corpus, disagreement as the signal. CR-4's rank table was implemented identically in both, and the differential test asserted their agreement and got it. **Agreement between implementations is evidence about consistency and never about correctness**, and it is weakest exactly where it feels strongest: when the second implementation was written by reading the first, a shared misreading is invisible by construction. §14 suite 6 (prose-derived differential) exists for this reason and is the only suite that could have caught it, because it derives its second reading from the *text* rather than from the code — and CR-4's text said "ranks", so it would have reproduced the defect faithfully. **A prose differential inherits the specification's errors. It cannot find them.** That limit is now stated in §15 rather than left for a reader to infer.

**What v1.3.9 changes.** Three claims this document had asserted but never measured are now measured, and one of them is **false as written**.

**EO-2 is exceeded under hybrid suites — open capacity finding.** §9.7 required deployments to re-measure rather than assume. Measured on a floor-HIGH receipt (one receipt signature plus three attestation signatures, real Ed25519 and real ML-DSA-65): **p99 = 40.7 ms for signature verification alone**, against EO-2's 25 ms end-to-end budget, with **13.2 kB of signatures on the wire versus 256 B classical-only — a 53× increase**. EO-2 is **not** relaxed. It is marked as an **open conflict** (§15) between two normative requirements — CR-6's hybrid floor and EO-2's latency bound — that a deployment cannot satisfy simultaneously on a pure-software verification path. *Measurement caveat, and it matters:* `dilithium-py` is a pure-Python reference implementation; a native ML-DSA (liboqs, AWS-LC) verifies roughly two orders of magnitude faster and would very likely fit. The finding is therefore **implementation-bound, not algorithm-bound** — but a deployment that assumes it away without re-measuring on its own library has assumed exactly what §9.7 forbids assuming. The 53× wire-size increase is algorithm-bound and does not go away with a faster library.

**CL-6 is now tested, and holds.** "Fail closed on partition" could not be exercised against an in-memory ledger that is linearizable by construction. A quorum-replicated ledger with fault injection now demonstrates it: minority sides refuse, majority sides continue to serve, consumption survives a heal, replica loss is tolerated to the quorum bound and refused past it, and quorum intersection is verified **exhaustively** over all 32 splits of a 5-replica set. See `partition_suite.py`.

**A ledger defect was found by that test and fixed (CL-7).** The first origin-binding implementation wrote the proposed value to each reachable replica and *then* compared results. On a partition whose members had not seen a prior binding, it mutated them before detecting the disagreement, leaving the binding permanently split: every later read saw two values and failed closed forever. **One ordinary network event produced a durable denial of service on that Proposal, with no attacker.** The defect is the same shape as the one CL-6 guards against in `claim` — mutate-then-check instead of check-then-mutate — and is fixed by two-phase binding (CL-7 below).

**Canonical CBOR is implemented and validated, closing AT-8a's implementation gap.** RFC 8949 §4.2.1 deterministic encoding with a **validating decoder** that re-encodes what it parsed and rejects any input that is not byte-identical. A permissive decoder silently normalises and reopens Z4. Eight encoding tests cover map-key ordering, non-shortest integer arguments, indefinite lengths, trailing bytes, duplicate keys, floats, and the Z4 two-encodings-one-value case.

**What v1.3.8 changes.** Signature agility and post-quantum readiness, per the French ANSSI doctrine, which insists on **hybridation** — a post-quantum algorithm combined with a well-studied classical one — rather than wholesale replacement, exempting only hash-based signatures (SLH-DSA, XMSS, LMS); the agency stops qualifying products without PQC from 2027 and states that purchasing products lacking PQC after 2030 will not be reasonable. §9.7 (NEW) specifies signature suites, makes hybrid composition **conjunctive** (CR-3), and places the accepted suite floor in the **signed bundle** (CR-4) so a compromised issuer cannot negotiate downward.

**The load-bearing decision is that hybrid means AND, not OR.** A verifier accepting a message when *either* signature validates is strictly weaker than either primitive alone — the attacker picks whichever breaks first, so adding a second algorithm under OR *reduces* security. Annex D Part V mechanizes both directions: `CR3_AND_SurvivesPQBreak` and its classical twin show the conjunction holds under a total break of one primitive; `CR3_OR_CollapsesOnSingleBreak` and `CR3_OR_IsWeakerThanEitherAlone` show the disjunction does not.

**Note on threat timing.** "Harvest now, decrypt later" is a *confidentiality* argument and does not transfer directly here, where signatures protect *authenticity*. Receipts live ≤ 120 s (L-14) and attestations ≤ 60 min (AT-1); a primitive broken in 2035 cannot forge a 2026 receipt the Consumption Ledger already consumed. The exposed surfaces are the **long-lived** ones: the offline bundle signing key, and above all the **§11 audit chain**, whose non-repudiation value is retrospective and measured in years. Deployments **SHOULD** prioritise PQC on audit anchoring and bundle signing over receipt signing, and **MAY** use SLH-DSA standalone there — hash-based, ANSSI-exempt from hybridation, and structurally aligned with a chain that is already hash-based.

**Schema consequence, and why it had to happen now.** AT-8b closes the Attestation Object schema: adding a field is a breaking change requiring a `receipt_version` increment. `alg` is therefore introduced as an AT-1 field **in this revision**, before deployment, rather than discovered as a needed extension afterwards.

**What v1.3.7 changes.** v1.3.6's deferred release let silence stand in for approval on every action class. That is a control whose default outcome equals its approved outcome — it teaches its own users to ignore it, and decays into a log entry while the dashboard continues to report that human oversight exists. v1.3.7 keys the release mode on a new **signed** bundle property, `reversibility.json` (RV-1, absent ⇒ IRREVERSIBLE, mirroring RK-1's absent ⇒ T3): irreversible actions require positive acknowledgement from a non-operator party (DR-9), a sampled fraction of reversible ones inherit that duty so recipients cannot learn that ignoring notifications is always safe (DR-10/DR-11), and silent releases are counted as measurable debt rather than forgotten (DR-12). RV-3 applies the TR-8 rule to the new field before it can be discovered as a defect: the class is recomputed from the signed bundle, never read from the receipt.

**What v1.3.6 changes.** This revision attacks the residual the document has carried unchanged since v1.2.0: **A-8**, the assumption that what an approver sees on screen corresponds to the bytes they sign. A compromised Attestation Presentation Service defeats every cryptographic control in this document, because the approver's signature is authentic and binds the *real* bytes — the lie happens upstream of the signature, where no verification reaches. §12.6's device re-render was the only mitigation and was a SHOULD.

**§9.6 (NEW) — deferred release.** Floor-HIGH actions are verified and then **held**. During a bounded hold window a summary rendered **independently from the canonical bytes** is delivered out-of-band to every attester and the operator; any recipient may repudiate; silence releases. A compromised presentation service can still obtain an approval — but it can no longer reach execution, because it does not control the notification path. **This raises the bar from one compromised component to two independent ones**, which is exactly the threshold INV-1-HIGH defines. It does not close A-8 and is not claimed to: an approver who ignores the notification is not protected, and the mechanism is detection-with-a-veto rather than prevention. Its virtue is that it costs the approver **nothing in the normal case** — no second device, no code to read, no extra click — which is why it survives real operational use where active-verification schemes decay.

**What v1.3.5 changes.** An adversarial pass over v1.3.4's own newest machinery — DS-6 and AT-8a, drafted one revision earlier — found **two defects in the fixes themselves**, consistent with the document's established pattern. (1) **Z3:** DS-6b required the Executor to verify the claimed `origin_nonce` was *a* consumed nonce, which is a membership test, not a pinning test; a compromised KMS substitutes any other consumed nonce, the idempotency key moves, and the action doubles — the RES-8 class, fourth recurrence, in the machinery the Y3 fix introduced. Closed by **DS-6f** (origin read from an immutable ledger binding, never from the receipt). (2) **Z4:** AT-8a fixed the canonicalizer but not the *schema*; an optional field admits two canonical encodings of one semantic object, two ids, two ledger slots, and T-14 amplification reopens through the mechanism Y1b closed. Closed by **AT-8b** (closed object schema). Both are mechanized in Annex D Part III. Additionally: `el1_migrate.py` closes the Z1 migration residual with an exhaustive per-bundle checker, and **ACP-CLASS-001** ships the suite-12 classification artifact that v1.3.4 made mandatory without providing.

**What v1.3.4 changes.** (1) The Y1 fix (AT-8 / TR-10 / step 7b) is **normative**, following independent confirmation that also reproduced Annex D at its published hash and re-ran the mutation control; (2) **Y3 is fixed** — DS-6 separates *action identity* from *authorization identity*, restoring exactly-once across the DS-3 re-drive path, mechanized in Annex D Part II; (3) **Y4 is actually implemented** — v1.3.3 dispositioned it in Annex C prose but never added `operator` to AT-1 or step 7b; (4) **AT-8a** pins the Attestation Object to one canonicalization, because AT-8 moved object hashing onto the binding path; (5) **EL-1** fixes a new finding (Z1): the expression grammar stated no operator precedence, and two evaluators written independently from the prose disagreed on 4.9% of mixed-connective cases; (6) **RK-2a** fixes Z2 — the document's own reference bundle used operators its own grammar did not define; (7) conformance suite **12** makes the RES-8/RES-9 field-and-relation classification table a shipping requirement, since it has now out-performed narrative review twice.

**What v1.3.2 changes.** Three things, all in the assurance story rather than the architecture: (1) the Annex B proof artifact has been **executed** — the published v1.3.1 obligations did not verify as written, and were completed by proof-body work only, with every lemma statement byte-identical (§1.1); (2) mutation testing was added as a negative control, which both confirmed the theorems are load-bearing and surfaced one honesty defect in a proof body (Annex C.3, X4); (3) a differential harness now binds production evaluators — the Policy Engine's and the Executor's TR-8 recomputation path — to the compiled verified model (B.7 item 4). No normative pipeline rule changed.

**Release integrity (new rule, from Annex C.3 X5).** Every published revision of this document is immutable. Any change to normative content or to the Annex B artifact — including a change of verification status — increments the version. A version string maps to exactly one document; two documents bearing the same version string is the collision defect that SR-1 and PB-5 prohibit in the system's own bundles, and the specification is not exempt from its own discipline.

Status is **Draft**, not Final. v1.2.0 was labelled "Final — no further substantive changes anticipated" while containing two single-component breaks of its own headline invariant. This document will not carry a Final label until an implementation exists and §14 suite 11's independent adversarial review — by a party that did not author or revise this document — has been performed and published.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

### 1.1 Verification Status of the Proof Artifact (Normative Disclosure)

The Dafny artifact in Annex B **has been executed**. Verification record:

| Item | Value |
| ------ | ------- |
| Toolchain | Dafny `4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2`, bundled Z3 **4.12.1** (default solver) |
| Command | `dafny verify --function-syntax:4 ACP_RiskFunction_Proof.dfy` |
| Result | `Dafny program verifier finished with 62 verified, 0 errors`, exit code 0 |
| Per-assertion log | 62/62 `Outcome: Valid` (`--log-format text`, published per B.7) |
| Artifact | 772 lines, `sha256:152b97eed5928738e7aedc7d6c4c0392be851d3972bd22201132a3c1a01b1067` |
| Negative controls | 5/5 semantic mutants killed (B.2a); differential validation 20,014 cases, 0 disagreements (B.7 item 4) |

**Disclosure of the path to this result.** The artifact as published in v1.3.1 did **not** verify: `45 verified, 6 errors`, across four lemmas — `EvalRiskLevelAcc_ExtensionBound`, `Transposition_Invariance`, `Permutation_Invariance`, `BreadthFitsInt64`. Completing them required **proof-body work only**: seven helper lemmas were added (`RiskLeq_Reflexive`, `EvalRiskLevelAcc_AgreeFrom`, `Transposition_Invariance_From`, and a `pow2` monotonicity/valuation family) and the four failing bodies were filled in. A signature-level diff (every `lemma`/`function`/`predicate`/`requires`/`ensures`/`decreases` line) against the v1.3.1 inline copy shows **zero deletions and zero modifications — additions only**. Every theorem statement the specification cites is byte-identical to what it cited before verification.

Two verification passes were performed independently — one by the specification's author, one by the reviewing party preparing this revision — and converged on the **same helper-lemma decomposition** without coordination. That convergence is evidence that the proof structure is stable, not an accident of one prover's style. It is **not** a substitute for §14 suite 11: both parties were involved in this document's revision history, so the independent adversarial review remains outstanding and remains a conformance prerequisite.

The v1.3.0/v1.3.1 prediction that `Permutation_Invariance` was the lemma most likely to require manual effort was **correct in both senses**: it did fail as published (its body asserted a prefix lift the verifier could not discharge), and the required work was proof engineering — a downward induction from the swap index to 0 via `Transposition_Invariance_From` — not a statement change.

Any statement in this document of the form "X is proven" now means the corresponding Annex B obligation has been machine-verified under the record above. Model verification remains distinct from production implementation correctness; the differential suite (B.7 item 4) is what binds a deployment's binaries to the verified model, and a deployment claiming conformance **MUST** run it against its own build.

---

## 2. Abstract

Door A is an ingress-to-execution pipeline in which every artifact crossing a trust boundary is validated against a closed, rigid schema, every authorization decision is produced by a deterministic policy engine, and every execution is gated on cryptographic verification of that decision.

The architecture rests on two principles. Every invariant below is a consequence of one or both:

> **P-FLOOR.** Only cryptographically read-only inputs may *lower* computed risk. Any input the runtime or the Context Store can influence may only *raise* it.

> **P-LEDGER.** Authenticity is proven by a signature; freshness and single-use are proven by a linearizable monotonic ledger. Every once-valid artifact — receipt, attestation, bundle epoch — is consumed against that ledger.

The invariant family:

> **INV-1-HIGH.** No single compromised component can cause execution of an action that is **HIGH by signed floor** (§8.3.2), without a fresh, single-use, quorum-satisfying set of attestations bound to that action's canonical hash. Conditional on A-1 through A-8.

> **INV-1-MEDIUM.** No single compromised component *other than the Policy Engine, KMS, or Context Store* can cause an unauthorized MEDIUM-impact state change. A compromised Policy Engine or KMS can cause bounded unauthorized MEDIUM actions (rate-limited by RAD-1/2, detectable via audit replay). A compromised Context Store can cause unauthorized MEDIUM actions by raising or withholding capability facts.

> **INV-1-FLOOR.** No runtime component — including a fully compromised Context Store — can cause a resource to be evaluated at a tier below its signed floor. This is the mechanism by which INV-1-HIGH survives Context Store compromise, and is mechanized as `FloorDominance` (Annex B).

The pipeline achieves grammar-level immunity to instruction injection *for adapters that admit no free text*, deterministic containment of parameter-level abuse, bounded exposure to compositional attacks, and non-repudiable, tamper-evident audit of every decision.

### 2.1 Applicability and Use-Case Coverage

| # | Use case (example) | Ingress shape | Fidelity class (§6.1) | Provider class (§8.8) | Decisive control | Fit |
| --- | ------------------- | -------------- | ---------------------- | ---------------------- | ----------------- | ----- |
| 1 | Computational science / drug-design task submission | Sequences, identifiers, assay parameters | F-HIGH | Static signed entitlements | Grammar + output validation | **Ideal** |
| 2 | Clinical / regulated data submission | Coded records, dosing schedules | F-HIGH | Static signed entitlements | Grammar + floor classification | **Ideal** |
| 3 | Threat-intelligence ingestion | Hashes, indicators, vulnerability IDs | F-HIGH | Workload attestation | Grammar + accumulators | **Ideal** |
| 4 | Batch / pipeline job control | Job enums, bounded input lists | F-HIGH | Workload attestation | Grammar + budget limits | **Ideal** |
| 5 | Industrial / operational setpoint changes | Bounded setpoints, predefined states | F-HIGH | Static or attestation | Parameter risk + receipts + at-most-once (§9.5) | **Strong** |
| 6 | Financial order / risk-parameter submission | Fixed ranges, instrument identifiers | F-HIGH | Static + live sync | Parameter risk + accumulators + at-most-once | **Strong** |
| 7 | Access & entitlement operations (human IT) | Closed operation set on identities/groups | F-HIGH structured, F-LOW if NL-fronted | Static preferred; live sync if churn demands | Floor tier + quorum + confirmation | **Strong** |
| 8 | Network-rule administration | Rule tuples: action, ranges, ports, protocol | F-HIGH structured, F-LOW if NL-fronted | Static or live sync | Parameter risk + quorum + confirmation | **Strong** |
| 9 | Read-only retrieval over curated corpora | Query identifiers, filter enums | F-HIGH | Any | Grammar + egress scoping | **Strong** (low stakes) |
| 10 | Free-form natural-language automation | Arbitrary text | **F-LOW** | Any | Confirmation (§8.6) + capability containment | **Conditional** |

**Reading rules.**

- Rows 1–4: ingress is naturally grammar-shaped and rights are stable. This is the architecture's home ground. Note that these rows also rarely need a model at all (B-5) — the strongest guarantee and the least inference coincide.
- Rows 5–6: the grammar holds, but harm lives in *values and sequences*. The deployment's real work is writing honest risk functions and accumulators. Additionally, these targets are typically non-idempotent; §9.5 applies.
- Rows 7–8: **corrected from v1.2.0**, which assigned these to Door A in one table and Door B in another. They are structured operations (F-HIGH) whenever the operator submits a typed tuple; they become F-LOW only if an NL adapter fronts them. The *provider class* (static vs live sync) is orthogonal to the fidelity class and must not be conflated with it.
- Row 10 is **no longer excluded**. It is admitted at F-LOW with mandatory confirmation (§8.6) and a higher disposition floor (§8.4). See §2.4 for why the exclusion was wrong.

### 2.2 Design Philosophy: Why Containment, Not Correction

> **A language model's input surface is a flaw by design, and the model cannot be patched.**

1. **The vulnerability is the feature.** A model that follows instructions in text cannot distinguish, with certainty, instructions it should follow from instructions it should not — both arrive in the same channel, in the same form. A system whose safety depends on the model *declining* to follow adversarial text has placed its security boundary inside the one component that structurally cannot hold it.
2. **Per-flaw correction does not terminate.** Each newly discovered injection technique would require retraining — slow, non-local, unverifiable, and obsolete at the next model version. Detection-based filtering (one model guarding another) is the same race with an extra participant.
3. **Therefore: never fix the model — remove its authority.** Every security-relevant decision lives in components that can be patched, tested, verified, and reasoned about. When a new attack technique is discovered, the response is a rule change, a schema constraint, or a floor reclassification — a signed bundle deploy, never a training run.
4. **Security claims are structural, never behavioral.** Nothing here asserts what the model *will do*; every guarantee asserts what its output *can reach*.

**Honest positioning (new in v1.3.0).** This premise is not novel. Capability-security literature, and DeepMind's CaMeL specifically, reach the same conclusion. The contribution of this document is not the insight but its *rigorization*: the invariant analysis, the conformance regime, the receipt and ledger construction, and the mechanized proof obligations. Readers evaluating novelty should evaluate those, not the premise.

### 2.3 Explicit Assumptions (Normative Preconditions)

Every invariant is conditional on all of the following. A deployment violating any assumption voids the corresponding guarantee.

**A-1. Client Application Trust.** The client application is trusted to represent the authenticated operator's intent *for F-HIGH adapters without confirmation configured*. Where confirmation is required (§8.6), this assumption is replaced by the operator's signed attestation, and A-1 is not relied upon. This is narrower than v1.2.0's A-1, which assumed client intent fidelity unconditionally.

**A-2. Clock Synchronization.** All receipt-issuing and receipt-verifying components maintain clocks disciplined by NTS (RFC 8915) within ±5 s skew.

**A-3. Cryptographic Primitive Security.** Ed25519, SHA-256, and nonce randomness are assumed secure per published analyses. Post-quantum threats are out of scope.

**A-4. Host Boundary.** The host kernel, hypervisor, and hardware beneath the container boundary are trusted.

**A-5. Formal Verification Baseline.** The risk-function evaluator *model* is total, monotone, and permutation-invariant — machine-verified per §1.1 and Annex B. What remains assumed per deployment is the **binding**: each production evaluator (the Policy Engine's step-8 evaluation and the Executor's TR-8 step-7 recomputation) MUST be validated against the compiled model by the differential suite (B.7 item 4). Until a deployment has run that suite against its own binaries, P-1/P-2 hold for that deployment as implementation requirements, not inherited properties.

**A-6. KMS Independence.** The receipt-signing substrate verifies bundle authenticity and epoch independently of the Policy Engine runtime (§9.1.1). If the KMS accepts bundle metadata from the Policy Engine without independent verification, INV-1-HIGH collapses.

**A-7. Honest Floors (NEW).** Each governable resource's signed floor tier reflects its true minimum sensitivity. **Understating a floor voids INV-1-HIGH for that resource.** This is the load-bearing assumption introduced by the floor/raise model: the architecture guarantees no runtime component can evaluate *below* the floor, but it cannot know whether the floor was set correctly. Floor maintenance is a two-person, offline-key operation (RK-5) precisely because it is where this assumption lives.

**A-8. Attestation Presentation Integrity (NEW).** The Attestation Presentation Service renders the canonical Proposal faithfully to the human, displays floor-derived values rather than Context-asserted ones, and displays the `proposal_hash` being signed. It is part of the TCB (§4.3). If it is compromised, quorum becomes a signature over a screen the humans did not understand.

**A-9. No Cross-Boundary Collusion (NEW — was implicit).** Operators are distinct principals and do not collude across component boundaries. Collusion spanning components (e.g. a Policy Engine operator with a Context Store operator, or two approvers) defeats INV-1-HIGH. v1.2.0 stated this only in §4.4, 130 sections after the invariant it conditions.

### 2.4 Why the Door A / Door B Binary Was Retired (Informative)

v1.2.0 excluded free-text ingress and defined a future "Door B" with a weaker guarantee and a mandatory intent-confirmation step (DB-1). This produced three problems.

First, an **inversion**: for an identical authorized operator, Door B had a mandatory intent check and Door A had none. Against a compromised client, the flagship "strong" door protected the operator *less* than the "weak" one.

Second, a **contradiction**: §2 claimed injection was structurally impossible, while §7.1 justified output-validation weakness by asserting the adversary controls prompt conditioning. Both could not hold for the same pipeline.

Third, a **utility gap**: the rows where the guarantee was strongest (1–4) are rows where a model contributes nothing, and the rows where a model would earn its place (7–8) were assigned to the weaker door.

The resolution: intent fidelity is a *dial*, not a *door*. Confirmation is a risk-proportional control available to any adapter. The strong-ingress case keeps its grammar-level injection immunity; the free-text case is admitted with confirmation mandatory and a raised disposition floor. One core serves both.

---

## 3. Terminology

| Term | Definition |
| ------ | ------------ |
| **Atom** | A single validated input object conforming to exactly one registered Input Schema. |
| **Proposal** | A candidate operation submitted to the Policy Engine. Carries a fidelity class (§6.1). |
| **Ingress Adapter** | A component converting external input into a Proposal, stamping a fidelity class. |
| **Fidelity class** | `F-HIGH` (no free text reaches the Proposal) or `F-LOW` (a translator model produced it). |
| **Input Schema** | A closed, versioned, registered schema defining one admissible input shape. |
| **Policy Engine** | The deterministic component mapping (Proposal, Bundle, Context) → Decision. |
| **Floor tier** | Bundle-signed minimum sensitivity of a resource. Read-only to the runtime. |
| **Raise tier** | Context-Store-served tier assertion. May only increase effective tier. |
| **Effective tier** | `max(floor, raise)`. |
| **Attestation** | A signed human act bound to a `proposal_hash`. Two kinds: **confirmation** (first-party, the operator) and **approval** (second-party, a distinct approver). |
| **Decision Receipt** | A signed, self-contained attestation of a Decision, verifiable by the Executor without trusting the Policy Engine's channel. |
| **Consumption Ledger** | The linearizable single-use registry consuming receipt nonces, attestation IDs, and bundle epochs (§9.3.1). |
| **Executor** | The component holding scoped credentials that performs real-world state changes. |
| **Context Store** | The state substrate supplying operator capabilities, tier raises, and accumulators. |
| **TCB** | The set of components whose compromise defeats INV-1 individually. Design objective: no single element defeats INV-1-HIGH alone (§10). |

---

## 4. Threat Model

### 4.1 In Scope

| ID | Threat | Countermeasure (§) |
| ---- | -------- | --------------------- |
| T-01 | Instruction injection via input | Closed grammar for F-HIGH (§6); capability containment + confirmation for F-LOW (§8.6) |
| T-02 | Adversarial model output | Output validation (§7) |
| T-03 | Parameter abuse within valid syntax | Parameter-sensitive risk (§8.3) |
| T-04 | Compositional attack | Session accumulators (§8.5) |
| T-05 | Policy Engine compromise | Signed receipts + Executor verification (§9) + KMS independence (§9.1.1) |
| T-06 | Executor compromise | Receipt requirement + scoped credentials + audit gap detection |
| T-07 | Policy tampering | Signed bundles, monotonic epoch (§8.2, §8.9) |
| T-08 | Audit tampering | Per-tenant hash chains + external anchoring (§11) |
| T-09 | Receipt replay | Nonce + expiry + consumption ledger (§9.3.1) |
| T-10 | TOCTOU on escalation | Attestation binding + revalidation (§8.6) + execution-time recheck for floor-HIGH (§9.3) |
| T-11 | Confused deputy via capability breadth | Floor tiers + parameter risk (§8.3) |
| T-12 | Schema-registry manipulation | Signed registry, decidable narrowing test (§6.5) |
| T-13 | Client intent misrepresentation | **Now in scope where confirmation is configured** (§8.6). Out of scope only for F-HIGH adapters without confirmation, per A-1. |
| T-14 | **Attestation amplification (NEW)** | One legitimate attestation reused across multiple receipts. Ledger consumption by attestation ID (§9.3.1) |
| T-15 | **Bundle rollback (NEW)** | Replay of a genuine but superseded, more permissive bundle. Monotonic `bundle_epoch` (§8.9 RAD-3) |
| T-16 | **Tier suppression (NEW)** | Falsifying a resource's tier downward to suppress escalation. Signed floor (§8.3.2), `FloorDominance` |
| T-17 | **Induced fail-closed → attestation flood (NEW)** | Tripping fail-closed controls to saturate the human quorum. Queue isolation (§8.6a) + ES-6 monitoring |
| T-18 | **Derived-risk forgery in the receipt (NEW in v1.3.1)** | A signing substrate asserts a lower floor-only risk or a stronger fidelity class than the bundle supports, suppressing the attestation requirement. Executor recomputation (TR-8, §9.3 steps 7/7a) |
| T-19 | **Attestation misbinding (v1.3.3)** | A compromised KMS attaches a genuine quorum raised for proposal P₁ to a receipt for attacker-chosen P₂; signatures verify but are not bound to P₂. Object transmission + binding check (AT-8, TR-10, §9.3 step 7b); mechanized in Annex D. **Fix NORMATIVE in v1.3.4** (independently confirmed). |
| T-20 | **Re-drive duplication (NEW in v1.3.4)** | A lost-outcome (`indeterminate`) floor-HIGH action is re-driven under a fresh attestation id, presenting the target a new idempotency key for an action that may already have committed — a doubled trade or actuator command. Action-identity key (DS-6), TR-10-verified; mechanized in Annex D. |
| T-28 | **Accumulator inflation (NEW in v1.3.10)** | Proposals attributed to a victim operator, then repudiated, increment counters for actions that never executed until a `deny`-effect accumulator locks the operator out. Count at release (AC-5). |
| T-29 | **Pre-anchor audit rewrite (NEW in v1.3.10)** | A compromised audit writer rewrites the record of an executed floor-HIGH action inside the ≤ 10 min anchoring gap, erasing the evidence §11.3 reconciliation depends on. Anchor before release (AU-7). |
| T-30 | **Anchor denial → approver fatigue (NEW in v1.3.10)** | Denying anchoring forces the ATTEST cap to compound with DR-9 until approvers rubber-stamp. Suspend sampling or fail closed (AU-6). |
| T-27 | **Suite downgrade (NEW in v1.3.8)** | A compromised issuer re-signs with a classical-only suite to escape post-quantum protection, or strips one half of a hybrid signature. Bundle-signed suite floor (CR-4), conjunctive composition (CR-3), `alg` signature-covered (CR-5). |
| T-25 | **Reversibility downgrade (NEW in v1.3.7)** | A compromised KMS asserts `REVERSIBLE` for an irreversible action to suppress the DR-9 acknowledgement requirement — the X1 pattern applied to a new field. Executor recomputes the class from the signed bundle (RV-3); receipt value is never read. |
| T-26 | **Notification habituation (NEW in v1.3.7)** | Not an attacker capability but a system effect: if silence always releases, recipients stop reading, and the detection channel decays into a log while appearing operational. DR-9 (silence never releases the irreversible class), DR-10 (sampling), DR-12 (silence is counted). |
| T-24 | **Display lie (A-8, mitigated in v1.3.6)** | A compromised Attestation Presentation Service shows a benign action while the canonical bytes describe a floor-HIGH one; approvers sign authentically and in good faith. No cryptographic control reaches this — the lie precedes the signature. Deferred release (§9.6): an independently rendered summary reaches the same humans out-of-band before execution, and any of them may veto. |
| T-22 | **Origin substitution (NEW in v1.3.5)** | A compromised KMS names a different consumed nonce as a re-drive's origin, moving the idempotency key so the target cannot dedup a floor-HIGH action that already committed. Ledger-pinned origin binding (DS-6f). |
| T-23 | **Attestation encoding split (NEW in v1.3.5)** | An optional Attestation Object field yields two canonical encodings, two ids, and two ledger slots for one attestation, reopening T-14. Closed object schema (AT-8b). |
| T-21 | **Expression parse divergence (NEW in v1.3.4)** | An ambiguous `&&`/` | | ` grammar lets the Policy Engine and Executor parse one bundle rule into different trees, or lets a bundle author's intent diverge silently from evaluated meaning. EL-1 precedence rule; suite 8 parser vectors. |

### 4.2 Explicitly Out of Scope

- **Semantically valid, dual-use domain inputs.** A syntactically valid molecule or trading parameter that is harmful *in the domain sense* is not detectable here. Domain screening (§7.4) is a separate layer deployments in sensitive domains MUST add.
- **Availability.** No availability SLO is specified. **But note:** DoS is not fully severable from safety — see RES-2 (§15), which discloses the induced-fail-closed composition rather than hiding behind this exclusion.
- **Compromise below the container boundary.**
- **Timing side channels in policy evaluation.** v1.2.0 prohibited short-circuit evaluation "because it leaks timing." That claim was contradicted by its own proof artifact and is retired; see §8.3.1.
- **Exactly-once execution against non-idempotent external targets.** Unachievable without target participation; §9.5 specifies what is achievable instead.

### 4.3 Trust Classification

| Component | Trust Class |
| ----------- | ------------- |
| Ingress Adapter (F-HIGH) | Trusted for shape, not for intent |
| Ingress Adapter (F-LOW) / translator model | **Untrusted.** Always. |
| Input / Output Schema Validator | Trusted (deterministic, small, testable) |
| LLM (any provider, any model) | **Untrusted.** Always. |
| Policy Engine | Trusted but **not solely relied upon** (receipts, §9) |
| Context Store | Trusted for *raises* only. **Cannot lower** effective tier (§8.3.2). |
| **Attestation Presentation Service (NEW)** | **TCB.** Per A-8. Compromise defeats quorum. |
| **Bundle Repository (NEW)** | **TCB.** Write-isolated from the Policy Engine host at a boundary stronger than filesystem permissions (§9.1.1). |
| **Consumption Ledger (NEW)** | **TCB.** Compromise permits replay and attestation amplification. |
| Executor | Trusted but **not solely relied upon** |
| Audit subsystem | Trusted for evidence, hardened per §11 |
| Network between components | Untrusted (mTLS REQUIRED) |

### 4.4 Compositional Attack Scope (Normative Boundary)

Explicitly out of scope for the baseline accumulator model: **cross-window composition** (patience attacks spanning window boundaries), **cross-operator collusion** (see A-9 — this now appears as a stated precondition, not only here), and **cross-session persistence** (fresh session credentials reset session-scoped accumulators).

Deployments requiring resistance MUST: (a) extend windows and groupings, (b) raise sensitive **floors** to force quorum, or (c) add workload attestation.

---

## 5. Pipeline Architecture

### 5.1 Normative Data Flow

```
  ┌──────────────────┐        ┌──────────────────┐
  │ ADAPTER: F-HIGH   │        │ ADAPTER: F-LOW    │
  │ typed submission  │        │ translator model  │
  └────────┬─────────┘        └────────┬─────────┘
           │                            │
           └───────────┬────────────────┘
                       │ (1) fidelity class stamped
            ┌──────────▼───────────┐
            │ INPUT VALIDATOR       │  reject → 400 + audit
            │ (closed grammar)      │
            └──────────┬───────────┘
                       │ (2) Atom
        ┌──────────────┴───────────────┐
        │                               │
   LLM-free path                  LLM path (optional)
        │                    ┌──────────────────────┐
        │                    │ MODEL (untrusted)     │
        │                    │ no tools, no network  │
        │                    └──────────┬───────────┘
        │                        raw    │
        │                    ┌──────────▼───────────┐
        │                    │ OUTPUT VALIDATOR      │
        │                    └──────────┬───────────┘
        └──────────────┬───────────────┘
              Proposal │ (3) carries fidelity class
             ┌─────────▼──────────┐
             │ POLICY ENGINE       │──── Context Store (capabilities,
             │ deterministic       │     tier RAISES, accumulators)
             │ tier = max(floor,   │
             │           raise)    │──── Bundle (tier FLOORS, rules,
             │ ALLOW/ATTEST/DENY   │     risk functions — signed)
             └─────────┬──────────┘
                       │ (4) if ATTEST
             ┌─────────▼──────────┐
             │ ATTESTATION GATE    │  confirmation (operator) and/or
             │ presentation in TCB │  approval quorum (distinct parties)
             └─────────┬──────────┘
                       │ (5) attestation set, each with attestation_id
             ┌─────────▼──────────┐
             │ KMS / SIGNING       │  independent bundle + epoch verify
             └─────────┬──────────┘
                       │ (6) Decision Receipt (signed)
             ┌─────────▼──────────┐        ┌────────────────────┐
             │ EXECUTOR            │◀──────▶│ CONSUMPTION LEDGER  │
             │ scoped credentials  │  CAS   │ nonces, attestation │
             │ verifies signature  │        │ ids, bundle epochs  │
             └─────────┬──────────┘        └────────────────────┘
                       │ (7)
             ┌─────────▼──────────┐
             │ AUDIT               │  per-tenant hash chain,
             │                     │  externally anchored
             └────────────────────┘
```

### 5.1a The two doors (Normative principle)

The architecture has exactly two paths out of the model, and their treatment is deliberately asymmetric.

**Door B — text.** The model's only channel is text-in/text-out (B-2). Door B carries no constraint on *content*: the model may be manipulated, injected, jailbroken or simply wrong, and the architecture takes no position on how often that happens. Door B is safe because it is **inert**, not because it is filtered.

This is not a gap. Text is an unbounded set; there is no closed grammar of safe sentences, and any check over it is necessarily statistical. §14's mutation discipline states the consequence: a control for which no falsifying test can be written cannot carry an invariant. **Door B therefore MUST NOT be relied upon for any security property**, and an implementation that adds a content filter and then relaxes a Door A control on the strength of it is non-conformant.

**Door A — action.** Every effect on the world passes Door A: a typed Proposal under the §6 closed grammar, risk recomputed from the signed bundle (TR-8), attestations bound to the action's canonical hash, quorum where the floor requires it, and release. **There MUST be no third route.** Any component capable of causing an external effect on the strength of anything other than a verified Decision Receipt (B-4) is a Door A bypass and a conformance failure.

**Why the asymmetry is principled.** Door A is controllable because actions are a **closed, typed, enumerable** set: each has a declared risk function and reversibility class, so a decision about one is a computation over trusted bytes rather than a judgement about meaning. Door B is uncontrollable for the mirror-image reason. Attempting to control Door B trades a mechanical guarantee for a statistical one; refusing to try, and removing consequence instead, is what makes the guarantee available at all.

This is the parameterised-query argument one layer up. The fix for injection was never better sanitisation of the shared channel — it was ensuring content on that channel could not become a statement. B-2 is that separation: Door B cannot be promoted to Door A.

**Corollary (B-5).** Most work never needs Door A, and much of it never needs the model. The fast path stays fast deliberately: a control plane that taxes cheap, reversible work gets routed around, and a control that is routed around provides nothing.

### 5.2 Boundary Rules (Normative)

- **B-1.** Every artifact crossing an arrow **MUST** be schema-validated at the receiving side, except (6)→(7) which is receipt-verified.
- **B-1a.** The canonical Proposal (or its hash-preimage) **MUST** be transmitted to the Executor alongside the Decision Receipt, over the same mTLS channel, canonicalized identically before hashing (§9.2).
- **B-2.** The model **MUST NOT** have tool access, network egress, function calling, or any channel other than text-in/text-out. Provider-side tool features **MUST** be disabled at the API-request level and this **MUST** be asserted in the audit record for every model call.
- **B-3.** Raw model output **MUST NOT** be transmitted to any component other than the Output Validator, nor logged verbatim into rendering systems without neutralization (§7.3).
- **B-4.** The Executor **MUST NOT** accept any instruction from any channel other than a verified Decision Receipt.
- **B-5.** Many tasks require no model at all. Implementations **SHOULD** prefer the LLM-free path whenever the task is expressible without inference. The model is a cost and a risk, never a default.
- **B-6 (NEW).** The fidelity class **MUST** be stamped by the adapter, carried in the Proposal, bound into the Decision and receipt, and **MUST NOT** be settable by the client.

---

## 6. Layer 1 — Ingress Adapters and Input Validation

### 6.1 Fidelity Classes (Normative)

- **FC-1.** Every adapter **MUST** declare exactly one fidelity class.
  - **F-HIGH**: no free text reaches the Proposal. Every field is a bounded scalar, constrained string, enum, or fixed-shape nested model. Instruction injection into the Proposal is grammatically impossible.
  - **F-LOW**: a translator model produced the Proposal from free text. Injection into the *translation step* is possible by construction; containment rests on capability limits, confirmation, and receipts — never on ingress hygiene.
- **FC-2.** Policy **MAY** condition on fidelity class. For F-LOW Proposals targeting effective tier ≥ T2, policy **MUST** require confirmation (§8.6) and **SHOULD** impose stricter disposition than for an identical F-HIGH Proposal.
- **FC-3.** No security claim may rest on length, encoding, or rate checks at an F-LOW ingress. These are cost and noise controls.
- **FC-4.** F-LOW deployments are limited to single-action, confirmation-gated operations until multi-step decomposition semantics are specified (§15, open problems).

### 6.2 Validator Requirements

- **V-1.** Validation **MUST** reject unknown fields (`extra='forbid'` in Pydantic v2, on every schema). `extra='ignore'` is a conformance failure.
- **V-2.** Free-form containers are prohibited: `dict`, `Any`, untyped `list`, `str` without pattern+length bounds, and `bytes` **MUST NOT** appear in any Input Schema. If a schema "needs flexibility," it is two schemas.
- **V-3.** Every string field **MUST** declare an anchored regular expression over an explicit allowlist character class, and a maximum length.
- **V-4.** Every numeric field **MUST** declare closed bounds (`ge`/`le`).
- **V-5.** Total serialized request size **MUST** be capped **before parsing** (§13).
- **V-6.** Parsing **MUST** use a hardened JSON parser with duplicate-key rejection at **all nesting depths**, depth limit, and no extension syntax. Duplicate keys are a hard reject at any level, never last-wins.
- **V-7.** String inputs **MUST** be NFC-normalized before pattern matching, and the normalized form is canonical downstream. Inputs containing bidirectional controls (U+202A–U+202E, U+2066–U+2069), zero-width characters (U+200B–U+200D, U+FEFF), or code points outside the declared class **MUST** be rejected.
- **V-8.** Closed-world on task types: `task_type` is a `Literal` over the registered set. No dynamic dispatch, no plugins.
- **V-9.** The validator **MUST** be side-effect-free and constant-shape.
- **V-10.** The validator **MUST** refuse to load if any external policy dependency is absent, stale, or fails signature verification against the active bundle.
- **V-11 (NEW).** The envelope union **MUST** be discriminated on `task_type`, and the validator **MUST** reject any envelope whose payload `task_type` disagrees with its `schema_id`.

### 6.3 Reference Schemas (Normative Examples)

These examples now implement V-7, which v1.2.0's examples omitted while V-7 required it.

```python
import unicodedata
from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Literal, Annotated, Union
from ipaddress import IPv4Network

MODEL_CONFIG = ConfigDict(
    extra='forbid',              # V-1
    str_strip_whitespace=False,  # no silent mutation; reject, don't repair
    frozen=True,                 # Atoms immutable after validation
)

_BIDI = {*range(0x202A, 0x202F), *range(0x2066, 0x206A)}
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0xFEFF}

def nfc_guard(v: str) -> str:
    """V-7: normalize first, then reject control/invisible code points."""
    v = unicodedata.normalize('NFC', v)
    for ch in v:
        cp = ord(ch)
        if cp in _BIDI or cp in _ZERO_WIDTH:
            raise ValueError("disallowed_codepoint")
    return v

class StrictBase(BaseModel):
    """All Input Schemas inherit V-7 enforcement."""
    model_config = MODEL_CONFIG

    @field_validator("*", mode='before')
    @classmethod
    def _normalize(cls, v):
        return nfc_guard(v) if isinstance(v, str) else v

class AddUserToGroup(StrictBase):
    task_type: Literal["add_user_to_group"]
    local_part: str = Field(pattern=r"^[a-z0-9._%+-]{1,64}$")
    domain: str = Field(pattern=r"^[a-z0-9.-]{1,255}$")
    resource: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    access_level: Literal["member", "owner"]
    ticket_ref: str = Field(pattern=r"^[A-Z]{2,8}-[0-9]{1,8}$")

    @field_validator("domain")
    @classmethod
    def domain_allowlist(cls, v: str) -> str:
        # V-10: sourced from the signed bundle; refuse to load if absent.
        v = v.lower()
        if v not in ALLOWED_DOMAINS:
            raise ValueError("domain_not_allowed")
        return v

class ModifyFirewallRule(StrictBase):
    task_type: Literal["modify_firewall_rule"]
    rule_id: str = Field(pattern=r"^[a-z0-9-]{1,32}$")
    action: Literal["allow", "deny", "delete"]
    source_cidr: IPv4Network
    destination_cidr: IPv4Network
    port_start: int = Field(ge=1, le=65535)
    port_end: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp", "icmp"]
    ticket_ref: str = Field(pattern=r"^[A-Z]{2,8}-[0-9]{1,8}$")

    @field_validator("port_end")
    @classmethod
    def port_range_sane(cls, v, info):
        if "port_start" in info.data and v < info.data["port_start"]:
            raise ValueError("invalid_port_range")
        return v

    @field_validator("source_cidr", "destination_cidr", mode='before')
    @classmethod
    def strict_network_address(cls, v):
        if isinstance(v, str):
            try:
                return IPv4Network(v, strict=True)
            except ValueError:
                raise ValueError("host_address_not_allowed")
        return v

    # Breadth of CIDR / sensitivity of port is NOT the validator's job.
    # /0 source is syntactically valid. Risk lives in the Policy Engine.

class BatchJobSubmit(StrictBase):
    task_type: Literal["batch_job_submit"]
    job_type: Literal["backup", "report", "cleanup"]
    inputs: list[str] = Field(min_length=1, max_length=100)
    ticket_ref: str = Field(pattern=r"^[A-Z]{2,8}-[0-9]{1,8}$")

    @field_validator("inputs")
    @classmethod
    def each_input_bounded(cls, v: list[str]) -> list[str]:
        import re
        pat = re.compile(r"^[a-z0-9-]{1,32}$")
        if not all(pat.fullmatch(i) for i in v):
            raise ValueError("input_item_malformed")
        if len(set(v)) != len(v):
            raise ValueError("duplicate_inputs")
        return v

# V-11: discriminated union, generated from the registry — not hardcoded.
Payload = Annotated[
    Union[AddUserToGroup, ModifyFirewallRule, BatchJobSubmit],
    Field(discriminator='task_type'),
]

class AtomEnvelope(StrictBase):
    schema_id: str = Field(pattern=r"^[a-z0-9_-]{1,32}$")
    schema_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    schema_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    fidelity: Literal["F-HIGH", "F-LOW"]   # B-6: adapter-stamped
    payload: Payload

    @field_validator("payload")
    @classmethod
    def triple_matches_payload(cls, v, info):
        # V-11: schema_id and payload.task_type must agree.
        if "schema_id" in info.data and v.task_type != info.data["schema_id"]:
            raise ValueError("envelope_payload_mismatch")
        return v
```

### 6.4 Rejection Semantics

- **R-1.** Rejection **MUST** be fail-closed, fast (<5 ms target), and **uninformative to the caller**: a fixed-shape 400 with a coarse reason class and an `audit_id`. Field-level diagnostics go to audit only — precise errors are a grammar-probing oracle.
- **R-2.** Rejected raw input **MUST** be stored hash-only by default, with full capture switchable per tenant under explicit retention policy. Rejected input **MUST NOT** flow to any model.
- **R-3.** Every rejection **MUST** produce an audit record and feed the accumulators.

### 6.5 Schema Registry and Change Control

- **SR-1.** Schemas are content-addressed: `schema_id` + `schema_version` (semver) + `schema_hash`.
- **SR-2.** The registry is part of the signed bundle. The validator **MUST** refuse to start on signature or hash mismatch.
- **SR-3 (REVISED).** Schema changes follow the bundle change-control path. A change is **narrowing** iff the new admissible set is a provable subset of the old, decided over the bounded lattice (character class × length bound × enum set × numeric range):
  - new character class ⊆ old, **and**
  - new max length ≤ old, **and**
  - new enum set ⊆ old, **and**
  - new numeric interval ⊆ old.

  Any change not provably narrowing in **every** dimension is **widening** and takes the distinct-reviewer path. Changes whose direction is undecidable default to widening. v1.2.0 left "narrowing" undefined, permitting a net-widening change (e.g. `^[a-z]{1,10}$` → `^[a-z0-9]{1,8}$`) to self-classify as narrowing and bypass review.
- **SR-4.** At most **32** registered schemas per tenant. A design-pressure limit, not a technical one.
- **SR-5.** Every Atom, Proposal, Decision, and audit record carries the `(schema_id, schema_version, schema_hash)` triple and the fidelity class.
- **SR-6.** A schema unused for 90 days is DEPRECATED; removed after 180. Proposals referencing a removed schema receive DENY (`schema_retired`).

---

## 7. Layer 2 — Model Boundary and Output Validation

### 7.1 The Containment Rule (Rewritten)

v1.2.0 asserted both that injection was structurally impossible and that "the adversary controls the conditioning signal via prompt injection." These are incompatible. The corrected statement distinguishes two mechanisms:

- **Instruction injection** — attacker text is interpreted as instructions by the model. For **F-HIGH** adapters this is eliminated: the prompt is template-assembled (M-3, M-6) from validated, bounded, pattern-constrained fields, so there is no channel through which free text reaches the model. For **F-LOW** adapters it is **possible by construction**.
- **Value conditioning** — the attacker chooses *which* allowlisted values appear in the template, steering generation without injecting instructions. This is **not** eliminated for either class. A field constrained to `^[a-z0-9-]{1,32}$` still lets an adversary choose among ~10^47 strings; the grammar bounds the alphabet, not the semantics.

Output validation therefore constrains what a compromised model can **emit**, not what it can be **conditioned toward**. That residual is bounded by downstream policy (§8), not eliminated by the Output Schema.

- **O-1.** Every model output influencing any downstream component **MUST** validate against a registered Output Schema meeting V-1..V-11.
- **O-1a.** Implementers **MUST NOT** treat output validation as equivalent in strength to input validation.
- **O-2.** Output Schemas are registered, versioned, and signed exactly as Input Schemas.
- **O-3.** A failing output **MUST** be discarded (never repaired, never partially accepted), audited with raw output preserved, and counted in accumulators. Retries **MAY** be attempted up to §13's limit; the retry prompt **MUST NOT** include the failed output.
- **O-4.** For generative tasks, the Output Schema constrains alphabet and bounds, and the artifact flows to domain screening (§7.4), not to the Executor.

### 7.2 Model Invocation Constraints

- **M-1.** Tool/function-calling **MUST** be disabled in the API request; configuration captured in audit.
- **M-2.** Model ID **MUST** be pinned to an immutable dated snapshot from the signed bundle. Floating aliases are prohibited. A model version change is a policy change.
- **M-3.** The prompt **MUST** be template-generated from the canonical Atom only. The template is part of the signed bundle.
- **M-4.** Max output tokens bounded per Output Schema. Truncated output is a validation failure.
- **M-5.** Per-call timeout, per-tenant concurrency cap, per-tenant daily budget REQUIRED. Exhaustion fails closed.
- **M-6.** Templates **SHALL** be logic-less: variable interpolation and static section inclusion only. Turing-complete template engines are prohibited.
- **M-7.** Model versions may be revoked via emergency bundle update: in-flight calls complete under heightened output validation; new calls fail closed for 24 h; the revoked version is permanently barred.

### 7.3 Neutralization for Human-Facing Surfaces

Any surface rendering pipeline data to humans **MUST** treat all fields — including validated ones — as data, never markup: context-appropriate encoding, no HTML interpretation, no terminal escape passthrough. Attestation surfaces **MUST** render from the canonical structure via fixed templates, never echo raw model text. An approver reading attacker-influenced prose is an injection target; T-02 includes humans.

### 7.4 Domain Screening Attachment Point (Informative)

Between Output Validation and the Policy Engine, deployments **MAY** insert a domain-screening stage. Contract: consumes a validated artifact, returns `PASS` or `FAIL(reason_class)`, is versioned in the bundle, and its verdict enters the Proposal as a field policy can rule on. This specification defines the socket, not the screen.

---

## 8. Layer 3 — Deterministic Policy Engine

### 8.1 Determinism Contract

- **P-1.** `Evaluate(Proposal, PolicyBundle, Context) → Decision` is a pure function of its three arguments. No LLM, no randomness, no network I/O, no clock reads inside evaluation — the evaluation timestamp is an *input*.
- **P-2.** Identical arguments **MUST** produce byte-identical Decisions, covered by golden-file replay in CI.
- **P-3.** Every Decision carries its `policy_bundle_hash` and `bundle_epoch`. Decisions are replayable bit-for-bit from audit.
- **P-4.** Default is DENY: no matching rule, unknown capability, unclassified resource, unavailable Context Store — each with a distinct reason code. **Unknown is never LOW.**
- **P-5 (REVISED).** P-1..P-3 hold as machine-verified properties of the Annex B model (§1.1). For production binaries they are enforced by golden-file replay (P-2) plus the differential suite (B.7 item 4), which **MUST** cover both evaluation points TR-8 created: the Policy Engine evaluator and the Executor's floor-only recomputation path. Evaluator drift between the two is exactly what §9.3 step 7a cannot distinguish from KMS compromise, so the differential suite is the control that keeps step 7a's alert semantics clean.

### 8.2 Policy Bundle

```
bundle/
├── manifest.json          # version, epoch, created_at, author, reviewer, expiry
├── rules.json             # decision rules
├── floors.json            # resource tier FLOORS (§8.3.2) — read-only to runtime
├── reversibility.json     # per-action-class reversibility (§9.6 RV-1) — absent ⇒ IRREVERSIBLE
├── notice_targets.json    # who is told when an IRREVERSIBLE action runs below floor-HIGH (§9.6 DR-13)
├── risk_functions.json    # parameter-risk definitions
├── accumulators.json      # session-window rules
├── schemas/               # input + output schema registry
├── templates/             # prompt + attestation rendering templates
├── attesters/             # approver + confirmer public keys, and quorum_k (PB-6, PB-7)
├── provider_selection.json
└── SIGNATURE              # detached hybrid signature over SHA-256 of the canonical bundle tree (PB-8)
```

- **PB-1.** The bundle **MUST** be signed with an offline key held by the security-policy role, distinct from all runtime keys. The engine **MUST** refuse to serve with an invalid or expired bundle (a grace window MAY be configured during which all Decisions are capped at ATTEST).
- **PB-2.** Author and reviewer identities **MUST** differ.
- **PB-3.** The engine holds exactly one active bundle; activation is atomic; in-flight evaluations complete under the bundle they started with.
- **PB-4.** Runtime components — including a fully compromised Policy Engine — possess no key capable of producing a valid bundle signature. Policy is read-only to the runtime **by cryptography**, not file permissions.
- **PB-5 (NEW).** `manifest.json` **MUST** carry a strictly increasing integer `bundle_epoch`. Epochs are never reused or decreased.
- **PB-6 (NEW in v1.3.15 — Normative).** The attester registry **MUST** carry an integer `quorum_k` ≥ 1: the number of **distinct approvals** a floor-HIGH action requires. It is signed policy, inside the bundle tree and therefore inside `policy_bundle_hash`, and it is the **only** authoritative source of that number (AT-9).

  *Rationale.* Until v1.3.15 no clause named a field to hold the threshold, while §9.3 step 7b(iii) required the Attestation Object's count to equal "the bundle rule's" — a comparison against a value the document never defined. An implementation reading the whole reference carefully could not locate the bundle side of that equality, and the reference itself took the count from the object instead. A requirement whose left-hand side is undefined is not a requirement. `quorum_k` = 1 is permitted and is a deployment choice, but it collapses INV-1-HIGH to single-compromise and a deployment choosing it **MUST** disclose that in its residual-risk statement rather than discover it later.
- **PB-7 (NEW in v1.3.15 — Normative). Attester verification keys MUST be pairwise distinct.** No two registry identities may carry the same verification key, compared over the **complete suite** — two identities differing in their classical key but sharing a post-quantum key are not distinct, and treating them as such is CR-3's conjunctive guarantee undone at the registry instead of at the verifier. An engine **MUST** refuse a bundle whose registry violates this, at load, as an invalid bundle under PB-1.

  *Rationale.* AT-2 requires approvers to be "mutually distinct" without saying what distinguishes them, and `quorum_k` counts approvals by identity. A registry mapping two names onto one key therefore lets the holder of one private key produce two signatures over two objects differing only in their attestation nonces, label them with the two names, and satisfy k = 2 alone — INV-1-HIGH defeated by a single compromise, by a route that requires no defect anywhere in the verification path. This is a **well-formedness** property of the bundle, not a check on the quorum path: a registry that cannot support its own threshold is invalid for every component that reads it, and enforcing it only where quorum is counted would leave every other reader believing it sound.

  *Conformance note.* This constraint is **not expressible in JSON Schema** — `uniqueItems` applies to arrays and there is no keyword for uniqueness across the values of a map. Implementations validating the registry by schema alone are non-conformant however cleanly they validate; the check belongs in the loader.

- **PB-8 (NEW in v1.3.15 — Normative). The `SIGNATURE` file carries the DECLARED SUITE and one signature value per primitive that suite requires**, over SHA-256 of the canonical bundle tree. A verifier **MUST** verify it conjunctively under CR-3: the values present must be exactly those the declared suite requires, and every one of them must verify. The declared suite **MUST** be inside the tree hash, and the file itself **MUST NOT** be a member of the tree it covers.

  *Rationale.* Until v1.3.15 the file listing above described this artifact as "Ed25519 over SHA-256 of canonical bundle tree" — naming a single classical primitive — while Part V requires hybrid composition and CR-3 requires it conjunctively. The two statements are not reconcilable, and the file listing is the one an implementer reads while building the bundle. An implementation following it emits a classical-only signature over the highest-leverage artifact in the system and is **CR-3 non-conformant while conforming to the sentence it read**, which is the failure mode a specification is supposed to remove rather than create. The post-quantum leg is absent by construction, so no verifier can detect its absence as tampering.

  Two consequences are stated because both were reached by getting them wrong first. The suite must be **inside** the hash, or an attacker relabels a hybrid bundle as classical, the verifier obligingly requires one primitive, and the downgrade costs nothing — the guarantee CR-3 exists for becomes decorative at the point it is loaded. And the signature must be **outside** the tree, because a member's digest would have to be known before the file existed; excluding it by name at the bundle root, rather than by extension or by suffix anywhere, keeps a nested file of the same name covered.

### 8.3 Parameter-Sensitive Risk

Static per-action risk ("modify_firewall_rule = HIGH") is insufficient: risk is a function of *parameters and targets*, not action names.

- **RK-1.** Every governable resource **MUST** carry a **floor** tier in `floors.json`: `T0` (public/sandbox), `T1` (internal), `T2` (production), `T3` (privileged). Resources absent from `floors.json` **MUST** be treated as `T3`.
- **RK-2.** Risk is computed by deterministic risk functions over the Proposal's parameters and the **effective tier** of its targets.

```json
{
  "risk_functions": [
    {
      "applies_to": "add_user_to_group",
      "base": "LOW",
      "raise_to": [
        {"if": "resource.effective_tier >= T2", "then": "MEDIUM"},
        {"if": "resource.effective_tier == T3", "then": "HIGH"},
        {"if": "access_level == 'owner' && resource.effective_tier >= T2", "then": "HIGH"},
        {"if": "fidelity == 'F-LOW' && resource.effective_tier >= T2", "then": "HIGH"}
      ]
    },
    {
      "applies_to": "modify_firewall_rule",
      "base": "MEDIUM",
      "raise_to": [
        {"if": "action == 'allow' && source_cidr.prefixlen <= 8", "then": "HIGH"},
        {"if": "action == 'allow' && port in SENSITIVE_PORTS", "then": "HIGH"},
        {"if": "destination.effective_tier >= T2 && action != 'deny'", "then": "MEDIUM"},
        {"if": "action == 'delete' && rule.effective_tier == T3", "then": "HIGH"}
      ],
      "constants": {
        "SENSITIVE_PORTS": [22, 23, 445, 1433, 3306, 3389, 5432, 5985, 5986]
      }
    }
  ]
}
```

- **RV-1 (NEW in v1.3.7 — Normative).** Every action class **MUST** carry a **reversibility class** in the signed bundle's `reversibility.json`: `REVERSIBLE` (the action's effect can be undone by a further governed action without external cost) or `IRREVERSIBLE` (it cannot — funds moved, data destroyed, a physical actuator fired, a trade executed). **Action classes absent from `reversibility.json` MUST be treated as `IRREVERSIBLE`.** This mirrors RK-1's absent-⇒-T3 rule for the same reason: an unclassified action is treated as the most dangerous kind, so forgetting to classify fails safe rather than silently downgrading a control.

  *Where this default has effect (CLARIFIED in v1.3.15).* Through v1.3.14 it had effect **only on the deferred path**, because DR-1 scopes that path to floor-HIGH and nothing below HIGH read the class. An unclassified action on a T0 resource therefore defaulted to `IRREVERSIBLE` and then executed exactly as if it had defaulted to `REVERSIBLE` — a fail-safe default that changed no outcome is documentation, not a control. **DR-13 gives it effect on both paths**, and an unclassified action now requires a notice channel or fails closed.
- **RV-2.** Reversibility lives **only** in the signed bundle. There is no Context-Store raise, no runtime override, and no receipt field of record. Downgrading an action class from `IRREVERSIBLE` to `REVERSIBLE` is a policy change of the same severity as lowering a tier floor and **MUST** be subject to RK-5 (author and reviewer distinct from the proposer, offline signing key).
- **RV-3 (TR-8 applied to reversibility).** The Executor **MUST** recompute the reversibility class from the trusted bundle and the canonical Proposal's `task_type`, and **MUST NOT** read it from the receipt. *Rationale:* a receipt-asserted `REVERSIBLE` would suppress the DR-9 confirmation requirement exactly as v1.3.0's forged `risk_level_floor_only` suppressed attestation (X1). Same defect class, new field; enumerated here before it can be discovered later.
- **RV-4.** The recomputed class **MUST** be recorded in audit for every floor-HIGH decision, together with the release mode it selected and whether a human acknowledgement was received.
- **RK-2a (NEW in v1.3.4 — closes Z2).** Every expression in `risk_functions` **MUST** be expressible in the §8.3.1 grammar, and registry admission **MUST** reject any bundle containing an expression that is not. Through v1.3.3 the normative example above used `∩` and `≠ ∅` — set-intersection operators that appear nowhere in the §8.3.1 grammar — so the specification's own reference bundle was not admissible under the specification's own expression language. Named bundle `constants` (e.g. `SENSITIVE_PORTS`) resolve as `Set` literals at admission time and **MUST** be expanded before hashing, so that a constant table change is a bundle change under PB-4/RK-5.
- **RK-3.** Risk functions are monotone escalators: conditions may only raise the level. The final level is the maximum over all matched conditions, making rule interaction order-independent — mechanized as `Permutation_Invariance` (Annex B), which v1.2.0 asserted but did not prove.
- **RK-4.** The expression language is minimal: field references, comparisons, set membership, CIDR prefix arithmetic, tier ordering, boolean AND/OR. No loops, no user functions, no regex in conditions. It **MUST** be total and monotone, embedded via a verified evaluator (Cedar-style) or hand-rolled with mechanized proof.
- **RK-5.** Floors are part of the signed bundle and under two-person change control. **Lowering a floor (e.g. T3→T1) is the single most dangerous policy operation in the system** and **MUST** additionally require author and reviewer identities distinct from the party proposing the change. Raising a floor follows the ordinary path.
- **RK-5a.** RK-5's protection collapses to the security of the offline `policy_signing_key`. Two-person rule is procedural, not cryptographic. Deployments **SHOULD** protect the offline key in an HSM with M-of-N authorization.

### 8.3.2 The Floor/Raise Tier Model (NEW — Normative)

This section resolves v1.2.0's most serious defect: tier data lived in two mutually exclusive places (bundle `classifications.json` under RK-5, and Context Store `tier()` under §8.8), so RK-5's dual control protected a copy that did not feed evaluation, and a Context Store compromise could falsify tier *downward* to suppress escalation entirely.

- **TR-1.** Each resource has a **floor** tier from the signed bundle (`floors.json`), read-only to the runtime by PB-4.
- **TR-2.** The Context Store **MAY** serve a **raise** tier through `tier_raise(resource)`.
- **TR-3.** `effective_tier(r) = max(floor(r), raise(r))`. Absent raise = `T0`.
- **TR-4.** Because risk functions only escalate (RK-3), a compromised Context Store can drive effective tier **up** — producing more attestation, which is safe — and **can never** drive it below the signed floor. Mechanized as `FloorDominance` (Annex B).
- **TR-5.** **"HIGH-impact" is defined as: the risk level computed using `floor(r)` alone, ignoring all raises, is HIGH.** This value depends only on the signed bundle and the Proposal, so no single runtime component can forge it downward. INV-1-HIGH is stated over this definition.
- **TR-6.** The Decision **MUST** record both the floor-only risk and the effective risk. The Executor's HIGH checks (§9.3) key on floor-only risk, **recomputed per TR-8 — never read from the receipt.**
- **TR-8 (NEW in v1.3.1 — Normative).** **Any receipt field that determines whether attestation is required MUST be independently recomputed by the Executor from the signed bundle and the canonical Proposal. Such fields MUST NOT be trusted as transmitted.** This applies to `risk_level_floor_only` and `fidelity`.

  *Rationale.* v1.3.0 placed `risk_level_floor_only` in the receipt (§9.2) and keyed the Executor's quorum requirement on it (§9.3 step 7). Because the KMS signs the receipt, a **single compromised KMS** could emit a receipt for a genuinely floor-T3 action carrying `risk_level_floor_only: "LOW"` and an empty `attestations` array: signature valid, bundle hash and epoch genuine, nonce fresh, and step 7 not requiring quorum because the receipt asserted the action was not floor-HIGH. Step 9's Context recheck would not fire for the same reason. A floor-HIGH action would execute with no attestation under one compromised component — a violation of INV-1-HIGH.

  This was the same defect class as v1.2.0's tier suppression (C2): a security decision keyed on a value the attacker controls. The floor/raise model made tier unforgeable *at the Policy Engine*; v1.3.0 then let the Executor accept the derived risk on trust, relocating the flaw rather than eliminating it.

  The Executor already holds everything needed to recompute: it verifies `policy_bundle_hash` and `bundle_epoch` (§9.3 step 4), so it holds a trusted bundle containing `floors.json` and `risk_functions.json`, and it independently receives the canonical Proposal (B-1a). Recomputation requires no new data flow.

  The same reasoning applies to `fidelity`: a forged `F-HIGH` stamp would suppress the FC-2 confirmation requirement. Fidelity is adapter-stamped (B-6) and bound into the Decision; the Executor **MUST** verify it against the bundle-registered adapter binding for the `schema_id`, not accept the receipt's assertion.
- **TR-10 (NEW in v1.3.3; NORMATIVE in v1.3.4, generalizes TR-8).** TR-8 governs derived *values*; TR-10 governs derived *relations*. **Any claimed binding between two artifacts on which a control decision depends MUST be verified by the consumer from the signed bytes of both artifacts.** A transmitted identifier is a *name* for a binding, not *evidence* of one. The Y1 defect is TR-8's defect one level up: v1.3.1 stopped the Executor trusting a derived *risk value*, but left it trusting a derived *binding* (this signature belongs to this proposal). Implementers extending this specification MUST apply TR-10 to every receipt field that names a relationship, not only to every field that names a value.

- **TR-9.** Consequence, stated plainly: **lowering** a floor is an offline-key deploy under RK-5; **raising** effective tier remains fast via the Context Store. Deployments with volatile downward reclassification must accept deploy latency for that direction. Since downward reclassification is the dangerous direction, this is intended.

*Cost:* assumption A-7 (§2.3). The architecture guarantees no runtime component evaluates below the floor; it cannot know the floor was set honestly.

### 8.3.1 Formal Semantics of the Expression Language (Normative)

**Grammar**

```
Expr       ::= Term (("&&" | "||") Term)*
Term       ::= "(" Expr ")" | Comparison
Comparison ::= Value ("==" | "!=" | "<" | "<=" | ">" | ">=") Value
             | Value "in" Set
             | Value ".prefixlen" "<=" Number
Value      ::= FieldRef | Literal | Number
FieldRef   ::= Identifier ("." Identifier)*
Literal    ::= String | TierLiteral
TierLiteral::= "T0" | "T1" | "T2" | "T3"
Set        ::= "[" Literal ("," Literal)* "]"
```

Static constraints, all of which are modelled in Annex B (v1.2.0 modelled only the second):

- Every FieldRef **MUST** resolve to a field declared in a typing environment derived from the Proposal schema and Context interface.
- Every Set **MUST** be non-empty and contain literals of homogeneous type.
- `.prefixlen` is valid only on fields typed as CIDR in that environment.
- Numeric literals are integers; see AC-1a for width.

**Evaluation rules.** `⟦e⟧(P, Ctx) ∈ {true, false}`.

- **Field resolution:** absent path ⇒ `false` (totality).
- **Comparison:** standard over the values' types; type mismatch ⇒ `false`.
- **Set membership:** `true` iff equal by value to some element.
- **CIDR prefix:** `true` iff prefix length ≤ *n*.
- **Boolean connectives (REVISED):** `⟦e₁ && e₂⟧ = ⟦e₁⟧ ∧ ⟦e₂⟧`, `⟦e₁ || e₂⟧ = ⟦e₁⟧ ∨ ⟦e₂⟧`. **Evaluation order MUST NOT affect the result.** Short-circuit implementation is permitted.
- **EL-1 (NEW in v1.3.4 — Normative, closes Z1). Operator precedence and associativity.** `&&` binds **tighter** than `||`; both are **left-associative**. The grammar production above is therefore refined to:

```
Expr    ::= AndExpr ("||" AndExpr)*
AndExpr ::= Term ("&&" Term)*
```

  *Rationale.* As written through v1.3.3 the production placed `&&` and `||` at one level with no precedence and no associativity rule. Two implementers reading only the specification text produce different parse trees for any mixed expression: a literal left-to-right fold of the flat production yields `((a || b) && c)`, while the C-family default yields `(a || (b && c))`. A prose-derived differential run (`diff_prose.py`, 10,000 cases, two seeds) found **493 disagreements — 4.9%** — with the minimal witness `action != 'deny' || action == 'allow' && action == 'allow'` evaluating to `false` under one reading and `true` under the other.

  This is **not** covered by Annex B: those theorems quantify over an already-parsed `Expr` datatype, so the parser is outside the proof TCB (B.4). It is **not** covered by B.7 item 4 either: that harness generates well-formed triples as ASTs, never as source text, so it cannot observe a parse divergence. Z1 lives precisely in the model↔production gap.

  *Consequences the rule closes.* (a) A Policy Engine and an Executor built independently from this text can compute different floor-only risk for the same bundle; §9.3 step 7a then fires a **critical alert indistinguishable from KMS compromise** (P-5 names this exact confusion as the thing the differential suite must prevent). Safety is preserved — the disagreement fails closed — but the alert channel is poisoned. (b) More seriously, where both evaluators share one parser, no disagreement is observable at all and the *bundle author's* intent silently diverges from the evaluated meaning: a rule intended as `(X && Y) || Z` grading an action HIGH may evaluate as `X && (Y || Z)` and grade it MEDIUM. Nothing in the pipeline detects that; it is an A-7-class governance defect enabled by an ambiguous normative grammar.

  Bundle authoring tools **SHOULD** emit fully parenthesized expressions regardless, and registry admission **SHOULD** warn on any mixed-connective expression lacking explicit parentheses.

> **Retired claim.** v1.2.0 prohibited short-circuit evaluation "because it leaks timing." That prohibition was contradicted by its own Dafny artifact (which used short-circuit `&&`/`||`), and the stated conformance method — value-equivalent differential testing — could not have detected a violation anyway, since short-circuit and full evaluation return identical booleans. Timing side channels in policy evaluation are now explicitly out of scope (§4.2). Deployments requiring data-oblivious evaluation must specify it separately; the guarantee this document makes is *result-order-independence*, which is what soundness actually requires and which Annex B proves.

**Conformance:** implementations **MUST** provide the mechanized proof as part of the conformance report. The model-level proof is executed (§1.1); the deployment-level obligation is re-execution against the shipped artifact hash plus the differential binding of both production evaluators (B.7 item 4).

### 8.4 Evaluation Order (Normative)

```
 1. Schema attestation      — valid (schema_id, version, hash) in bundle   → else DENY
 2. Fidelity admission      — adapter class permitted for this task_type   → else DENY
 3. Action rule lookup      — a rule exists for task_type                  → else DENY
 4. Identity & capability   — operator holds every required capability     → else DENY
 5. Scope constraints       — domains, tenancy, target set membership      → else DENY
 6. Segregation of duties   — operator ∉ excluded roles; operator ≠ auditor→ else DENY
 7. Tier resolution         — effective_tier = max(floor, raise); also
                              compute floor-only risk (§8.3.2 TR-5)
 8. Risk computation        — §8.3; produces LOW/MEDIUM/HIGH
 9. Accumulator evaluation  — §8.5; may raise risk or DENY outright
10. Temporal constraints    — change windows by (action, tier, risk)       → else DENY
11. Disposition             — LOW    → ALLOW, unless confirmation required
                              MEDIUM → ALLOW iff rule.allow_medium and no
                                       confirmation required, else ATTEST
                              HIGH   → ATTEST (never auto-ALLOW)
                              F-LOW and effective_tier ≥ T2 → ATTEST
12. Attester eligibility    — (ATTEST only) eligible pool non-empty and
                              disjoint from operator for approvals         → else DENY
13. Receipt issuance        — §9
```

- **EO-1.** HIGH **MUST NOT** be auto-allowed by any configuration. There is no flag that makes step 11 emit ALLOW for HIGH.
- **EO-2 (REVISED in v1.3.10 — the latency budget is per risk class).** Steps 1–12 target **< 10 ms p99** excluding Context round-trips. End-to-end warm: **< 25 ms p99 for LOW and MEDIUM** decisions; **< 250 ms p99 for floor-HIGH** decisions.

  *Rationale, and why this is not a relaxation.* v1.3.9 measured the floor-HIGH path under the CR-6 hybrid floor at **p99 = 40.7 ms for signature verification alone** (one receipt plus three attestation signatures, real Ed25519 and real ML-DSA-65), against a 25 ms end-to-end budget: two normative requirements, jointly unsatisfiable. The resolution is not to weaken either but to observe that **the 25 ms bound was written for the wrong path**. A floor-HIGH action has already waited for a human quorum to read and approve it, and DR-1 then holds it a further 60 s before release. Optimising 15 ms of verification on a path containing minutes of deliberate human latency is a category error. The 25 ms bound is correct and retained where it matters: the hot path of LOW/MEDIUM decisions that pass without human involvement, whose receipts live 120 s and whose signatures verify in well under a millisecond.

  **No security property is weakened.** Hybrid suites remain mandatory on every path including LOW and MEDIUM (CR-6). Only the latency budget is differentiated, by the same risk class that already differentiates attestation, deferred release, and acknowledgement.

  *Implementation requirement.* The measurement used `dilithium-py`, a pure-Python reference implementation; native ML-DSA (liboqs, AWS-LC) verifies roughly two orders of magnitude faster. Deployments **MUST NOT** ship a reference implementation of a signature primitive in production, independently of whether it meets the budget, and **MUST** publish their own measurement against the class-appropriate bound. The **53× increase in signature bytes on the wire** (13.2 kB vs 256 B for a floor-HIGH receipt) is **algorithm-bound**, does not improve with a faster library, and **MUST** be sized for in transport and storage.

### 8.5 Session Accumulators

```json
{
  "accumulators": [
    {"key": "privilege_grants",        "group_by": ["operator"],          "window": "1h",  "threshold": 5,    "effect": "raise_risk_to:HIGH"},
    {"key": "firewall_allow_breadth",  "group_by": ["operator","session"],"window": "24h", "metric": "sum(2^(32-prefixlen))", "threshold": 65536, "effect": "raise_risk_to:HIGH"},
    {"key": "distinct_T2_resources",   "group_by": ["operator"],          "window": "1h",  "threshold": 10,   "effect": "raise_risk_to:HIGH"},
    {"key": "schema_rejections",       "group_by": ["operator","source"], "window": "10m", "threshold": 20,   "effect": "deny"},
    {"key": "output_validation_fails", "group_by": ["tenant"],            "window": "10m", "threshold": 10,   "effect": "flag"},
    {"key": "batch_input_total",       "group_by": ["operator"],          "window": "24h", "threshold": 1000, "effect": "raise_risk_to:MEDIUM"}
  ]
}
```

- **AC-1.** Accumulators are declared in the bundle: key, grouping, window, threshold, effect.
- **AC-1a (REVISED).** Accumulator metrics **MUST** be computed over arbitrary-precision integers with deterministic semantics. v1.2.0 permitted 64-bit with an "or arbitrary-precision" fallback and asserted a ≤10⁶-term bound that no normative limit enforced (L-05 bounds items *per request*; windows run to 30 days). Arbitrary precision removes the precondition entirely. Fixed-width implementations are permitted only if the deployment proves its own term bound in the conformance report.
- **AC-2.** Accumulator updates are atomic with Decision commit and audit write under `SERIALIZABLE` isolation or equivalent. Inconsistencies are reconciled within 60 s (§11.3). Audit record and accumulator update share a transaction ID.
- **AC-3.** Accumulator state is part of Context (P-1); the snapshot consumed is captured in audit, so replay is exact.
- **AC-4.** Accumulator effects are monotone (RK-3 applies).
- **AC-5 (NEW in v1.3.10 — Normative, closes W1). Accumulators count executions, not decisions.** An increment **MUST** be committed at **release** (§9.6), not at Decision commit. A Decision that is repudiated (DR-4), times out unacknowledged (DR-9), or fails closed at any Executor step **MUST NOT** increment any accumulator. A DS-3 re-drive of one logical action **MUST** increment at most once, keyed on the DS-6 `action_id`.

  *Rationale (W1).* AC-2 bound accumulator updates to Decision commit, correct before v1.3.6 because a committed Decision executed immediately. Deferred release breaks that identity: an action can be decided and never execute. Counting at decision time inflates counters with actions that never happened, and the inflation is **attacker-controllable** — a party able to trigger proposals attributed to a victim operator, each subsequently repudiated, drives that operator's counters over threshold. Where the effect is `deny` (e.g. `schema_rejections`) the result is a targeted denial of service against a legitimate operator, mounted entirely through actions the system correctly refused. Note the shape: the defect was introduced by the DR-*machinery and lived in a section DR-* never mentions.

  *Bounded, stated for completeness:* evasion in the opposite direction — splitting activity across identities to stay under a threshold — **cannot** suppress floor-HIGH attestation, because floor-only risk (TR-5) is computed from the signed bundle alone and ignores accumulator raises entirely. Floor dominance caps this residual as it caps Context Store compromise.

### 8.6 Attestation Protocol (Unified — replaces v1.2.0 §8.6 and DB-1)

Confirmations and approvals are the same object with different attester constraints. This unification is what removes v1.2.0's inversion, in which free-text ingress had a mandatory intent check and structured ingress had none.

- **AT-1 (REVISED in v1.3.4 — closes Y4).** ATTEST creates an **Attestation Object** binding: `proposal_hash`, `policy_bundle_hash`, `bundle_epoch`, `context_snapshot_hash`, floor-only risk, required attester roles and counts, **`operator`**, `expires_at` (≤ 60 min), and a unique **`attestation_id`** = SHA-256 over the canonical CBOR encoding (AT-8a) of those fields plus a 128-bit fresh attestation nonce. `operator` is included so that approver-distinctness (AT-2) and the step-9 capability recheck key on a **signature-covered** value rather than a receipt-body claim; mechanized as `Y4_OperatorTamperDetected` (Annex D).
- **AT-2.** Two kinds:
  - **Confirmation** — first-party. The *operator* re-affirms the canonical Proposal. Required when policy demands it, and **MUST** be required for F-LOW at effective tier ≥ T2. Closes the semantic gap between "what was meant" and "what was proposed."
  - **Approval** — second-party. Attesters **MUST** be distinct from the operator and mutually distinct. Quorum ≥ 2 for floor-HIGH.
- **AT-3.** Attesters **MUST** be shown the canonical Proposal rendered by fixed template (§7.3): full parameter list, **floor tiers and the bundle `rule_id`s that raised the risk** (not Context-asserted values — see A-8), computed risk, fidelity class, the operator's accumulator standing, and the `proposal_hash` being signed. Attesters sign a *hash-identified Proposal*, never a paraphrase.
- **AT-4.** On quorum, the engine **re-runs steps 1–10** against *current* Context before receipt issuance. If capability, floor, raise, accumulator, or bundle state changed such that the Decision would differ, the attestation is void and the Proposal returns to disposition.
- **AT-5.** Expired attestations are void. Partial quorum at expiry is void. **Attestation objects are single-use, enforced by ledger consumption of `attestation_id` (§9.3.1) — not by assertion.** v1.2.0 stated single-use as a property with no enforcing mechanism, permitting attestation amplification (T-14).
- **AT-6.** Deployments **SHOULD** monitor attestation latency and rate per attester. A sustained approval rate above ~95% with sub-minute median latency is the signature of rubber-stamping and **SHOULD** trigger review of which actions genuinely require attestation. A quorum that always says yes is a control that has already failed.
- **AT-7.** **Behavioral assumption warning.** INV-1-HIGH depends on attesters maintaining discriminative review. If attesters converge to rubber-stamping, the mechanical guarantee becomes a behavioral fiction. There is no mechanical fallback; operational monitoring and human governance are the only countermeasures.
- **AT-8 (NEW in v1.3.3; NORMATIVE in v1.3.4, closes Y1).** The receipt **MUST** carry each full **Attestation Object** — all AT-1 fields, including the 128-bit attestation nonce and the object's own `expires_at` — not merely its `attestation_id`. The attester signature is over the canonical encoding of that object. Rationale: the Executor cannot verify that a signature is *bound to the executed proposal* unless it can reconstruct the signed bytes. Transmitting only the id (v1.3.2) reduced binding verification to a claim the KMS asserts and the Executor cannot check — a receipt bearing a genuine quorum raised for proposal P₁ verifies against an attacker-chosen P₂ under one compromised KMS. Mechanized in Annex D (`Y1_CurrentCheckAcceptsMisbinding` shows the v1.3.2 check accepts the misbinding; `Y1_AttackBlocked_Generalized` shows AT-8 rejects it against an attacker holding arbitrarily many observed signatures).
- **AT-8a (NEW in v1.3.4 — Normative, closes Y5.2 on the binding path).** The Attestation Object **MUST** be canonicalized as **canonical CBOR (RFC 8949 §4.2)** for both signing and `attestation_id` derivation — the same canonicalization as the receipt (WE-1/2). JCS (RFC 8785) **MUST NOT** be used for the Attestation Object. Rationale: AT-8 moved object hashing onto the binding path, where the id the ledger consumes is now `SHA-256(canonical(obj))`. Any encoder disagreement between issuer and Executor becomes a freshness and single-use defect in the exact mechanism Y1b closes — two encoders means two ids for one object, so a re-encoded object claims a fresh ledger slot. The dual-canonicalization observation was filed as an informative minor in ACP-AUDIT-001 (Y5.2); AT-8 promotes it to a binding-path requirement. Implementations **MUST** reject any Attestation Object whose received encoding is not the canonical one (non-canonical encodings **MUST NOT** be re-serialized and accepted).
- **AT-9 (NEW in v1.3.15 — Normative). The quorum threshold is RECOMPUTED from the signed bundle, never read from an attestation.** The number of distinct approvals required for a floor-HIGH action **MUST** be taken from `quorum_k` (PB-6). The Attestation Object's `required_count` **MUST NOT** be an input to that decision, in whole or in part, under any circumstance — including the case where every entry agrees on it.

  Separately and **additionally**, every Attestation Object presented **MUST** carry a `required_count` equal to `quorum_k`, and a mismatch **MUST** fail closed with a critical alert. These are two requirements with two purposes and neither substitutes for the other:

  - The **first** is the security requirement. `required_count` is signed by the attester, and an attester is exactly the party under verification, so a verifier reading the threshold from it asks the adversary how large a quorum to demand. Under the §14 suite-12 classification the threshold is class **R**; there is no reading of the method under which it may be **T**.
  - The **second** is a **consent** requirement and belongs to AT-3, not to INV-1-HIGH. `required_count` is part of what the attester was shown and signed, so a mismatch means the humans approved under a policy the engine did not apply. An attester shown "3 approvals required" who signs on that basis has consented to an action three people would review; executing it after two is a real loss of the basis their signature rested on, even though the count enforced was the bundle's and the invariant held throughout. **Do not collapse the second into the first.** They fail closed on disjoint inputs, and an implementation that keeps only the first satisfies INV-1-HIGH while silently executing actions no attester agreed to.

  *Rationale.* This clause exists because its absence was exploited. See the v1.3.15 alert in §1 (a).
- **AT-8b (NEW in v1.3.5 — Normative, closes Z4). The Attestation Object schema is CLOSED.** Every AT-1 field is **REQUIRED**; there are no optional fields, no defaultable fields, and no extension points. An object carrying an unknown field, or omitting any AT-1 field, **MUST** be rejected — never normalized, never defaulted. *Rationale (Z4).* AT-8a pinned the canonicalizer but not the schema. Given any optional field, an object present-as-null and the same object with the field omitted are **each** canonical CBOR, hash to **two distinct ids**, and therefore claim **two ledger slots** — one attestation, consumed twice. T-14 attestation amplification reopens through the very mechanism Y1b closed. Canonicalization rules cannot fix this: the ambiguity is in the field set, not the encoding, so the fix must be schema-level. Mechanized as `Z4_OptionalFieldYieldsTwoIds`. Extending the Attestation Object in a future revision is therefore a **breaking** change requiring a `receipt_version` increment, never an additive one.

### 8.6a Attestation Queue Isolation (NEW — Normative)

Numerous controls cap Decisions at ATTEST when tripped (RAD-2, §8.7.1 anomaly detection, AU-6 anchoring loss, §12.5 NTS loss, PB-1 expiry grace). An adversary who can cheaply trip any of them floods the human queue, and AT-7's rubber-stamping failure follows. v1.2.0 scoped DoS out and never discussed this composition, even though every link in it was specified.

- **AQ-1.** Attestation queues **MUST** be partitioned by floor-only risk. Floor-HIGH items **MUST NOT** share a queue with items escalated only by a fail-closed cap.
- **AQ-2.** When a fail-closed cap is active, items escalated *solely* by that cap **MUST** be marked `cap_escalated` and **MUST** be rate-limited into the queue.
- **AQ-3.** Queue depth and arrival rate per attester **MUST** be monitored; depth beyond a configured bound is a critical alert, not a silent backlog.

### 8.7 Context Store Integrity

The engine's Decisions are only as truthful as its Context. For live-directory-sync deployments, capability data **MUST** be sourced from the authoritative IdP/IGA via authenticated sync with staleness ≤ 5 min for revocations (push preferred). Static-entitlement and attestation providers **MUST** satisfy their own freshness contracts (§8.8). Context reads are snapshot-consistent. A Context Store unreachable or beyond staleness bounds fails closed. All Context mutations are audited. The Context Store **MUST NOT** be writable by the Executor, the model path, or any ingress component.

**Note:** under §8.3.2, Context Store compromise can no longer suppress escalation. It remains able to *withhold* capability facts (causing DENY — safe) or *raise* tier (causing more attestation — safe), and to falsify capability *grants* for MEDIUM, which is INV-1-MEDIUM's disclosed residual.

### 8.7.1 Context Store Hardening (Informative)

- Context Store signing key **SHOULD** be in an offline HSM.
- The Policy Engine **SHOULD** read from a read-only replica with ≤ 5 min replication lag.
- **Mandatory anomaly detection** on capability deltas: >5% of tenant population changed in one sync triggers a critical alert and caps new Decisions at ATTEST pending review, subject to AQ-2.

### 8.8 Context Provider Interface (Provider-Agnostic)

```
has_capability(operator, capability, resource) → bool
tier_raise(resource) → T0..T3          # RAISE only; floor comes from the bundle
snapshot_hash() → sha256
freshness() → age of last authoritative update
```

| Deployment character | Provider class | Freshness contract |
| --------------------- | ---------------- | ------------------- |
| Few operators, contract-driven entitlements | **Static signed entitlement bundle** — changes are deploys | Bundle validity; staleness ≈ 0 |
| Non-human operators, M2M pipelines | **Workload-identity attestation** | Per-request proof; no directory |
| Thousands of operators, rights change daily | **Live directory sync** | ≤ 5 min for revocations, push-based; sync broken → fail closed |

- **CP-1.** Provider selection is declared per tenant in the bundle and is itself a signed, reviewed change.
- **CP-2.** All providers **MUST** honor P-4: unknown operator, unknown resource, or stale freshness resolves to DENY.
- **CP-3.** Evaluation logic is identical across providers; only the source and freshness model differ.
- **CP-4 (NEW).** The provider class is **orthogonal to the fidelity class.** v1.2.0's provider table labelled human-IT operations "Door B," conflating a *provider* property (live sync) with an *ingress* property (free text). A live-sync deployment with typed submission is F-HIGH.

The practical consequence stands: the strongest deployments are the simplest ones. Static signed entitlements eliminate the sync pipeline, the staleness race, and most of the Context Store attack surface in one move.

### 8.9 Signing-Substrate Controls

- **RAD-1.** Per-tenant rate limit: max 100 ALLOW receipts per minute, sliding window.
- **RAD-2.** Burst detection: signing rate beyond 3σ of the 7-day rolling baseline caps that tenant's Decisions at ATTEST for 10 minutes with a critical alert, subject to AQ-2.
- **RAD-3 (REVISED).** **Monotonic epoch binding.** The KMS **MUST** maintain the highest `bundle_epoch` it has ever validated for a tenant, in durable storage, and **MUST** reject any signing request referencing an epoch lower than that value. v1.2.0 used a last-10-hashes history window, which correctly rejected forged and long-obsolete bundles but **permitted replay of a genuine, more permissive bundle from within the window** (T-15). Epoch monotonicity closes that: a superseded bundle is rejected regardless of signature validity.
- **RAD-4. KMS Bundle Independence.** The KMS **MUST** hold its own copy of the `policy_signing_key` public key and **MUST** independently verify the Ed25519 signature of any bundle it consults. It **MUST NOT** accept bundle metadata, epochs, or policy hashes from the Policy Engine runtime without cryptographic verification. On verification failure the KMS **MUST** reject all signing requests until a valid bundle is presented.

---

## 9. Layer 4 — Decision Receipts, Ledger, and Verified Execution

### 9.1 Rationale

If the Executor acts on the Policy Engine's say-so over a trusted channel, the Policy Engine alone can cause execution, and INV-1-HIGH fails. The remedy: **the Executor trusts a signature, not a channel.** A compromised Policy Engine without the signing key produces nothing the Executor will act on; a compromised Executor without a matching receipt produces an execution provably unauthorized in audit.

### 9.1.1 KMS Independence Protocol (Normative)

1. The KMS holds the `policy_signing_key` public key in hardware-protected storage, loaded at initialization by an operator distinct from the Policy Engine administrator.
2. On every signing request, the KMS extracts the claimed `policy_bundle_hash` and `bundle_epoch`.
3. The KMS retrieves the bundle from a **read-only bundle repository** that the Policy Engine runtime cannot write to. **The isolation boundary MUST be stronger than filesystem permissions on a host shared with the Policy Engine** — separate host, separate credential domain, or hardware-enforced. The repository is populated only by the offline signing ceremony and is TCB (§4.3). v1.2.0 introduced this repository without specifying its integrity model, so a Policy-Engine-host compromise could have supplied attacker-chosen bytes to an "independent" verification.
4. The KMS verifies the bundle's Ed25519 signature against the offline public key.
5. The KMS verifies `bundle_epoch` ≥ its durably stored high-water mark, and updates the mark (RAD-3).
6. Only if 2–5 succeed does the KMS sign with the `receipt_signing_key`.
7. On any failure the KMS returns `SIGNING_DENIED` with a critical alert; the Policy Engine **MUST** propagate a DENY.

### 9.2 Receipt Format

Canonical wire representation is **COSE_Sign1 over CBOR** (RFC 8152, RFC 8949) with Ed25519 (RFC 8032). The JSON below is decoded diagnostic form only.

```json
{
  "receipt_version": 2,
  "decision": "ALLOW",
  "proposal_hash": "sha256:…",
  "schema_id": "modify_firewall_rule",
  "schema_version": "1.2.0",
  "schema_hash": "sha256:…",
  "fidelity": "F-HIGH",
  "policy_bundle_hash": "sha256:…",
  "bundle_epoch": 47,
  "context_snapshot_hash": "sha256:…",
  "rule_id": "RULE-002",
  "risk_level_effective": "HIGH",
  "risk_level_floor_only": "HIGH",
  "attestations": [
    {"obj": {"proposal_hash": "sha256:…", "policy_bundle_hash": "sha256:…",
             "bundle_epoch": 47, "context_snapshot_hash": "sha256:…",
             "floor_only_risk": "HIGH", "required_roles": ["net_approver"],
             "required_count": 2, "operator": "op_8842",
             "att_nonce": "b64:…", "expires_at": "2026-08-09T14:55:00Z"},
     "kind": "approval",     "attester": "op_1121", "sig": "…"},
    {"obj": { … }, "kind": "approval",     "attester": "op_3307", "sig": "…"},
    {"obj": { … }, "kind": "confirmation", "attester": "op_8842", "sig": "…"}
  ],
  "tenant_id": "ten_04qf",
  "operator": "op_8842",
  "issued_at": "2026-08-09T14:02:11Z",
  "expires_at": "2026-08-09T14:04:11Z",
  "nonce": "b64:…",
  "audit_id": "aud_01JCM8QK"
}
```

Canonical encoding for hashed structures is RFC 8785 (JCS) for the **Proposal**, and canonical CBOR (RFC 8949 §4.2) for the **receipt and the Attestation Object** (WE-1/2, AT-8a). Per AT-8 the `attestations` array carries the **full Attestation Object**, not merely its id; the id is never transmitted for trust and is recomputed by the Executor (§9.3 step 7b(v)).

> **Authority of `operator` (NEW in v1.3.4).** The top-level `operator` field is **diagnostic only**. The authoritative operator identity for approver-distinctness and the step-9 capability recheck is `attestations[].obj.operator`, which is signature-covered (Y4).

> **Authority of receipt fields (NEW in v1.3.1).** `risk_level_effective`, `risk_level_floor_only`, and `fidelity` are **diagnostic and audit fields only**. They record what the Policy Engine computed, for replay and forensics. They are **NOT authoritative** for any Executor control decision: per TR-8, the Executor recomputes floor-only risk and verifies fidelity from the signed bundle and the canonical Proposal. A receipt whose transmitted values disagree with the Executor's recomputation is a **critical alert** (§9.3 step 7a) — it means the signing substrate is emitting Decisions the bundle does not support.

- **WE-1.** Normative wire format is COSE_Sign1 with Ed25519 over canonical CBOR.
- **WE-2.** The COSE payload is the canonical CBOR encoding of the receipt structure.
- **WE-3.** Implementations MUST provide a reference decoder emitting JSON diagnostic for review, but MUST NOT accept JSON as receipt input.

### 9.3 Executor Verification (Normative Checklist)

Before any state change, the Executor **MUST** verify in order, failing closed on any step:

1. Signature valid under the current `receipt_signing_key` (public key from the signed bundle).
2. `decision == "ALLOW"`.
3. `proposal_hash` equals the hash of the Proposal the Executor independently received and canonicalized. The Executor hashes what it will execute — never "whatever the receipt describes."
4. `policy_bundle_hash` matches the bundle the Executor trusts, and `bundle_epoch` ≥ the Executor's last-seen epoch.
5. `expires_at` not passed; `issued_at` not future beyond ±5 s skew; **`expires_at − issued_at ≤ 120 s` (NEW in v1.3.3; NORMATIVE in v1.3.4, closes Y2: the window *length* is Executor-enforced, not read from the KMS-written value). Violation fails closed with a critical alert.**
6. **`nonce` absent from the Consumption Ledger; claim atomically (§9.3.1).**
7. **Recompute floor-only risk (TR-8)** from the trusted bundle's `floors.json` and `risk_functions.json` applied to the independently-received canonical Proposal, ignoring all Context-Store raises and ignoring the receipt's asserted value. **Verify `fidelity` against the bundle-registered adapter binding for this `schema_id`.** All subsequent attestation requirements key on the **recomputed** values.
7a. **If the recomputed floor-only risk or fidelity disagrees with the value transmitted in the receipt: fail closed and emit a critical alert.** Disagreement means the signing substrate produced a Decision the bundle does not support (T-18 in progress).
7b. **(REWRITTEN in v1.3.3; NORMATIVE in v1.3.4, closes Y1/Y1b/Y4.)** For each attestation entry, which per AT-8 carries the full Attestation Object `obj` and the attester key:
   (i) **verify the attester signature over the canonical encoding of `obj`** against the bundle's attester keys;
   (ii) **verify `obj.proposal_hash` equals the hash computed in step 3** (the executed proposal) — *this is the binding check whose absence is Y1*;
   (iii) verify `obj.policy_bundle_hash` and `obj.bundle_epoch` equal step 4's trusted values, `obj.floor_only_risk` equals the step-7 recomputed value, and **`obj.required_count` equals the bundle's `quorum_k` (PB-6)** — *(REVISED in v1.3.15)*. Through v1.3.13 this read "`obj`'s required roles/counts equal the bundle rule's", naming no bundle field on the right-hand side; AT-9 supplies it. Note what this comparison is **for**: it detects an attester who signed under a different stated threshold than the one being applied, which is an AT-3 consent failure. It is **not** how the threshold is obtained — see (vi);
   (iii-a) **(NEW in v1.3.4, closes Y4)** verify `obj.operator` is identical across every attestation entry, and take the operator identity for distinctness (vi) and for the step-9 capability recheck **from the verified object — never from the receipt body's `operator` field**, which is diagnostic only;
   (iii-b) **(NEW in v1.3.4)** verify the received encoding of `obj` is canonical CBOR per AT-8a; a non-canonical encoding fails closed;
   (iv) verify `obj.expires_at` had not passed at the receipt's `issued_at`;
   (v) **recompute `attestation_id := SHA-256(obj)` per AT-1 — never read the id from the receipt — and claim the recomputed id atomically in the Consumption Ledger** (closes Y1b: there is no transmitted id to substitute);
   (vi) **(REVISED in v1.3.15, closes the §1 (a) defect)** the count of distinct approvals is compared against **`quorum_k`, read from the bundle established in step 4** — never against any value carried by the receipt or by an Attestation Object, and never against `entries[0]` (AT-9). Attester distinctness per AT-2, resolved over registry **keys** and not over names (PB-7); confirmation present if policy required it for the recomputed fidelity and tier.
   Any failure of (i)–(vi) is fail-closed with a critical alert: a validly-signed quorum bound to a *different* proposal means the signing substrate is composing receipts the attesters did not authorize. *(The range was written as (i)–(iv) through v1.3.13, which left (v) and (vi) — the id recomputation that closes Y1b, and the quorum comparison itself — outside the sentence stating their failure mode. That was an editing slip rather than a design choice, and it is corrected here rather than silently: it is precisely the kind of gap this document keeps finding in itself.)*
8. Tenant of the receipt matches the tenant scope of the credentials about to be used.
9. **For recomputed floor-only risk HIGH: re-query the Context Store for capability of the operator established in step 7b(iii-a) on the target. If the capability has been revoked, fail closed.** This closes the issuance→execution window (T-10), during which v1.2.0 honored receipts for up to 120 s after revocation with no recheck. Applied to floor-HIGH only, to bound the added round-trip.

### 9.3.1 Consumption Ledger (Normative — generalizes v1.2.0's nonce registry)

One linearizable ledger consumes three artifact classes under one guarantee.

- **CL-1.** The ledger **MUST** provide linearizability: once an identifier is claimed, all subsequent reads by any Executor in the tenant observe it as claimed.
- **CL-2.** Claims **MUST** use compare-and-swap or an equivalent atomic primitive. If the ledger is unavailable, the Executor **MUST** fail closed.
- **CL-3.** Consumed identifier classes:
  - **Receipt nonces** — one execution per receipt (T-09).
  - **Attestation IDs** — one receipt per attestation (T-14). A second receipt bearing the same attester signatures and a fresh nonce is rejected at step 7.
  - **Bundle epochs** — the high-water mark consulted by RAD-3 (T-15).
  - **Origin bindings (NEW in v1.3.5)** — one immutable `proposal_hash → origin_nonce` per Proposal, claimed atomically with the first receipt nonce (DS-6f, T-22). Unlike the three classes above this is a *binding*, not a consumption: it is written once and read many times, and a rebind attempt **MUST** be a critical alert. Retention is **indefinite** — an expiring origin binding would reopen Z3 for any long-lived re-drive.
- **CL-4.** Retention: ≥ `receipt_validity + 24 h` for nonces and attestation IDs; **indefinite** for epoch high-water marks (an expiring epoch mark would reopen rollback).
- **CL-5.** Multi-Executor deployments **MUST** share the ledger per tenant. Acceptable: strongly-consistent distributed KV with consistent reads, a `SERIALIZABLE` table with unique constraints on `(tenant_id, artifact_class, identifier)`, or a consensus-backed append-only log.
- **CL-6.** Partition behavior: if the ledger cannot confirm absence, the Executor **MUST** fail closed. Availability is a liveness concern; safety is preserved by failing closed.
- **CL-7 (NEW in v1.3.9 — Normative). Ledger writes are check-then-mutate.** Any ledger operation that can fail **MUST** complete its read phase across the quorum before mutating any replica. Specifically, the DS-6f origin binding **MUST** (i) read the binding from a reachable majority, (ii) fail closed if reachable replicas disagree — **never** resolving a security value by majority vote — and (iii) adopt an existing binding where one is found, writing only when none exists. Because any two majorities intersect, a majority always observes a binding a prior majority wrote, so adoption is total rather than best-effort. *Rationale:* the converse ordering leaves a partitioned write permanently split across the replica set, which is a durable denial of service reachable by an ordinary network event and requiring no attacker. Conformance: partition a replica set so that a later majority intersects a prior binding at exactly one node, and assert the prior value is adopted and readable after heal.
- **CL-8 (RENUMBERED in v1.3.15 — was a second CL-7).** Every claim operation (hit and miss) **MUST** be audited with identifier, class, timestamp, and Executor identity.

### 9.4 Execution Constraints

- **EX-1.** The Executor holds **per-action-class, per-tenant scoped credentials**. A wildcard-privileged executor credential is a conformance failure.
- **EX-2.** Executions report `executed | failed | not_attempted | indeterminate` with target correlation IDs into audit.
- **EX-3.** The Executor emits an audit record for **every** verification failure with the offending receipt attached. A signature-invalid receipt reaching the Executor is a **critical alert**.
- **EX-4.** The `policy_signing_key` (offline), `receipt_signing_key` (KMS-held, non-exportable), and attester keys are three distinct key classes. No component holds private keys from more than one class. Bundle forgery requires the offline key; receipt forgery requires the KMS key; attestation forgery requires an attester key *and* is insufficient without a receipt.

### 9.5 Execution Delivery Semantics (NEW — Normative)

v1.2.0 required marking the nonce spent "atomically with execution commit," but execution commits on an **external** system that is not a participant in the ledger transaction. EX-2 quietly conceded the limit ("idempotent where the target API permits") while §2.1 rows 5–6 put non-idempotent, physically and financially consequential targets in scope.

- **DS-1 (REVISED in v1.3.4 — closes Y3).** For targets supporting idempotency keys, the Executor **MUST** use the **action-identity key** defined in DS-6 as the target idempotency key, achieving **exactly-once across re-drives**. Through v1.3.3 this rule named `attestation_id`, which is an *authorization* identifier and is fresh on every re-drive; see DS-6.
- **DS-2.** For targets without idempotency support, the Executor **MUST** default to **at-most-once**: claim the ledger identifier *before* the target call. A crash between claim and completion yields no execution, never a duplicate.
- **DS-3.** At-most-once means an authorized action may be **silently dropped**. Deployments **MUST** implement a reconciliation procedure keyed on the DS-6 `idempotency_key` to detect `indeterminate` outcomes and re-drive them **through a new attestation**, never by replaying the consumed one.
- **DS-4.** At-least-once **MAY** be configured per action class, but **MUST NOT** be configured for floor-HIGH actions on non-idempotent targets. Doubling a trade or an actuator command is a worse failure than dropping it.
- **DS-5.** The delivery class per action class **MUST** be declared in the bundle and recorded in audit.
- **DS-6 (NEW in v1.3.4 — Normative, closes Y3). Action identity is distinct from authorization identity.**
  - **DS-6a.** Every Proposal admitted to execution acquires an **action identity** `action_id = (proposal_hash, origin_nonce)`, where `origin_nonce` is the receipt nonce of the **first** receipt issued for that Proposal. The action identity is fixed at first authorization and **MUST NOT** change across re-drives.
  - **DS-6b.** The target idempotency key is `idempotency_key = SHA-256(canonical(action_id))`. It **MUST** be carried as a distinct receipt field, **MUST** be included in the Attestation Object of every re-drive attestation, and is therefore covered by TR-10 verification: the Executor **MUST** verify the key in the receipt equals the key in the verified Attestation Object and **MUST NOT** accept it as transmitted. A re-drive receipt **MUST** carry the `origin_nonce` of the original receipt, and the Executor **MUST** verify that the original receipt's nonce is recorded as consumed in the Consumption Ledger — a re-drive whose claimed origin was never issued fails closed.
  - **DS-6c.** The *authorization* remains fresh: a re-drive **MUST** carry a new Attestation Object with a new attestation nonce, consumed against the ledger exactly as any other (AT-5, CL-3). Key stability and authorization freshness are independent properties and both hold; mechanized as `Y3_Fixed_RedriveIsDedupped` and `Y3_Fixed_AuthorizationStillFresh` (Annex D).
  - **DS-6d.** Distinct actions **MUST NOT** collide on the key. `Y3_Fixed_DistinctActionsDistinctKeys` (Annex D) discharges this for the DS-6b derivation; a coarser key (e.g. `proposal_hash` alone) would suppress a legitimate *second* execution of an identical Proposal and is a conformance failure.
  - **DS-6e.** Re-drives **MUST** be bounded: a bundle-configured maximum re-drive count per `action_id` (default 3), breach = critical alert and fail closed. An unbounded re-drive loop against an `indeterminate`-returning target is an amplification channel.

  - **DS-6f (NEW in v1.3.5 — Normative, closes Z3). The origin nonce MUST be pinned by the ledger, not claimed by the receipt.** At issuance of the **first** receipt for a Proposal, the Consumption Ledger **MUST** atomically claim an immutable binding `proposal_hash → origin_nonce` alongside the nonce claim itself. On any subsequent re-drive the Executor **MUST** read `origin_nonce` from that ledger binding and derive `idempotency_key` from the value it read. A receipt-carried `origin_nonce` is **diagnostic only**; if present it **MUST** equal the ledger value or the Executor fails closed with a critical alert. The binding is immutable: an attempt to rebind an existing `proposal_hash` to a different origin is a critical alert and fails closed.

    *Rationale (Z3).* DS-6b as drafted in v1.3.4 required the Executor to verify that the claimed `origin_nonce` was "recorded as consumed in the Consumption Ledger." That is a **membership** test: it proves the value is *a* consumed nonce, never that it is *the* origin nonce of this Proposal. A compromised KMS therefore issues a re-drive receipt that passes every check — fresh quorum, honest recomputed risk, valid AT-8 binding — while naming any other consumed nonce as the origin. The idempotency key moves, the target has never seen it, and the floor-HIGH action doubles: exactly the failure DS-6 was written to prevent. Under the RES-8 classification the drafted `origin_nonce` was class **T**, enumerated against no disclosed residual, which by §14 suite 12 is a conformance failure. This is the fourth recurrence of the class (C2 → X1 → Y1 → Z3), again in the machinery the previous fix introduced. Mechanized as `Z3_MembershipCheckDoesNotPinOrigin` (defect) and `Z3_Fixed_DistinctProposalsDistinctKeys` (the fix does not over-collapse).

  *Rationale (Y3).* DS-1 keyed exactly-once on `attestation_id`; DS-3 requires re-driving an `indeterminate` outcome through a **new** attestation, which necessarily carries a new nonce and therefore a new id — a **new idempotency key** presented to the target in exactly the case where the original call may have **succeeded** and only its outcome was lost. The duplicate-prevention mechanism was disabled precisely and only in the recovery path built to cope with lost outcomes, and for floor-HIGH non-idempotent targets (§2.1 rows 5–6) that is the doubled trade or doubled actuator command DS-4 names as the worst failure. Mechanized as `Y3_RedriveDefeatsDedup` (the defect) and `Y3_Fixed_RedriveIsDedupped` (the fix).

---

### 9.6 Deferred Release (NEW in v1.3.6 — Normative, mitigates A-8)

Verification (§9.3) establishes that a receipt is authentic, bound, fresh, and quorum-satisfying. It cannot establish that the approvers **saw** the action they approved. §9.6 adds an independent detection channel between verification and execution.

- **DR-1.** An action whose recomputed floor-only risk is HIGH **MUST NOT** execute at verification time. The **release mode** — silent (DR-7) or confirmed (DR-9/DR-10) — is determined by the recomputed reversibility class and the sampling draw, never by a transmitted value. It enters `pending_release` and is held for a bundle-configured `hold_window` (default 60 s, minimum 30 s). Release before the window has elapsed **MUST** fail closed.
- **DR-2. Independence of the notification path.** During the hold, a human-readable summary **MUST** be rendered **from the canonical Proposal bytes** by a service that shares **no rendering code path** with the Attestation Presentation Service. The notification service **MUST NOT** obtain display text from any component of the approval chain.

  *This is TR-10/RES-8 restated for rendering.* A summary obtained from the party under verification is that party's *claim* about what it displayed, not evidence. Two channels sourced from one renderer are **one channel wearing two hats**, and a single compromise of that renderer lies to both simultaneously. Implementations **MUST** be able to demonstrate path distinctness structurally — a shared formatting library used by both is a conformance failure even when it renders honestly from canonical bytes, because independence must hold under compromise, not merely in the nominal case.
- **DR-3.** The notification **MUST** be delivered to every attester recorded in the verified Attestation Objects and to the operator, over a channel distinct from the one used to obtain approval.
- **DR-4.** Any notified party **MAY** repudiate during the window. Repudiation **MUST** fail closed with a critical alert. Consumed attestations remain consumed: a repudiated action requires a fresh quorum, never a replay.
- **DR-5.** Repudiation **MUST** be accepted only from a party recorded as notified, and the repudiation path **MUST NOT** depend on any component of the approval chain — otherwise a compromised presentation service suppresses the veto it exists to enable.
- **DR-6. The receipt MUST outlive the hold.** Release **MUST** fail closed if the receipt has expired during the window. Since L-14 caps receipt validity at 120 s, deployments **MUST** satisfy `hold_window + processing margin < receipt validity`, and a `hold_window` at or above the L-14 ceiling is an **unsatisfiable configuration** — no legal receipt can outlive it — which **MUST** be rejected rather than silently never releasing. Testing found this interaction directly: a 60 s hold inside a 60 s receipt window expires mid-hold and never releases the honest path.
- **DR-7. Silence releases only where release is recoverable.** For `REVERSIBLE` action classes, and only there, the absence of repudiation during the window releases the action. The mechanism does not assert that any recipient read the notification; it asserts that the opportunity existed and was not taken, and that if it was missed the action can be undone.

  *Why this is not stated as a general rule.* A control whose default outcome is identical to its approved outcome is a control that teaches its own users to ignore it: if doing nothing and confirming produce the same result, recipients stop confirming, and the notification degrades into a log entry while the dashboard continues to report that a human oversight step exists. That is worse than having no step, because it manufactures false assurance. Silence is therefore permitted as an outcome **only** where the cost of a missed detection is bounded by reversibility, and is **forbidden** by DR-9 where it is not.
- **DR-9 (NEW in v1.3.7). Irreversible actions require positive acknowledgement.** Where the **recomputed** reversibility class (RV-3) is `IRREVERSIBLE`, release **MUST** require an explicit acknowledgement from at least one notified party during the hold window. **Timeout fails closed**, and a timed-out action requires a fresh quorum, never a replay. The acknowledgement **MUST NOT** come from the operator: the party who initiated the action carries no independent information about whether the displayed summary was honest — AT-2's approver-distinctness rule, restated for the release step.
- **DR-10 (NEW in v1.3.7). Sampled confirmation on reversible actions.** A bundle-configured fraction of `REVERSIBLE` floor-HIGH actions (default 10%) **MUST** be selected for mandatory acknowledgement under the DR-9 rule. *Rationale:* if recipients can learn that reversible actions never require a response, they stop reading those notifications too, and the detection channel decays for the class that constitutes most of the traffic. Sampling keeps the channel live at a bounded average cost.
- **DR-11 (NEW in v1.3.7). The sampling draw MUST NOT be predictable or influenceable by the requester.** A draw derived from the Proposal, the operator identity, or any requester-supplied value permits grinding inputs until an action falls outside the sample. The draw **MUST** be made by the Executor from a cryptographically secure source, or by an equivalently isolated component, and **MUST** be recorded in audit so the realised rate is verifiable after the fact.
- **DR-12 (NEW in v1.3.7). Silent releases are counted, not forgotten.** Every release without human acknowledgement **MUST** increment a per-tenant counter recorded in audit. Silence is a *measurable debt*, and a deployment whose reversible floor-HIGH traffic releases unacknowledged at a high rate has a visible operational finding rather than an invisible one. Deployments **SHOULD** alert on the rate, not merely record it.
- **DR-8. Undeliverable notification fails closed.** If no recipient is reachable, or delivery to any recipient fails, the action **MUST NOT** release. Executing while the detection channel is absent is executing unwatched.
- **DR-13 (NEW in v1.3.15 — Normative). Irreversible actions below floor-HIGH are notified, not acknowledged.** DR-1 through DR-12 govern the **deferred path**, and DR-1 scopes that path to floor-HIGH. Risk and reversibility are **orthogonal**: risk is recomputed from the target resource's tier floor (TR-5), reversibility is a property of the action class (RV-1), and an action may therefore be `IRREVERSIBLE` and `LOW` at the same time. Before v1.3.15 such an action executed on the fast path with no notification, no acknowledgement, and no record that a human ever existed — RV-1's fail-safe default set a value that nothing below floor-HIGH read. Therefore, where the **recomputed** reversibility class (RV-3) is `IRREVERSIBLE` and the **recomputed** floor-only risk is **below** HIGH:

  1. The Executor **MUST** commit a **notice** of the action — proposal hash, action class, targets, operator, and the recipient set — to its **own durable audit state** *before* the action executes. Executing ahead of the committed notice **MUST** fail closed. This is AU-7's anchor-before-release ordering applied to the fast path, and for the same reason: a record written after the fact can be suppressed by whatever the action enabled.
  2. The recipient set **MUST** be read from the **signed bundle**, keyed by action class. An action class that is `IRREVERSIBLE`, graded below HIGH, and names **no** notice recipients **MUST** fail closed. A notice with no addressee is not a detection channel, and DR-8's rule — executing while the detection channel is absent is executing unwatched — does not become false because the risk grade is lower.
  3. Acknowledgement **MUST NOT** be required, and silence **MUST NOT** block release on this path.

  *Why no acknowledgement, when DR-9 requires one.* DR-9's friction is affordable because floor-HIGH traffic has already paid for a human quorum. Below HIGH there is no quorum, the traffic is the bulk of the deployment, and requiring acknowledgement on every irreversible low-tier action would page a human for routine work at volume. T-26's habituation argument and AT-7's rubber-stamping concession both then apply with full force, and W2 already recorded what saturating approvers produces: not refusal, but assent. The trade taken here is **detection instead of prevention**, chosen deliberately and stated as a weaker guarantee rather than presented as an equivalent one.

  *Why the recipient set lives in the bundle.* A notification service that selects its own audience is certifying its own coverage — RES-8, and exactly the shape of the open notifier-self-certification finding (**T-32** in **ACP-CLASS-001**, where `note.source_path`, `note.from_canonical` and `delivered` are all classified **T**). Naming recipients in the signed bundle puts the audience under RK-5 two-person control alongside the floors it complements, and makes "who would have found out" a property an auditor can read off the signed policy rather than ask the notifier about.

  *Interaction with EO-2, stated plainly.* EO-2 retains a **25 ms p99** end-to-end budget for LOW and MEDIUM decisions, and a synchronous out-of-band delivery does not fit inside it. Two normative requirements that cannot both hold is the DR-6 defect class, so the resolution is stated rather than left to implementers: what DR-13 makes a precondition of execution is the **durable local commit** of the notice, which is Executor-local and inside the budget. **Actual delivery is asynchronous and is not a precondition of execution.** This is a genuinely weaker obligation than DR-8's confirmed delivery, and the difference is the residual: a notice committed and never delivered leaves an audit record and no human. Deployments **MUST** reconcile committed notices against delivery outcomes and **MUST** alert on the undelivered backlog, which is the DR-12 discipline — silence as measurable debt — applied to a channel where silence is the default rather than the exception.

  *Counted separately from DR-12.* Releases under DR-13 are unacknowledged **by construction**, so folding them into DR-12's counter would swamp the signal DR-12 exists to carry: a floor-HIGH reversible action that released on silence is a fact about human attention, and a below-HIGH irreversible notice is not. They **MUST** be counted as distinct audit classes.

  *What this does not do.* It does not make an irreversible low-tier action safe; it makes it **loud**. An attacker who wins an injected `send_email` from an inbox floored at T1 still sends the mail. The claim is only that the send is no longer invisible, and the question of whether that floor should have been T1 relocates onto **A-7**, which §15 concedes is unprovable. Deployments **SHOULD** floor action classes that are both irreversible and externally visible at **T2 or above**, which moves them onto the deferred path and under DR-9; DR-13 is what holds when they have not.

*Residual.* A-8 is **not** closed, and the residual differs by class. For `IRREVERSIBLE` actions the mechanism does not depend on human attention to fail safe: absence of acknowledgement blocks execution (DR-9), so an ignored notification costs availability, not safety. For `REVERSIBLE` actions an ignored notification does release the action, bounded by the fact that it can be undone and by DR-10 sampling and DR-12 counting. In both cases an attacker holding **both** the presentation service and the notification service defeats the mechanism. The claim is precisely: no *single* compromised component reaches an unauthorized floor-HIGH execution through a display lie, and for irreversible actions no *inattentive human* does either. Mechanization is not attempted — acknowledgement is modelled as an input, but whether the acknowledging human actually read the summary is outside any model.

*Cost, stated plainly.* DR-9 reintroduces friction on the irreversible class, deliberately. The v1.3.6 design minimised friction everywhere and was wrong to: a control whose default outcome equals its approved outcome trains its users to skip it. The correct trade is not uniform low friction but **friction concentrated where a missed detection is unrecoverable**, which is why the classification in RV-1 is load-bearing rather than documentary.

### 9.7 Signature Suites and Cryptographic Agility (NEW in v1.3.8 — Normative)

- **CR-1.** Every signed structure — receipt, Attestation Object, bundle manifest, audit anchor — **MUST** carry an explicit `alg` identifying a **signature suite**: a named set of primitives, registered in the signed bundle. An unregistered or unknown suite **MUST** fail closed.
- **CR-2.** A signature under a suite is a **map from primitive to signature value**, one entry per primitive. A bare scalar signature **MUST NOT** be accepted under any suite, even one with a single primitive: format leniency is a downgrade in disguise.
- **CR-3. Hybrid composition is conjunctive.** Verification succeeds only if **every** primitive in the declared suite verifies, and the supplied set **exactly** matches the suite — no missing entries, **no extra ones**. An accepted extra primitive is an undeclared code path chosen by the party under verification.

  *Rationale.* Disjunctive composition is strictly weaker than its weakest member: an attacker breaking one primitive is unconstrained by the other, so adding an algorithm under OR reduces security. Same structure as INV-1-HIGH's quorum — safety comes from requiring all, not any. Mechanized in Annex D Part V in both directions.
- **CR-4 (REVISED in v1.3.15). The accepted suite floor lives in the signed bundle, and is satisfied by CONTAINMENT.** Each deployment declares a minimum suite. A structure's `alg` satisfies the floor **iff the suite it names contains every primitive the floor's suite names**; anything else **MUST** fail closed with a critical alert. Extra primitives are permitted; a missing one never is, whatever is offered in its place. The floor is **never** taken from a transmitted value — this is RK-1's tier floor applied to cryptography, and lowering it is an RK-5 change (offline key, author and reviewer distinct from the proposer).

  *Rationale, and a correction (v1.3.15).* Through v1.3.13 this clause said "ranks below", which presumes a **total order** over suites. There is none. A suite is a *named set of primitives* (CR-1), and those sets are incomparable: `hybrid-ed25519-mldsa65` is `{classical, ML-DSA}` and contains no SLH-DSA, while `slhdsa128s` is `{SLH-DSA}` and contains no classical leg. Neither dominates. Every implementation that read "ranks" built a rank table, and every such table placed hybrid above `slhdsa128s` — so a deployment that set its floor to `slhdsa128s` **precisely because** it wanted a hash-based signature resting on no lattice assumption was served a lattice signature and told its floor was met. That is not a stronger suite being accepted; it is one hardness assumption silently substituted for another, against an offline policy decision CR-4 exists to make un-negotiable. Containment is the only comparison that is well-defined over sets, and it has the further merit of forcing a deployment that genuinely wants "either of these two" to say so as two floors rather than to smuggle it through an ordering.
- **CR-5.** `alg` is an **AT-1 field** and therefore signature-covered: an issuer cannot rewrite the suite without invalidating the object. It is likewise covered by the receipt signature.
- **CR-6.** Deployments **SHOULD** register `hybrid-ed25519-mldsa65` (FIPS 204) as the floor for receipts and attestations, and **SHOULD** use SLH-DSA (FIPS 205) for audit anchoring and bundle signing.
- **CR-7.** Suite migration is **forward-only**: the floor may be raised at any epoch; lowering it is an RK-5 change. A deployment **MUST** verify structures signed under a *higher* suite than its floor.

*Performance note.* ML-DSA-65 signatures are roughly two orders of magnitude larger than Ed25519, and a floor-HIGH receipt now carries full Attestation Objects (AT-8) each hybrid-signed. Receipt size and verification cost both rise materially. Deployments **MUST** re-measure against EO-2 (< 25 ms p99 end-to-end warm) rather than assume the budget holds. This document does not relax EO-2: a deployment that cannot meet it under hybrid suites has a capacity finding, not a licence to downgrade.

## 10. Invariant Analysis (Single-Component Compromise)

Conditional on A-1 through A-9.

| Compromised component | What the attacker gains | INV-1-HIGH | Why the bound holds |
| ----------------------- | ------------------------ | ----------- | --------------------- |
| Client / ingress adapter | Submit arbitrary bytes; for F-HIGH, arbitrary authorized Atoms | **No violation** *if confirmation is configured*; otherwise per A-1 the operator is authorized and intent is out of scope | Closed grammar rejects non-conforming shapes; floor-HIGH still requires attestation. Where confirmation is required, the operator's own signature is needed and a compromised client cannot produce it. |
| Model / translator | Arbitrary output content | No violation | No tools, no egress (B-2); output must pass a closed Output Schema; a valid-shaped malicious Proposal still faces capability, risk, accumulator checks, and — if floor-HIGH — quorum. |
| Input/Output Validator | Pass-through of malformed artifacts | No violation | Policy Engine re-attests schema (step 1) via bundle-registered hashes; Executor hashes the canonical Proposal itself. |
| Policy Engine | Emit arbitrary Decision content | **No violation.** MEDIUM auto-allows bounded by RAD-1/2, detectable via replay. | Cannot forge attester signatures; cannot alter the bundle (PB-4); **cannot reuse an attestation — `attestation_id` is ledger-consumed (CL-3)**; cannot induce signing under a superseded bundle (RAD-3 epoch monotonicity). |
| KMS / signing substrate | Forge receipts for arbitrary Decisions, including forged derived-risk and fidelity fields | **No violation.** MEDIUM forgery possible for the current bundle. | Cannot forge attester signatures; **cannot replay a valid attestation onto a second receipt (CL-3)**; epoch high-water mark is durable; **cannot suppress the attestation requirement by asserting a lower floor-only risk or a stronger fidelity class, because the Executor recomputes both from the signed bundle (TR-8) and fails closed on disagreement (§9.3 step 7a).** In v1.3.0 this row was wrong: derived risk was read from the receipt, so a single KMS compromise could execute a floor-HIGH action with no attestation. **In v1.3.2 this row was wrong again, for the adjacent reason (Y1): it answered the T-14 *replay* question ("cannot replay a valid attestation onto a second receipt") and never asked the *binding* question. CL-3 guarantees one receipt per attestation, not the *right* receipt; first-use misbinding is not replay. Closed in v1.3.4 by AT-8 binding verification — the KMS cannot attach a quorum raised for P₁ to a receipt for P₂ because the Executor reconstructs and checks the signed bytes.** |
| **Context Store** | Falsify capabilities; assert tier raises | **No violation.** INV-1-MEDIUM violated. | **Cannot lower effective tier below the signed floor (TR-4, `FloorDominance`), so it cannot suppress the escalation trigger.** It can raise tier (more attestation — safe) or withhold capability (DENY — safe). This is the v1.2.0 break that is now closed by construction rather than by argument. |
| **Attestation Presentation Service** | Misrepresent the Proposal to attesters | **Violation possible — disclosed, not denied.** | Per A-8 this component is TCB. Baseline mitigations: bundle-signed templates, floor-derived display values, `proposal_hash` shown. Full mitigation requires device-side re-render (§12.6), which is a SHOULD, not baseline. |
| **Consumption Ledger** | Permit replay / attestation reuse | **Violation possible — disclosed.** | TCB per §4.3. CL-1/CL-2 require linearizability and fail-closed; a ledger that falsely reports "absent" reopens T-09 and T-14. Mitigate by consensus-backed implementation and CL-8 auditing. |
| **Bundle Repository** | Supply attacker-chosen bundle bytes to the KMS | **No violation** *if §9.1.1 step 3 isolation holds* | Signature verification against the offline public key still fails for forged bundles; epoch monotonicity blocks genuine-but-superseded ones. |
| Executor | Act on target systems | No violation | Only within per-action-class scoped credentials; any act without a matching verified receipt is provable in audit by absence; blast radius = one credential scope. |
| Audit subsystem | Suppress/alter evidence | No violation | Per-tenant hash chains with externally anchored heads: suppression breaks the chain, alteration breaks anchored hashes. |
| Attester (one) | One malicious attestation | No violation | Quorum ≥ 2 with distinctness for floor-HIGH. |

**Honest residual.** INV-1-HIGH is robust to any single compromise of the *original* component set, and the two v1.2.0 breaks (tier suppression, attestation amplification) are closed structurally. The cost is that three components have been **added** to the TCB — the Attestation Presentation Service, the Consumption Ledger, and the Bundle Repository — and compromise of the first two does defeat INV-1-HIGH. This is not a regression: those components existed in v1.2.0 as unstated dependencies (HA-1, HA-2) and were doing the same load-bearing work while absent from the trust table. Naming them makes the residual auditable.

INV-1-MEDIUM remains violated by single compromise of Policy Engine, KMS, or Context Store, bounded by rate limits and detectable by replay. Two-component collusion exceeds the stated invariant; deployments needing resistance should raise sensitive **floors** to force quorum and add attestation (§12.4).

---

## 11. Audit Subsystem

### 11.1 Record Content

Every pipeline event produces one record containing: event class, tenant, session, operator, fidelity class, all relevant hashes (`raw_input_hash`, `proposal_hash`, `policy_bundle_hash`, `bundle_epoch`, `context_snapshot_hash`, receipt nonce, attestation IDs), floor-only and effective risk, Decision fields, and a monotonic sequence number.

### 11.2 Chain Construction

**Hash notation for this section (NEW in v1.3.15 — Normative).** Throughout §11, `H(x)` denotes the ASCII string `"sha256:"` followed by the SHA-256 digest of `canonical(x)` rendered in **lowercase hexadecimal** — 64 hex characters, 71 characters in total. `canonical()` is the single canonical encoding required by AT-8a (§8.6) — canonical CBOR, RFC 8949 §4.2 — the same one used for signing and id derivation everywhere else in this document. Chain values are carried, stored, anchored **and fed forward as that string**, never as the 32 raw digest bytes. The type is pinned here because it was not pinned before, and an implementer who fed forward raw bytes built a different chain while following the text.

- **AU-1 (REVISED in v1.3.15 — Normative).** Chains are per-tenant.
  `chain_hash_n = H({"prev": chain_hash_{n-1}, "record": record_n})` — the canonical encoding of a **two-key map** whose keys are exactly `prev` and `record`. The key names are part of the preimage. `chain_hash_0` is defined by AU-8.

  *Rationale, and a correction (v1.3.15).* Through v1.3.13 this clause read `SHA-256(chain_hash_{n-1} ‖ canonical(record_n))` — a **concatenation**, which is the conventional formulation and was wrong here for a structural reason. `canonical()` is this document's **one** encoding rule; `‖` is a **second** one, expressing a framing discipline that no canonicaliser covers, no conformance suite exercises, and no vector can express. That is precisely the encoding-split defect AT-8a (§8.6) exists to prevent, introduced by the clause that defines the tamper-evidence chain. Putting the whole preimage through `canonical()` removes the second rule rather than documenting it. **The clause moved, not the implementations**, and the reasoning is recorded because the default runs the other way: this document is the normative source and an implementation disagreeing with it is the thing that is wrong. The exception is argued here rather than taken silently.
- **AU-2.** `chain_hash` carries a UNIQUE constraint; `previous_hash` is a foreign key; `(tenant_id, seq)` is UNIQUE and gapless. Inserts append under `SERIALIZABLE` or single-writer-per-tenant discipline.
- **AU-3.** **External anchoring is REQUIRED** at ≤ 10 min intervals and at every bundle activation, using cryptographic primitives: a public transparency log with inclusion proofs, a threshold signature from ≥3 independent parties, or RFC 3161 timestamping. WORM storage MAY be a durability layer but **MUST NOT** be the sole anchor. An unanchored in-database chain is tamper-*decorated*, not tamper-*evident*.
- **AU-3a.** Every anchor **MUST** be independently verifiable by any party holding the anchor public keys.
- **AU-4.** Anchors are verified on schedule by a process outside the production trust domain; a head failing to extend a previously anchored head is a critical integrity alert.
- **AU-5.** Retention: Decisions, receipts, attestations, anchors ≥ 24 months or per regulation, whichever is longer.
- **AU-7 (NEW in v1.3.10 — Normative, closes W3). Floor-HIGH executions MUST be anchored before release.** The audit record of a floor-HIGH Decision **MUST** be covered by an external anchor before the action is released (§9.6); release **MUST** fail closed otherwise.

  *Rationale (W3).* AU-3 anchors on a ≤ 10 min schedule while a floor-HIGH action is verified, held 60 s, then executed. An execution can complete up to ten minutes before its record is anchored, and in that window the chain is — in AU-3's own words — tamper-*decorated*, not tamper-*evident*. A compromised audit writer rewrites the record of an executed floor-HIGH action before any anchor covers it, defeating §11.3 reconciliation, which is the mechanism by which several disclosed residuals (Y1's included) are said to be *detected* rather than prevented. **Detection that can be erased is not detection.**

  *This costs no new latency,* which is why it belongs here and not in future work: DR-1 already holds every floor-HIGH action 60 s, and that window is idle. Anchor unavailability during the hold is a DR-8-class condition — fail closed, never release unanchored.
- **AU-8 (NEW in v1.3.10 — closes Y5.1; TYPE PINNED in v1.3.15). Chain genesis is specified.** `chain_hash_0 = H({tenant_id, created_at, bundle_epoch, schema_version})` over a **tenant-creation record**, using the `H` of AU-1's notation — so genesis and every subsequent link carry the same type, anchored **immediately** on tenant creation, not on the ≤ 10 min schedule. *Rationale:* without an anchored genesis, deletion of an entire tenant chain is detectable only after the first scheduled anchor, so a chain destroyed inside its first ten minutes leaves no evidence it existed.
- **AU-6 (REVISED in v1.3.10 — closes W2).** If anchoring is unreachable, the system **SHALL** continue chaining internally but **SHALL** cap new Decisions at ATTEST until anchoring resumes, subject to AQ-2. Critical alert immediately. Gap records anchor in one batch on restore. **The ATTEST cap MUST NOT compound with DR-9 into unbounded human load (W2):** during an anchoring outage a deployment **MUST** either (i) suspend DR-10 sampling, so only genuinely irreversible actions demand acknowledgement, or (ii) fail closed entirely for the affected tenant. *Rationale:* an attacker denying the anchoring service otherwise forces every action through human quorum **and** human acknowledgement at once. That is RES-2 composing into safety rather than mere availability — the predictable outcome of saturating approvers is not refusal but rubber-stamping, degrading precisely the control DR-9 exists to provide. An availability attack that manufactures approver fatigue is a safety attack with one extra step.

### 11.3 Reconciliation

A scheduled job **MUST** reconcile:
(a) every execution record ↔ exactly one valid receipt (orphan executions = critical);
(b) every floor-HIGH receipt ↔ attestations satisfying its rule;
(c) **every `attestation_id` ↔ exactly one receipt and at most one execution** (NEW — the check whose absence permitted T-14);
(d) **every signing event ↔ a `bundle_epoch` ≥ all prior epochs** (NEW — rollback detection);
(e) sampled Decisions re-derived via replay ↔ recorded Decisions (mismatch = critical);
(f) **`indeterminate` execution outcomes surfaced for DS-3 handling** (NEW);
(g) **every floor-HIGH execution record ↔ an anchor covering it, dated at or before release** (NEW in v1.3.10 — AU-7 enforcement);
(h) **every accumulator increment ↔ a released execution** (NEW in v1.3.10 — AC-5 enforcement).
Findings are themselves audited. **Reconciliation runs in the anchor-verifier's trust domain (AU-4), never the production domain** — otherwise its findings are written to the chain it audits by a party inside the domain under suspicion.

---

## 12. Deployment Requirements

- **D-1.** Tenant separation: dedicated containers per tenant for ingress/validation/engine, dedicated per-tenant database schemas, dedicated per-tenant executor credentials. Container isolation is a *soft* boundary and **MUST NOT** be represented as hardware isolation in any external claim.
- **D-2.** The model path has **no route** to the Executor network segment, the Context Store, the Consumption Ledger, or the audit database. Enforced by network policy, verified by test.
- **D-3 (NEW).** The Bundle Repository **MUST** be isolated from the Policy Engine host per §9.1.1 step 3.
- **12.2 Transport.** mTLS on every inter-component link; SPIFFE-style workload identity RECOMMENDED. Receipts remain REQUIRED even over mTLS — channel security ≠ authorization proof.
- **12.3 Keys.** Rotation: receipt keys ≤ 90 days; bundle keys ≤ 1 year; rotation events are bundle changes, audited and anchored.
- **12.4 Attestation Roadmap (Informative).** Policy Engine and Executor in confidential VMs (SEV-SNP, TDX) with remote attestation; receipt verification extended to check engine attestation evidence. None of this changes the wire formats.
- **12.5 Time Synchronization.** All receipt-issuing and verifying components **MUST** use NTS (RFC 8915). If unavailable, cap Decisions at ATTEST until restored, subject to AQ-2. Skew allowance ±5 s.
- **12.6 Attestation Device Rendering (Informative, SHOULD for high assurance).** Attesters **SHOULD** re-render the Proposal from canonical bytes on a device distinct from the Presentation Service and compare the displayed `proposal_hash`. This reduces A-8 from a trust assumption to a detection control.
- **12.7 Capability-Scoped Execution (Informative).** Executors **SHOULD** implement action handlers as WebAssembly components with WASI capabilities scoped per receipt action class, granting no ambient authority.

---

## 13. Limits and Constraints (Normative)

| # | Constraint | Value | Enforcement point |
| --- | ------------ | ------- | ------------------- |
| L-01 | Max request size (transport) | 32 KiB | Reverse proxy, pre-parse |
| L-02 | Max JSON nesting depth | 8 | Parser |
| L-03 | Max fields per schema | 24 | Registry admission |
| L-04 | Max string field length | 2,048 chars. **No exceptions.** | Schema |
| L-05 | Max list length / items per request | 100 / 1,000 | Schema / validator |
| L-06 | Registered Input Schemas per tenant | 32 | Registry |
| L-07 | Registered Output Schemas per tenant | 32 | Registry |
| L-08 | Input validation latency | < 5 ms p99 | SLO, tested |
| L-09 | Policy evaluation latency (excl. Context I/O) | < 10 ms p99 | SLO, tested |
| L-10 | End-to-end decision latency (warm Context) | < 25 ms p99 | SLO, tested |
| L-11 | Model max output tokens | per Output Schema, ≤ 8,192 | API request |
| L-12 | Model call retries on output-validation failure | 2 | Pipeline |
| L-13a | LLM-path model calls per tenant per day | bundle-configured; fail closed | Engine |
| L-13b | LLM-free-path model calls | exempt | Engine |
| L-13c | Per-operator LLM-path reserve | ≥10% of tenant budget | Engine |
| L-14 | ALLOW receipt validity | ≤ 120 s | **Executor (§9.3 step 5)** — window *length* enforced, not read from the receipt |
| L-15 | Attestation window | ≤ 60 min | Attestation object |
| L-16 | Approval quorum for floor-HIGH | ≥ 2, distinct, ≠ operator | AT-2 |
| L-17 | Nonce size / ledger retention | 128-bit / ≥ receipt validity + 24 h | Ledger (CL-4) |
| L-18 | Context capability staleness (revocations) | ≤ 5 min | Context sync |
| L-19 | Audit anchor interval | ≤ 10 min | Anchoring job |
| L-20 | Clock skew allowance | ± 5 s (NTS-disciplined) | Executor |
| L-21 | Accumulator windows | as declared; max window 30 days | Bundle |
| L-22 | Policy bundle expiry | ≤ 90 days | Manifest |
| L-23 | **Attestation queue depth per attester (NEW)** | bundle-configured; breach = critical alert | AQ-3 |
| L-24 | **Bundle epoch (NEW)** | strictly increasing integer, never reused | Manifest, KMS high-water mark |
| L-25 | **Re-drive count per `action_id` (NEW)** | bundle-configured, default 3; breach = critical alert, fail closed | Executor (DS-6e) |
| L-26 | **Attestation Object encoding (NEW)** | canonical CBOR (RFC 8949 §4.2); non-canonical rejected; closed schema, all fields REQUIRED | Executor (AT-8a/AT-8b) |
| L-27 | **Origin binding (NEW)** | one immutable `proposal_hash → origin_nonce` per Proposal; rebind attempt = critical alert | Consumption Ledger (DS-6f) |
| L-28 | **Hold window (NEW)** | default 60 s, min 30 s; `hold + margin < receipt validity`; ≥ L-14 ceiling = unsatisfiable config, reject | Executor (DR-1, DR-6) |
| L-29 | **Confirmation sampling rate (NEW)** | bundle-configured, default 10% of REVERSIBLE floor-HIGH; draw from CSPRNG, recorded in audit | Executor (DR-10, DR-11) |
| L-30 | **Unacknowledged release counter (NEW)** | per tenant, per epoch; recorded in audit, SHOULD alert on rate | Audit (DR-12) |
| L-31 | **Signature suite floor (REVISED v1.3.15)** | declared in signed bundle; forward-only; an `alg` whose suite does not CONTAIN every primitive the floor names = critical alert | Executor (CR-4, CR-7) |

---

## 14. Conformance

An implementation is **Door A Conformant** iff it satisfies every MUST/MUST NOT in §§2–15 and passes the following suites, which **MUST** ship with the implementation:

1. **Grammar suite** — per schema: accepted canonical vectors; rejected vectors for every field boundary (length ±1, range ±1, pattern near-misses), unknown-field injection, duplicate keys at all depths, depth bombs, **Unicode confusables/bidi/zero-width (V-7)**, oversize pre-parse, **envelope/payload `task_type` mismatch (V-11)**.
2. **Determinism suite** — golden-file replay: recorded (Proposal, bundle, Context) triples re-evaluate to byte-identical Decisions across versions and platforms.
3. **Receipt suite** — Executor rejects: bad signature, wrong key epoch, expired, future-dated, spent nonce, proposal-hash mismatch, bundle-hash mismatch, **lower bundle epoch**, missing/insufficient/duplicate attestations, **reused `attestation_id`**, cross-tenant receipt, **a validly-signed receipt asserting `risk_level_floor_only` below the bundle-derived value (T-18), and a validly-signed receipt asserting `fidelity: "F-HIGH"` for a Proposal from an F-LOW-bound adapter.** The last two MUST fail closed with a critical alert, not merely be logged. **NEW (v1.3.4, NORMATIVE): a validly-signed receipt carrying genuine attestation signatures whose Attestation Objects bind a *different* `proposal_hash` than the executed proposal (Y1) MUST fail closed with a critical alert; a receipt whose transmitted `attestation_id` differs from the object-derived id (Y1b) MUST fail closed; a receipt with `expires_at − issued_at > 120 s` (Y2) MUST fail closed; a receipt whose body `operator` differs from `attestations[].obj.operator` MUST fail closed and MUST NOT be resolved in favour of the body (Y4); an Attestation Object in non-canonical CBOR MUST fail closed (AT-8a); a re-drive receipt whose `idempotency_key` differs from the Executor's ledger-derived value, or whose claimed `origin_nonce` differs from the pinned ledger binding, MUST fail closed (DS-6f, Z3); an Attestation Object carrying an unknown field or omitting any AT-1 field MUST be rejected rather than normalized (AT-8b, Z4).** **NEW (v1.3.15):** a quorum threshold taken from any transmitted value rather than recomputed from the bundle's `quorum_k` MUST fail closed, and an Attestation Object whose `required_count` differs from `quorum_k` MUST fail closed independently of whether the quorum was met (AT-9, PB-6); a bundle whose attester registry maps two identities onto one verification key MUST be refused at load (PB-7). **NEW (v1.3.6, §9.6):** a floor-HIGH action MUST NOT execute at verification time; release before `hold_window` MUST fail closed (DR-1); a notification service sharing a rendering code path with the Attestation Presentation Service MUST be rejected **even when it renders honestly from canonical bytes** (DR-2); incomplete or empty notification delivery MUST fail closed (DR-8); repudiation from a non-notified party MUST be refused (DR-5); a hold outliving receipt validity, or configured at or above the L-14 ceiling, MUST fail closed (DR-6). **NEW (v1.3.7):** an IRREVERSIBLE action released without acknowledgement MUST fail closed (DR-9); an acknowledgement from the operator MUST be refused (DR-9); a sampled REVERSIBLE action released without acknowledgement MUST fail closed (DR-10); a receipt asserting a reversibility class different from the recomputed one MUST fail closed (RV-3); an action class absent from `reversibility.json` MUST behave as IRREVERSIBLE (RV-1). **NEW (v1.3.15, §9.6):** an action whose recomputed reversibility is IRREVERSIBLE and whose recomputed floor-only risk is below HIGH MUST NOT execute before a notice of it is durably committed (DR-13), and MUST fail closed where the signed bundle names no notice recipients for that action class — a notice with no addressee being no detection channel. **NEW (v1.3.8):** a structure whose `alg` names a suite not containing every primitive of the bundle floor's suite MUST fail closed (CR-4); a hybrid signature missing any declared primitive, carrying any undeclared extra primitive, or carrying a forged value for one primitive alongside a genuine one, MUST fail closed (CR-3); a bare scalar signature MUST be refused (CR-2); an unknown suite identifier MUST fail closed (CR-1).
4. **Composition suite** — accumulator thresholds trigger at N, not N−1; risk escalators fire on each declared condition independently and jointly; **permutation tests: shuffling the condition order yields identical risk (RK-3)**; **append-monotonicity tests**.
5. **TOCTOU suite** — capability revoked between quorum and issuance voids the attestation (AT-4); **capability revoked between issuance and execution blocks a floor-HIGH execution (§9.3 step 9)**.
6. **Adversarial suite** — known prompt-injection payloads embedded in every string field of every schema: 100% MUST be either rejected by grammar or demonstrably inert. **For F-LOW adapters, this suite tests containment, not prevention** — success is "injection cannot exceed the operator's capability envelope and cannot bypass confirmation," never "injection does not occur."
7. **Audit suite** — chain verification detects single-record tamper, deletion, reorder; anchor verification detects full-chain rewrite.
8. **Evaluator correctness suite** — the mechanized proof of Annex B, **executed** (record in §1.1), with complete verifier output per B.7, the mutation kill set (B.2a) re-run, and the differential validation of **both** production evaluators — Policy Engine and Executor TR-8 path — against the compiled model (B.7 item 4). Deployments MUST re-execute all three against the artifact hash they ship. **NEW (v1.3.4): parser conformance.** Because Annex B quantifies over parsed `Expr` values, the parser is outside the proof TCB and MUST be tested separately: the suite **MUST** include mixed-connective **source-text** vectors asserting EL-1 precedence and associativity, and **MUST** be run against the deployment's own parser, not only its evaluator. `diff_prose.py` is the reference method — two evaluators written independently from the specification prose, diffed on generated source text. A deployment whose parser disagrees with EL-1 on any vector is non-conformant.
9. **Floor-integrity suite (NEW)** — with the Context Store adversarially controlled, no sequence of tier raises causes any resource to evaluate below its signed floor, and no floor-HIGH action reaches ALLOW without attestation.
10. **Ledger suite (NEW)** — under concurrent Executors and induced partitions: no nonce double-claim, no `attestation_id` double-claim, no epoch regression, fail-closed on partition.
11. **Empirical validation suite** — every conformance claim supported by either (a) an executed mechanized proof, or (b) a red-team report by a party distinct from the implementation authors, demonstrating no single-component bypass achieves an unauthorized floor-HIGH state change. The report **MUST** be published with the conformance claim. **Status (v1.3.4): partially satisfied.** ACP-REVIEW-002 is an independent pass covering §§8.6, 9, 11, the Annex D artifact, and the §8.3.1 parser layer. It does **not** cover §§6–7 ingress, §8.5 accumulators, or §11 anchoring operations. Suite 11 is **not** closed until those surfaces are covered by a qualified party.
12. **Field-and-relation audit suite (NEW in v1.3.4 — from RES-8/RES-9).** The implementation **MUST** ship a mechanical classification table for **every** input any component consumes for a control decision, classifying each as **R** (recomputed by the consumer), **B** (cryptographically bound to something the consumer already trusts), or **T** (trusted as transmitted from the party under verification). Every **T** entry **MUST** be enumerated against §10's disclosed residuals; **any unlisted T is a conformance failure.** The table **MUST** additionally enumerate every claimed *binding* between artifacts on which a control decision depends and show the verification that discharges it (TR-10). Rationale: this method found Y1 where three narrative adversarial passes did not, and cost an afternoon. **Reference artifact: `ACP-CLASS-001`**, which classifies this specification as written (17 Executor inputs, 12 other-consumer inputs, 10 claimed relations; 0 undisclosed T). **A deployment MUST re-derive the table against its own build** — an implementation can introduce a T the specification does not have, for example by caching a bundle rather than re-reading it, or by accepting a pre-parsed expression tree from a shared library instead of parsing under EL-1 itself. **Definedness precedes classification:** for each input, the specification must determine a unique value independent of implementation choice. Z1 was invisible to classification precisely because an ambiguous parse is not a *trusted* value but an *undefined* one, and the classifier silently normalizes it; differential testing against the prose (`diff_prose.py`) is the complementary method that catches that class.

---

## 15. Security Considerations (Summary of Honest Limits)

0. **RES-0 (NEW in v1.3.15): what §14's differential evidence cannot tell you.** Two classes of test in §14 compare independent readings and treat disagreement as the finding. Both are blind in the same direction, and CR-4 was the demonstration.

   - **Implementation differential** (reference against a second implementation on a shared corpus) detects *divergence*. It is silent on a defect both implementations share, and the probability they share one is not small: the second is normally written by reading the first, so a misreading propagates with the code. CR-4's rank table was byte-for-byte agreed across both languages, asserted by a passing test, and wrong in both.
   - **Prose differential** (§14 suite 6, two evaluators written from this text alone) detects *ambiguity in the text*. It is silent on a defect the text states clearly and wrongly. CR-4 said "ranks below"; two faithful readings would have agreed, and both would have been exploitable.

   Neither method has any purchase on a requirement whose right-hand side is undefined (PB-6's predecessor) or whose comparison is undefined over its domain (CR-4's ordering). Those are found by classification (§14 suite 12, and note that the method found nothing here until its *enumeration* step was redone rather than re-affirmed), by adversarial review, or by an implementer noticing they cannot locate what a clause refers to. **A green differential run is evidence that this document has been read consistently. It is not evidence that it is right.**

1. **The guarantee is anti-injection and anti-forgery, not anti-harm.** Domain semantics are not evaluated; dual-use valid inputs require §7.4 screening.

2. **RES-1: Honest floors (A-7).** The architecture guarantees no runtime component evaluates a resource below its signed floor. It cannot know whether the floor was set correctly. A resource whose floor understates its true sensitivity is outside INV-1-HIGH's protection entirely. Floor maintenance is the highest-leverage governance task in the system.

3. **RES-2: Induced fail-closed → attestation flood.** DoS is out of scope, but every fail-closed control routes to ATTEST, and a flooded quorum converges to rubber-stamping (AT-7), silently converting floor-HIGH into effective-ALLOW. §8.6a mitigates by queue partitioning and rate-limiting; it does not eliminate the composition. This was fully implicit in v1.2.0 and never stated.

4. **RES-3: At-most-once means actions can be dropped.** For non-idempotent targets, DS-2 prefers a missed execution over a duplicate one. Deployments must operate the DS-3 reconciliation path or they will silently lose authorized actions.

5. **RES-4: Attestation decays.** AT-6 is normative operational hygiene, not advice. An unmonitored quorum becomes a rubber stamp. There is no mechanical fallback.

6. **RES-5: Three components entered the TCB.** The Attestation Presentation Service, Consumption Ledger, and Bundle Repository are load-bearing. Two of them defeat INV-1-HIGH if compromised. They were load-bearing in v1.2.0 too, but unnamed.

7. **RES-6: Value conditioning is not eliminated.** Grammar bounds the alphabet, not the semantics. An adversary choosing among allowlisted values still steers model behavior (§7.1).

8. **RES-7: F-LOW is contained, not secured.** Free-text ingress admits injection by construction. Containment rests on capability limits, confirmation, and receipts. No claim of injection prevention at an F-LOW membrane is conformant (FC-3).

9. **Grammar breadth is the enemy.** Every added schema, widened bound, and new enum member spends the auditability budget that justifies this architecture. If the registry is growing monthly, the system is becoming the general-purpose API it was built to replace.

10. **Empirical validation is required.** Architectural soundness is not implementation correctness. Until Annex B is executed and a red-team report exists, the invariants are conditional theorems, not proven facts (§1.1).

11. **RES-8: Derived values must be recomputed, not transmitted (v1.3.1).** The v1.3.0 draft reintroduced the v1.2.0 defect class in a new location: a control decision keyed on an attacker-influenceable value. The general principle, now stated as TR-8: **a verifier must never accept a derived security value from the party it is verifying.**

12. **RES-9: Derived *relations* must be verified, not named (v1.3.3).** Y1 is RES-8 one level up. TR-8 stopped the Executor trusting a derived risk *value*; it kept trusting a derived *binding* — that a transmitted signature belonged to the executed proposal — because the signed object's preimage was not transmitted. TR-10 generalizes: **a transmitted identifier is a name for a binding, not evidence of one.** That this class recurred a *third* time (C2 → X1 → Y1), each in the machinery the previous fix introduced, is now strong evidence it is the architecture's structural failure mode. The mechanical RES-8/RES-9 field-and-relation audit (ACP-AUDIT-001 §1, proposed conformance suite 12) is the enforcement: it found Y1 where narrative review did not, and it should run against every future receipt field and every claimed binding before it ships.

13. **RES-10: An ambiguous normative grammar is an unenforced invariant (v1.3.4).** Z1 is the RES-8/RES-9 family in a third register. RES-8 concerned a *value* trusted rather than recomputed; RES-9 a *relation* named rather than verified; RES-10 concerns a *meaning* assumed rather than pinned. Through v1.3.3 the §8.3.1 production stated no precedence for `&&`/`||`, so "the" evaluated meaning of a mixed rule was not a property of the specification at all — it was a property of whichever parser happened to read it, and 4.9% of mixed expressions differed between two faithful readings. Note where it hid: Annex B proves eight theorems *about parsed expressions*, and the differential harness generates *ASTs*, so the entire assurance apparatus sat downstream of the ambiguity and could not see it. **The lesson generalizes: every proof has a boundary, and the defect will be found immediately outside it.** EL-1 closes Z1; the standing obligation is to ask, of each new proof, what it quantifies over and what feeds it.

**Resolved conflict (v1.3.9 → v1.3.10): CR-6 versus EO-2.** The hybrid floor and the 25 ms bound were jointly unsatisfiable on the measured floor-HIGH path. Resolved in v1.3.10 by differentiating the latency budget per risk class (EO-2, §8.4) — not by weakening either requirement. Hybrid suites remain mandatory on every path.

**Open problems.** **Z1 migration (v1.3.4, tooling delivered v1.3.5):** EL-1 fixes the grammar going forward, but bundles authored against the ambiguous grammar may already encode the wrong meaning. Deployments **MUST** run `el1_migrate.py` (or an equivalent exhaustive checker) against every existing bundle before adopting EL-1; a reported grade change is a floor-honesty (A-7) event requiring RK-5 re-authoring with explicit parentheses and re-signing, not a routine deploy. **Whether §8.6a's `cap_escalated` marking creates an adversary-influenceable channel** — an attacker who can trip a fail-closed control may thereby influence which queue an item lands in, and the interaction between AQ-2 rate-limiting and floor-HIGH queue priority has not been analysed. Multi-step F-LOW intents (decomposition into Proposal sequences; per-step vs plan-level confirmation; rollback semantics). Confirmation fatigue at scale — DB-1's successor decays exactly like quorums do. Ambiguity handling when an utterance maps to multiple valid Proposals. Whether conversational state may condition F-LOW translation (context reuse widens the injection surface materially).

---

## Annex A — Fidelity Classes in Practice (Informative)

| Property | F-HIGH | F-LOW |
| ---------- | -------- | ------- |
| Instruction injection into the Proposal | Grammatically impossible | **Possible by construction** |
| Value conditioning of model output | Possible | Possible |
| Blast radius of a successful injection | — | Operator's capability envelope: cannot mint capabilities, cannot exceed policy, cannot reach the Executor without a receipt |
| Intent fidelity | Client-trusted (A-1) unless confirmation configured | **Confirmation mandatory** at effective tier ≥ T2 |
| Disposition | Standard | Stricter floor per FC-2 |
| Audit | Standard | Utterance hash **and** Proposal hash both recorded, enabling post-hoc divergence analysis without placing a model in the decision path |

Both classes share the enforcement core unchanged. The difference is *how much the Proposal is trusted to represent intent*, which policy expresses as a confirmation requirement and a disposition floor — not as a separate architecture.

---

## Annex B — Mechanized Proof of the Risk-Function Expression Language

**Per §1.1, this artifact has been executed: 62 verified, 0 errors, under the recorded toolchain. Mutation and differential controls accompany it.**

### B.1 Artifact

**File:** `ACP_RiskFunction_Proof.dfy` (inline below — this document is the authoritative copy)
**Size:** 772 lines
**SHA-256:** `152b97eed5928738e7aedc7d6c4c0392be851d3972bd22201132a3c1a01b1067`
**Tool:** Dafny `4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2` with bundled Z3 4.12.1
**Command:** `dafny verify --function-syntax:4 ACP_RiskFunction_Proof.dfy`
**Result:** `62 verified, 0 errors` (per-assertion log: 62/62 Valid)

v1.2.0's artifact used Dafny-3 `predicate method` / `function method` syntax in 25 places while stating `--function-syntax:4`, under which those declarations do not parse — so its stated command could not have produced its claimed output. The code below uses v4 syntax throughout and is the byte-exact verified copy: re-running the stated command against this artifact reproduces the stated result.

### B.2 Methodology

Following AWS Cedar's verification-guided development pattern: model the language in Dafny, prove properties as lemmas with explicit bodies, validate the production evaluator separately by differential random testing.

Lemmas over finite enumerations (`RiskMax_*`, `TierMax_*`, and — per X4 — `FloorDominance` itself) are discharged by SMT case enumeration and carry comment-only bodies; this is legitimate and is stated here rather than claimed otherwise. v1.2.0 asserted "empty lemma bodies are not used for non-trivial properties" while `RiskMax_Monotone` — used in its primary proof — had a comment-only body.

### B.2a Mutation Testing (Negative Control)

A clean verification run is only meaningful if the theorems constrain the model. Six mutants, two purposes:

| ID | Mutation | Class | Result |
| ---- | ---------- | ------- | -------- |
| M1 | `EffectiveTier`: max → min | Semantic | **KILLED** — 5 errors (`FloorDominance` family) |
| M2 | `RiskMax`: max → min | Semantic | **KILLED** — 6 errors |
| M3 | `FloorDominance`: remove `TierMax_GeqLeft` hint | Proof-minimality | **SURVIVED** — theorem verifies without the hint. Not a soundness defect; an honesty defect (FG-7 class). Dispositioned: hint deleted, body discloses SMT discharge. See X4. |
| M4 | `RiskLeq`: invert `(MEDIUM, LOW)` case | Semantic | **KILLED** — 1 error |
| M5 | Fold: condition target replaces `RiskMax(acc, target)` | Semantic | **KILLED** — 12 errors |
| M6 | `TierLeq`: invert `(T1, T0)` case | Semantic | **KILLED** — 1 error |

Semantic mutants: 5/5 killed — the clean run is load-bearing. The proof-minimality finding (M3) is the reason `FloorDominance` now carries an honestly empty body. One boundary observation for future revisions: the int64-bound theorem (`BreadthFitsInt64`) is one-sided and would not detect a `CidrMetric` definition error that *shrinks* the metric; the differential suite, which tests exact values, is the control that covers that direction.

### B.3 Theorems

| # | Theorem | Spec ref | Status |
| --- | --------- | ---------- | -------- |
| 1 | `Eval` totality | §8.3.1 | **Verified.** Termination by `decreases ExprSize(e)`; boolean codomain by return type. **No separate lemma** — v1.2.0's `EvalTerminates` had postcondition `exists b :: Eval(e,ctx)==b`, a tautology satisfied by any total boolean function. |
| 2 | `FloorDominance` | §8.3.2 TR-4 | **Verified.** The security-critical one. No raise value causes effective tier below floor. SMT-discharged over the 4×4 lattice (B.2a M3); killed by mutation M1. |
| 3 | `Monotonicity_Extension` | RK-3 | **Verified.** Appending a raise condition cannot decrease evaluated risk. Body completed in v1.3.2 (statement unchanged). |
| 4 | `BaseBound` | RK-3 | **Verified.** Evaluated risk ≥ base. |
| 5 | `RiskMax_Commutative` | RK-3 | **Verified.** Required for order-independence; absent in v1.2.0. |
| 6 | `Permutation_Invariance` | RK-3 | **Verified — and it required the manual effort §1.1 predicted.** Adjacent transposition invariance, lifted to a fold from index 0 by downward induction (`Transposition_Invariance_From`, added v1.3.2; statement unchanged). v1.2.0 asserted order-independence in prose and proved only associativity; v1.3.1 stated the right theorem with an insufficient body. |
| 7 | `ExpressionEvaluationDeterminism` | P-1, P-2 | **Verified.** Expression evaluator only. Full engine determinism is architectural (§8.1) + golden-file replay + differential suite. |
| 8 | `BreadthAccumulator_Exact` | AC-1a | **Verified.** Accumulator fold over CIDR metrics, arbitrary precision — no overflow precondition. `BreadthFitsInt64` (optional int64 bound) body completed in v1.3.2 via a `pow2` monotonicity family; statement unchanged. |

### B.4 Proof TCB

1. **Well-formedness** (`WellFormedExpr` under a typing environment) holds at evaluation time. Enforced by registry validation, bundle signature verification, and validator load-time checks.
2. **Context accuracy** — `EvalContext` reflects true state. Enforced by Context Store integrity, snapshot hashing, audit replay. Note: `FloorDominance` deliberately does *not* assume this for the raise component; that is its point.
3. **Arbitrary-precision integers** — Dafny's `int` is unbounded, matching AC-1a. Fixed-width production implementations must prove their own bounds.

### B.5 Scope Exclusions

Not covered: production implementation correctness (differential testing required); Context Store integrity; cryptographic properties; human attester behavior; full engine determinism; **the floor-setting process itself (A-7)** — the proof shows floors dominate raises, not that floors are correct.

### B.6 Conformance

A deployment claiming conformance **MUST** include this artifact (or an equivalent in Lean/Coq/Dafny) with its conformance report, verified cleanly with the stated toolchain. Grammar changes require re-verification of affected lemmas.

### B.7 Required Publication

1. The artifact with SHA-256 hash. **Published:** `sha256:152b97eed5928738e7aedc7d6c4c0392be851d3972bd22201132a3c1a01b1067`, 772 lines.
2. Toolchain metadata. **Published:** Dafny `4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2`; Z3 4.12.1 (bundled default; 4.8.5 also ships with the release and was not used); command `dafny verify --function-syntax:4 ACP_RiskFunction_Proof.dfy`.
3. Complete `dafny verify` output showing 0 errors, 0 timeouts. **Published:** summary `62 verified, 0 errors`, exit 0; per-assertion log (`--log-format text`) showing 62/62 `Outcome: Valid`, shipped alongside this document as `verify_full_log.txt`.
4. Differential test plan for the production evaluator. **Published as an executed harness, not a plan** (`diff_harness.py`): the verified model is compiled to an executable oracle (`dafny translate py`); a generator produces well-formed §8.3.1 triples (random, plus hand-written boundary vectors covering absent fields, type mismatches, proposal-shadows-context resolution, `prefixlen` boundaries, and empty condition lists); every case is evaluated by three implementations — the **oracle**, an **iterative Engine-style evaluator**, and a **recursive Executor-style evaluator** modelling the TR-8 step-7 recomputation path — and any pairwise disagreement fails. Metamorphic checks additionally test Theorems 2/3/4/6 empirically against the Engine implementation (condition shuffling, extension, base bound, and the full 4×4 floor/raise lattice). **Result: 20,014 cases across two seeds, 0 disagreements, 0 metamorphic violations.** Deployments MUST substitute their own production binaries for the two model implementations and re-run.

**Methodological note.** The harness's first run failed with 103 disagreements — all traced to the harness's own FFI bridge (the Python backend erases Dafny wrapper datatypes such as `FieldRef`, so the bridge passed a wrapped value where compiled code expected the erased one). The oracle was right and the harness was wrong. This is disclosed because it is the differential method working as intended: representation mismatches between a verified model and the code that talks to it are precisely the defect class this suite exists to catch, and a deployment wiring its own binaries to the oracle should expect to hit the same class first.

### B.8 Artifact

```dafny
// ============================================================================
// Door A Risk-Function Expression Language — Mechanized Proof Obligations
// ============================================================================
// Tool:    Dafny 4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2 (Z3 4.12.1)
// Version: 1.3.2
// Command: dafny verify --function-syntax:4 ACP_RiskFunction_Proof.dfy
//
// STATUS: EXECUTED. 62 verified, 0 errors. See ACP-SPEC-001 v1.3.2 §1.1
// for the full verification record, mutation kill set, and differential
// validation of production evaluators against the compiled model.
// Proves properties of the expression language and tier lattice ONLY.
// ============================================================================

module ACP_RiskFunction_Proof {

  // ==========================================================================
  // Tier lattice (T0 < T1 < T2 < T3)
  // ==========================================================================
  datatype Tier = T0 | T1 | T2 | T3

  predicate TierLeq(a: Tier, b: Tier) {
    match (a, b) {
      case (T0, _)  => true
      case (T1, T0) => false
      case (T1, _)  => true
      case (T2, T0) => false
      case (T2, T1) => false
      case (T2, _)  => true
      case (T3, T3) => true
      case (T3, _)  => false
    }
  }

  function TierMax(a: Tier, b: Tier): Tier {
    if TierLeq(a, b) then b else a
  }

  lemma TierMax_GeqLeft(a: Tier, b: Tier)
    ensures TierLeq(a, TierMax(a, b))
  { }

  lemma TierMax_Commutative(a: Tier, b: Tier)
    ensures TierMax(a, b) == TierMax(b, a)
  { }

  // ==========================================================================
  // THEOREM 2 (§8.3.2 TR-4): FloorDominance
  //
  // The security property that makes INV-1-HIGH well-defined and true under
  // Context Store compromise. Effective tier is max(signed floor, served
  // raise). No value of `raise` — including one chosen adversarially — can
  // produce an effective tier below the floor.
  // ==========================================================================
  datatype TierAssertion = TierAssertion(floor: Tier, raise: Tier)

  function EffectiveTier(ta: TierAssertion): Tier {
    TierMax(ta.floor, ta.raise)
  }

  lemma FloorDominance(floor: Tier, raise: Tier)
    ensures TierLeq(floor, EffectiveTier(TierAssertion(floor, raise)))
  {
    // SMT-discharged by case enumeration over the 4x4 tier lattice (B.2).
    // Mutation testing (v1.3.2, M3) showed the previous TierMax_GeqLeft hint
    // was decorative: the theorem verifies without it. Per the FG-7 standard,
    // the body discloses the discharge mechanism instead of overstating
    // manual proof work.
  }

  // Adversarial form: for ANY two raise values the floor still dominates,
  // so a compromised Context Store cannot lower the evaluated tier.
  lemma FloorDominance_Adversarial(floor: Tier, r1: Tier, r2: Tier)
    ensures TierLeq(floor, EffectiveTier(TierAssertion(floor, r1)))
    ensures TierLeq(floor, EffectiveTier(TierAssertion(floor, r2)))
  {
    FloorDominance(floor, r1);
    FloorDominance(floor, r2);
  }

  // ==========================================================================
  // Risk lattice (LOW < MEDIUM < HIGH)
  // ==========================================================================
  datatype RiskLevel = LOW | MEDIUM | HIGH

  predicate RiskLeq(a: RiskLevel, b: RiskLevel) {
    match (a, b) {
      case (LOW, _)      => true
      case (MEDIUM, LOW) => false
      case (MEDIUM, _)   => true
      case (HIGH, HIGH)  => true
      case (HIGH, _)     => false
    }
  }

  function RiskMax(a: RiskLevel, b: RiskLevel): RiskLevel {
    if RiskLeq(a, b) then b else a
  }

  lemma RiskMax_GeqLeft(a: RiskLevel, b: RiskLevel)
    ensures RiskLeq(a, RiskMax(a, b))
  { }

  lemma RiskMax_GeqRight(a: RiskLevel, b: RiskLevel)
    ensures RiskLeq(b, RiskMax(a, b))
  { }

  lemma RiskMax_Monotone(a: RiskLevel, b: RiskLevel, a': RiskLevel, b': RiskLevel)
    requires RiskLeq(a, a')
    requires RiskLeq(b, b')
    ensures RiskLeq(RiskMax(a, b), RiskMax(a', b'))
  { }

  lemma RiskMax_Associative(a: RiskLevel, b: RiskLevel, c: RiskLevel)
    ensures RiskMax(RiskMax(a, b), c) == RiskMax(a, RiskMax(b, c))
  { }

  // THEOREM 5: commutativity. Required for order-independence (RK-3).
  // Absent from v1.2.0, which claimed order-independence anyway.
  lemma RiskMax_Commutative(a: RiskLevel, b: RiskLevel)
    ensures RiskMax(a, b) == RiskMax(b, a)
  { }

  lemma RiskLeq_Reflexive(a: RiskLevel)
    ensures RiskLeq(a, a)
  { }

  // ==========================================================================
  // Types, values, and the typing environment (§8.3.1 static constraints)
  // v1.2.0 modelled only set homogeneity; field declaration and CIDR typing
  // were unmodelled, so the static checker had no target for validation.
  // ==========================================================================
  datatype ValueType = TyString | TyTier | TyInt | TyCidr | TyBool

  datatype Value =
    | VString(s: string)
    | VTier(t: Tier)
    | VInt(n: int)
    | VCidr(prefixlen: int)
    | VBool(b: bool)
    | VAbsent

  function TypeOf(v: Value): ValueType
    requires v != VAbsent
  {
    match v {
      case VString(_) => TyString
      case VTier(_)   => TyTier
      case VInt(_)    => TyInt
      case VCidr(_)   => TyCidr
      case VBool(_)   => TyBool
      case VAbsent    => TyBool  // unreachable under precondition
    }
  }

  datatype FieldRef = FieldRef(path: seq<string>)

  datatype Literal = LString(s: string) | LTier(t: Tier)

  datatype CompOp = Eq | Neq | Lt | Leq | Gt | Geq

  datatype ValRef = VField(fr: FieldRef) | VLit(l: Literal) | VNum(n: int)

  datatype Comparison =
    | CComp(left: ValRef, op: CompOp, right: ValRef)
    | CIn(value: ValRef, elems: seq<Literal>)
    | CPrefixLen(field: FieldRef, bound: int)

  datatype Expr =
    | ETrue
    | EFalse
    | EComp(c: Comparison)
    | EAnd(e1: Expr, e2: Expr)
    | EOr(e1: Expr, e2: Expr)

  type TypeEnv = map<seq<string>, ValueType>

  // ==========================================================================
  // Well-formedness under a typing environment
  // ==========================================================================
  predicate WellFormedFieldRef(fr: FieldRef, env: TypeEnv) {
    0 < |fr.path| <= 8 && fr.path in env
  }

  predicate Homogeneous(s: seq<Literal>) {
    if |s| <= 1 then true
    else
      (match (s[0], s[1]) {
        case (LString(_), LString(_)) => true
        case (LTier(_), LTier(_))     => true
        case _ => false
      })
      && Homogeneous(s[1..])
  }

  predicate WellFormedSet(s: seq<Literal>) {
    |s| > 0 && Homogeneous(s)
  }

  predicate WellFormedValRef(vr: ValRef, env: TypeEnv) {
    match vr {
      case VField(fr) => WellFormedFieldRef(fr, env)
      case VLit(_)    => true
      case VNum(_)    => true
    }
  }

  predicate WellFormedComparison(c: Comparison, env: TypeEnv) {
    match c {
      case CComp(left, _, right) =>
        WellFormedValRef(left, env) && WellFormedValRef(right, env)
      case CIn(value, elems) =>
        WellFormedValRef(value, env) && WellFormedSet(elems)
      case CPrefixLen(field, bound) =>
        // .prefixlen is valid ONLY on CIDR-typed fields (§8.3.1).
        WellFormedFieldRef(field, env)
        && env[field.path] == TyCidr
        && 0 <= bound <= 32
    }
  }

  predicate WellFormedExpr(e: Expr, env: TypeEnv) {
    match e {
      case ETrue      => true
      case EFalse     => true
      case EComp(c)   => WellFormedComparison(c, env)
      case EAnd(a, b) => WellFormedExpr(a, env) && WellFormedExpr(b, env)
      case EOr(a, b)  => WellFormedExpr(a, env) && WellFormedExpr(b, env)
    }
  }

  // ==========================================================================
  // Evaluation context, and its agreement with the typing environment
  // ==========================================================================
  type FieldMap = map<seq<string>, Value>

  datatype EvalContext = EvalContext(proposal: FieldMap, ctxmap: FieldMap)

  function ResolveField(fr: FieldRef, ctx: EvalContext): Value {
    if fr.path in ctx.proposal then ctx.proposal[fr.path]
    else if fr.path in ctx.ctxmap then ctx.ctxmap[fr.path]
    else VAbsent
  }

  // A context is well-typed w.r.t. env when every declared path that resolves
  // carries the declared type. Absent paths are permitted (totality: absent
  // yields false, never undefined behaviour).
  predicate WellTypedContext(ctx: EvalContext, env: TypeEnv) {
    forall p :: p in env ==>
      (var v := ResolveField(FieldRef(p), ctx);
       v == VAbsent || TypeOf(v) == env[p])
  }

  function Deref(vr: ValRef, ctx: EvalContext): Value {
    match vr {
      case VField(fr) => ResolveField(fr, ctx)
      case VLit(l)    => match l {
                           case LString(s) => VString(s)
                           case LTier(t)   => VTier(t)
                         }
      case VNum(n)    => VInt(n)
    }
  }

  function InSet(v: Value, elems: seq<Literal>): bool {
    if |elems| == 0 then false
    else
      match (v, elems[0]) {
        case (VString(s), LString(ss)) => s == ss || InSet(v, elems[1..])
        case (VTier(t),   LTier(tt))   => t == tt || InSet(v, elems[1..])
        case _ => InSet(v, elems[1..])
      }
  }

  function EvalComparison(c: Comparison, ctx: EvalContext): bool {
    match c {
      case CComp(left, op, right) =>
        var lv := Deref(left, ctx);
        var rv := Deref(right, ctx);
        if lv == VAbsent || rv == VAbsent then false
        else
          match (lv, op, rv) {
            case (VInt(a),    Eq,  VInt(b))    => a == b
            case (VInt(a),    Neq, VInt(b))    => a != b
            case (VInt(a),    Lt,  VInt(b))    => a < b
            case (VInt(a),    Leq, VInt(b))    => a <= b
            case (VInt(a),    Gt,  VInt(b))    => a > b
            case (VInt(a),    Geq, VInt(b))    => a >= b
            case (VString(a), Eq,  VString(b)) => a == b
            case (VString(a), Neq, VString(b)) => a != b
            case (VTier(a),   Eq,  VTier(b))   => a == b
            case (VTier(a),   Neq, VTier(b))   => a != b
            case (VTier(a),   Lt,  VTier(b))   => TierLeq(a, b) && a != b
            case (VTier(a),   Leq, VTier(b))   => TierLeq(a, b)
            case (VTier(a),   Gt,  VTier(b))   => TierLeq(b, a) && a != b
            case (VTier(a),   Geq, VTier(b))   => TierLeq(b, a)
            case _ => false
          }
      case CIn(value, elems) =>
        var v := Deref(value, ctx);
        if v == VAbsent then false else InSet(v, elems)
      case CPrefixLen(field, bound) =>
        match ResolveField(field, ctx) {
          case VCidr(pl) => pl <= bound
          case _ => false
        }
    }
  }

  function ExprSize(e: Expr): nat {
    match e {
      case ETrue      => 1
      case EFalse     => 1
      case EComp(_)   => 1
      case EAnd(a, b) => 1 + ExprSize(a) + ExprSize(b)
      case EOr(a, b)  => 1 + ExprSize(a) + ExprSize(b)
    }
  }

  // ==========================================================================
  // THEOREM 1 (§8.3.1): Totality.
  //
  // Termination is discharged by `decreases ExprSize(e)`; the boolean codomain
  // is the return type. There is deliberately NO separate lemma: v1.2.0's
  // `EvalTerminates` asserted `exists b :: Eval(e,ctx) == b`, which is
  // satisfied by any total boolean function and proved nothing.
  //
  // Note on connectives: `&&` / `||` are Dafny's short-circuit operators.
  // Per §8.3.1 as revised, evaluation ORDER is unconstrained; only the RESULT
  // must be order-independent, which is what Theorem 6 establishes.
  // ==========================================================================
  function Eval(e: Expr, ctx: EvalContext, env: TypeEnv): bool
    requires WellFormedExpr(e, env)
    decreases ExprSize(e)
  {
    match e {
      case ETrue      => true
      case EFalse     => false
      case EComp(c)   => EvalComparison(c, ctx)
      case EAnd(a, b) => Eval(a, ctx, env) && Eval(b, ctx, env)
      case EOr(a, b)  => Eval(a, ctx, env) || Eval(b, ctx, env)
    }
  }

  // THEOREM 7: determinism of the expression evaluator.
  lemma ExpressionEvaluationDeterminism(e: Expr, c1: EvalContext, c2: EvalContext, env: TypeEnv)
    requires WellFormedExpr(e, env)
    requires c1 == c2
    ensures Eval(e, c1, env) == Eval(e, c2, env)
  { }

  // ==========================================================================
  // Risk functions
  // ==========================================================================
  datatype RaiseCondition = RaiseCondition(cond: Expr, target: RiskLevel)

  datatype RiskFunction = RiskFunction(base: RiskLevel, conditions: seq<RaiseCondition>)

  predicate WellFormedRiskFunction(rf: RiskFunction, env: TypeEnv) {
    forall i :: 0 <= i < |rf.conditions| ==> WellFormedExpr(rf.conditions[i].cond, env)
  }

  function EvalRiskLevelAcc(rf: RiskFunction, ctx: EvalContext, env: TypeEnv,
                            acc: RiskLevel, i: nat): RiskLevel
    requires WellFormedRiskFunction(rf, env)
    requires i <= |rf.conditions|
    decreases |rf.conditions| - i
  {
    if i == |rf.conditions| then acc
    else
      var c := rf.conditions[i];
      var next := if Eval(c.cond, ctx, env) then RiskMax(acc, c.target) else acc;
      EvalRiskLevelAcc(rf, ctx, env, next, i + 1)
  }

  function EvalRiskLevel(rf: RiskFunction, ctx: EvalContext, env: TypeEnv): RiskLevel
    requires WellFormedRiskFunction(rf, env)
  {
    EvalRiskLevelAcc(rf, ctx, env, rf.base, 0)
  }

  lemma EvalRiskLevelAcc_Monotone(rf: RiskFunction, ctx: EvalContext, env: TypeEnv,
                                  a1: RiskLevel, a2: RiskLevel, i: nat)
    requires WellFormedRiskFunction(rf, env)
    requires i <= |rf.conditions|
    requires RiskLeq(a1, a2)
    ensures RiskLeq(EvalRiskLevelAcc(rf, ctx, env, a1, i),
                    EvalRiskLevelAcc(rf, ctx, env, a2, i))
    decreases |rf.conditions| - i
  {
    if i == |rf.conditions| {
    } else {
      var c := rf.conditions[i];
      var b := Eval(c.cond, ctx, env);
      var n1 := if b then RiskMax(a1, c.target) else a1;
      var n2 := if b then RiskMax(a2, c.target) else a2;
      if b {
        RiskMax_Monotone(a1, c.target, a2, c.target);
      }
      EvalRiskLevelAcc_Monotone(rf, ctx, env, n1, n2, i + 1);
    }
  }

  // ==========================================================================
  // THEOREM 3: Monotonicity under extension (RK-3).
  // Appending a raise condition never decreases evaluated risk.
  // ==========================================================================
  lemma EvalRiskLevelAcc_ExtensionBound(rf: RiskFunction, ctx: EvalContext, env: TypeEnv,
                                        acc: RiskLevel, i: nat, extra: RaiseCondition)
    requires WellFormedRiskFunction(rf, env)
    requires i <= |rf.conditions|
    requires WellFormedExpr(extra.cond, env)
    ensures RiskLeq(
      EvalRiskLevelAcc(rf, ctx, env, acc, i),
      EvalRiskLevelAcc(RiskFunction(rf.base, rf.conditions + [extra]), ctx, env, acc, i))
    decreases |rf.conditions| - i
  {
    var rfp := RiskFunction(rf.base, rf.conditions + [extra]);
    if i == |rf.conditions| {
      assert rfp.conditions[i] == extra;
      assert i + 1 == |rfp.conditions|;
      assert EvalRiskLevelAcc(rf, ctx, env, acc, i) == acc;
      var b := Eval(extra.cond, ctx, env);
      var nextp := if b then RiskMax(acc, extra.target) else acc;
      assert EvalRiskLevelAcc(rfp, ctx, env, acc, i)
          == EvalRiskLevelAcc(rfp, ctx, env, nextp, i + 1);
      assert EvalRiskLevelAcc(rfp, ctx, env, nextp, i + 1) == nextp;
      if b {
        RiskMax_GeqLeft(acc, extra.target);
      } else {
        RiskLeq_Reflexive(acc);
      }
    } else {
      var c := rf.conditions[i];
      assert rfp.conditions[i] == c;
      var b := Eval(c.cond, ctx, env);
      var next := if b then RiskMax(acc, c.target) else acc;
      EvalRiskLevelAcc_ExtensionBound(rf, ctx, env, next, i + 1, extra);
    }
  }

  lemma Monotonicity_Extension(rf: RiskFunction, ctx: EvalContext, env: TypeEnv,
                               newCond: RaiseCondition)
    requires WellFormedRiskFunction(rf, env)
    requires WellFormedExpr(newCond.cond, env)
    ensures RiskLeq(
      EvalRiskLevel(rf, ctx, env),
      EvalRiskLevel(RiskFunction(rf.base, rf.conditions + [newCond]), ctx, env))
  {
    EvalRiskLevelAcc_ExtensionBound(rf, ctx, env, rf.base, 0, newCond);
  }

  // ==========================================================================
  // THEOREM 4: BaseBound. Evaluated risk is never below the declared base.
  // ==========================================================================
  lemma BaseBound_Acc(rf: RiskFunction, ctx: EvalContext, env: TypeEnv,
                      acc: RiskLevel, i: nat)
    requires WellFormedRiskFunction(rf, env)
    requires i <= |rf.conditions|
    requires RiskLeq(rf.base, acc)
    ensures RiskLeq(rf.base, EvalRiskLevelAcc(rf, ctx, env, acc, i))
    decreases |rf.conditions| - i
  {
    if i == |rf.conditions| {
    } else {
      var c := rf.conditions[i];
      var b := Eval(c.cond, ctx, env);
      var next := if b then RiskMax(acc, c.target) else acc;
      if b {
        RiskMax_GeqLeft(acc, c.target);
      }
      BaseBound_Acc(rf, ctx, env, next, i + 1);
    }
  }

  lemma BaseBound(rf: RiskFunction, ctx: EvalContext, env: TypeEnv)
    requires WellFormedRiskFunction(rf, env)
    ensures RiskLeq(rf.base, EvalRiskLevel(rf, ctx, env))
  {
    BaseBound_Acc(rf, ctx, env, rf.base, 0);
  }

  // Helper (v1.3.2 verification pass): folds over two condition sequences that
  // agree pointwise from index j onward, with equal accumulators, are equal.
  lemma EvalRiskLevelAcc_AgreeFrom(rf1: RiskFunction, rf2: RiskFunction,
                                   ctx: EvalContext, env: TypeEnv,
                                   acc: RiskLevel, j: nat)
    requires WellFormedRiskFunction(rf1, env)
    requires WellFormedRiskFunction(rf2, env)
    requires |rf1.conditions| == |rf2.conditions|
    requires j <= |rf1.conditions|
    requires forall k :: j <= k < |rf1.conditions| ==> rf1.conditions[k] == rf2.conditions[k]
    ensures EvalRiskLevelAcc(rf1, ctx, env, acc, j)
         == EvalRiskLevelAcc(rf2, ctx, env, acc, j)
    decreases |rf1.conditions| - j
  {
    if j == |rf1.conditions| {
    } else {
      var c := rf1.conditions[j];
      assert rf2.conditions[j] == c;
      var b := Eval(c.cond, ctx, env);
      var next := if b then RiskMax(acc, c.target) else acc;
      EvalRiskLevelAcc_AgreeFrom(rf1, rf2, ctx, env, next, j + 1);
    }
  }

  // ==========================================================================
  // THEOREM 6: Permutation invariance (RK-3 order-independence).
  //
  // v1.2.0 claimed "rule interaction is order-independent" and proved only
  // associativity, which is insufficient. The proof proceeds by adjacent
  // transposition: swapping two neighbouring conditions leaves the result
  // unchanged (by associativity + commutativity of RiskMax, and because each
  // condition's truth value is independent of its position). Arbitrary
  // permutations are compositions of adjacent transpositions.
  //
  // NOTE (§1.1): this is the lemma most likely to need manual proof effort.
  // Verify it first.
  // ==========================================================================
  function SwapAt(s: seq<RaiseCondition>, i: nat): seq<RaiseCondition>
    requires i + 1 < |s|
  {
    s[..i] + [s[i+1], s[i]] + s[i+2..]
  }

  lemma Transposition_Invariance(rf: RiskFunction, ctx: EvalContext, env: TypeEnv,
                                 acc: RiskLevel, i: nat)
    requires WellFormedRiskFunction(rf, env)
    requires i + 1 < |rf.conditions|
    requires WellFormedRiskFunction(RiskFunction(rf.base, SwapAt(rf.conditions, i)), env)
    ensures EvalRiskLevelAcc(rf, ctx, env, acc, i)
         == EvalRiskLevelAcc(RiskFunction(rf.base, SwapAt(rf.conditions, i)), ctx, env, acc, i)
  {
    var s := rf.conditions;
    var s2 := SwapAt(s, i);
    var rf2 := RiskFunction(rf.base, s2);
    var c1 := s[i];
    var c2 := s[i+1];
    assert |s2| == |s|;
    assert s2[i] == c2 && s2[i+1] == c1;
    assert forall k :: i + 2 <= k < |s| ==> s2[k] == s[k];
    var b1 := Eval(c1.cond, ctx, env);
    var b2 := Eval(c2.cond, ctx, env);

    // Step both folds through positions i and i+1 explicitly.
    var a1  := if b1 then RiskMax(acc, c1.target) else acc;   // original, after i
    var a12 := if b2 then RiskMax(a1, c2.target) else a1;     // original, after i+1
    var a2  := if b2 then RiskMax(acc, c2.target) else acc;   // swapped, after i
    var a21 := if b1 then RiskMax(a2, c1.target) else a2;     // swapped, after i+1

    assert EvalRiskLevelAcc(rf, ctx, env, acc, i)  == EvalRiskLevelAcc(rf, ctx, env, a1, i + 1);
    assert EvalRiskLevelAcc(rf, ctx, env, a1, i + 1) == EvalRiskLevelAcc(rf, ctx, env, a12, i + 2);
    assert EvalRiskLevelAcc(rf2, ctx, env, acc, i)  == EvalRiskLevelAcc(rf2, ctx, env, a2, i + 1);
    assert EvalRiskLevelAcc(rf2, ctx, env, a2, i + 1) == EvalRiskLevelAcc(rf2, ctx, env, a21, i + 2);

    // Both orders reach position i+2 with the same accumulator:
    //   b1 && b2  : max(max(acc,t1),t2) == max(max(acc,t2),t1)
    //               by RiskMax_Associative + RiskMax_Commutative
    //   b1 xor b2 : only one target applied, identical either way
    //   neither   : accumulator unchanged
    if b1 && b2 {
      RiskMax_Associative(acc, c1.target, c2.target);
      RiskMax_Associative(acc, c2.target, c1.target);
      RiskMax_Commutative(c1.target, c2.target);
    }
    assert a12 == a21;

    // Suffix from i+2 is identical in both sequences; lift equality to the tail.
    EvalRiskLevelAcc_AgreeFrom(rf, rf2, ctx, env, a12, i + 2);
  }

  // Helper (v1.3.2 verification pass): the swap lemma generalized to a fold
  // starting at any j <= i. The prefix [j, i) is shared between the two
  // sequences, so equality at i lifts stepwise down to j.
  lemma Transposition_Invariance_From(rf: RiskFunction, ctx: EvalContext, env: TypeEnv,
                                      acc: RiskLevel, i: nat, j: nat)
    requires WellFormedRiskFunction(rf, env)
    requires i + 1 < |rf.conditions|
    requires j <= i
    requires WellFormedRiskFunction(RiskFunction(rf.base, SwapAt(rf.conditions, i)), env)
    ensures EvalRiskLevelAcc(rf, ctx, env, acc, j)
         == EvalRiskLevelAcc(RiskFunction(rf.base, SwapAt(rf.conditions, i)), ctx, env, acc, j)
    decreases i - j
  {
    var rf2 := RiskFunction(rf.base, SwapAt(rf.conditions, i));
    if j == i {
      Transposition_Invariance(rf, ctx, env, acc, i);
    } else {
      assert rf2.conditions[j] == rf.conditions[j];
      var c := rf.conditions[j];
      var b := Eval(c.cond, ctx, env);
      var next := if b then RiskMax(acc, c.target) else acc;
      assert EvalRiskLevelAcc(rf, ctx, env, acc, j)  == EvalRiskLevelAcc(rf, ctx, env, next, j + 1);
      assert EvalRiskLevelAcc(rf2, ctx, env, acc, j) == EvalRiskLevelAcc(rf2, ctx, env, next, j + 1);
      Transposition_Invariance_From(rf, ctx, env, next, i, j + 1);
    }
  }

  lemma Permutation_Invariance(rf: RiskFunction, ctx: EvalContext, env: TypeEnv, i: nat)
    requires WellFormedRiskFunction(rf, env)
    requires i + 1 < |rf.conditions|
    requires WellFormedRiskFunction(RiskFunction(rf.base, SwapAt(rf.conditions, i)), env)
    ensures EvalRiskLevel(rf, ctx, env)
         == EvalRiskLevel(RiskFunction(rf.base, SwapAt(rf.conditions, i)), ctx, env)
  {
    // The prefix [0, i) is shared, so equality at i lifts to equality at 0.
    Transposition_Invariance_From(rf, ctx, env, rf.base, i, 0);
  }

  // ==========================================================================
  // THEOREM 8 (AC-1a): Accumulator breadth, arbitrary precision.
  //
  // Dafny's `int` is unbounded, matching AC-1a as revised. v1.2.0 proved a
  // disconnected int64 bound under a <=1e6-term precondition that no normative
  // limit enforced (L-05 bounds items per REQUEST; windows run to 30 days).
  // Here the metric is wired into the actual fold and no bound is needed.
  // ==========================================================================
  function pow2(n: nat): nat
    decreases n
  {
    if n == 0 then 1 else 2 * pow2(n - 1)
  }

  function CidrMetric(prefixlen: int): nat
    requires 0 <= prefixlen <= 32
  {
    pow2((32 - prefixlen) as nat)
  }

  // The accumulator fold as actually specified in §8.5.
  function BreadthAccumulate(prefixlens: seq<int>): nat
    requires forall i :: 0 <= i < |prefixlens| ==> 0 <= prefixlens[i] <= 32
    decreases |prefixlens|
  {
    if |prefixlens| == 0 then 0
    else CidrMetric(prefixlens[0]) + BreadthAccumulate(prefixlens[1..])
  }

  // Exactness and monotonicity: the accumulator is total, non-negative, and
  // never decreases as terms are appended. No overflow obligation arises.
  lemma BreadthAccumulator_Exact(prefixlens: seq<int>)
    requires forall i :: 0 <= i < |prefixlens| ==> 0 <= prefixlens[i] <= 32
    ensures BreadthAccumulate(prefixlens) >= 0
    decreases |prefixlens|
  {
    if |prefixlens| == 0 {
    } else {
      BreadthAccumulator_Exact(prefixlens[1..]);
    }
  }

  lemma BreadthAccumulator_Monotone(prefixlens: seq<int>, extra: int)
    requires forall i :: 0 <= i < |prefixlens| ==> 0 <= prefixlens[i] <= 32
    requires 0 <= extra <= 32
    ensures BreadthAccumulate(prefixlens + [extra]) >= BreadthAccumulate(prefixlens)
    decreases |prefixlens|
  {
    if |prefixlens| == 0 {
      assert (prefixlens + [extra])[1..] == [];
    } else {
      assert (prefixlens + [extra])[1..] == prefixlens[1..] + [extra];
      BreadthAccumulator_Monotone(prefixlens[1..], extra);
    }
  }

  // Helpers (v1.3.2 verification pass) for the optional int64 bound.
  lemma pow2_Step(n: nat)
    ensures pow2(n + 1) == 2 * pow2(n)
    ensures pow2(n) >= 1
  {
    if n > 0 { pow2_Step(n - 1); }
  }

  lemma pow2_MonoTo32(n: nat)
    requires n <= 32
    ensures pow2(n) <= pow2(32)
    decreases 32 - n
  {
    if n < 32 {
      pow2_Step(n);
      pow2_MonoTo32(n + 1);
    }
  }

  lemma pow2_32_Value()
    ensures pow2(32) == 4294967296
  {
    assert pow2(0) == 1;
    assert pow2(1) == 2;
    assert pow2(2) == 4;
    assert pow2(3) == 8;
    assert pow2(4) == 16;
    assert pow2(5) == 32;
    assert pow2(6) == 64;
    assert pow2(7) == 128;
    assert pow2(8) == 256;
    assert pow2(9) == 512;
    assert pow2(10) == 1024;
    assert pow2(11) == 2048;
    assert pow2(12) == 4096;
    assert pow2(13) == 8192;
    assert pow2(14) == 16384;
    assert pow2(15) == 32768;
    assert pow2(16) == 65536;
    assert pow2(17) == 131072;
    assert pow2(18) == 262144;
    assert pow2(19) == 524288;
    assert pow2(20) == 1048576;
    assert pow2(21) == 2097152;
    assert pow2(22) == 4194304;
    assert pow2(23) == 8388608;
    assert pow2(24) == 16777216;
    assert pow2(25) == 33554432;
    assert pow2(26) == 67108864;
    assert pow2(27) == 134217728;
    assert pow2(28) == 268435456;
    assert pow2(29) == 536870912;
    assert pow2(30) == 1073741824;
    assert pow2(31) == 2147483648;
    assert pow2(32) == 4294967296;
  }

  lemma pow2_Bound(prefixlen: int)
    requires 0 <= prefixlen <= 32
    ensures CidrMetric(prefixlen) <= 4294967296
  {
    pow2_MonoTo32((32 - prefixlen) as nat);
    pow2_32_Value();
  }

  // Optional fixed-width bound, retained for implementations that must use
  // int64. Its precondition is now an explicit deployment obligation
  // (AC-1a), not an unstated assumption.
  lemma BreadthFitsInt64(prefixlens: seq<int>, maxTerms: nat)
    requires forall i :: 0 <= i < |prefixlens| ==> 0 <= prefixlens[i] <= 32
    requires |prefixlens| <= maxTerms
    requires maxTerms * 4294967296 <= 9223372036854775806
    ensures BreadthAccumulate(prefixlens) <= maxTerms * 4294967296
    decreases |prefixlens|
  {
    if |prefixlens| == 0 {
    } else {
      assert 1 <= maxTerms;
      pow2_Bound(prefixlens[0]);
      BreadthFitsInt64(prefixlens[1..], maxTerms - 1);
      assert BreadthAccumulate(prefixlens)
          == CidrMetric(prefixlens[0]) + BreadthAccumulate(prefixlens[1..]);
      assert (maxTerms - 1) * 4294967296 + 4294967296 == maxTerms * 4294967296;
    }
  }

  // ==========================================================================
  // Conformance export predicates (§14 suite 8)
  // ==========================================================================
  predicate Conformance_FloorDominance(floor: Tier, raise: Tier) {
    TierLeq(floor, EffectiveTier(TierAssertion(floor, raise)))
  }

  predicate Conformance_Monotonicity(rf: RiskFunction, ctx: EvalContext,
                                     env: TypeEnv, newCond: RaiseCondition) {
    (WellFormedRiskFunction(rf, env) && WellFormedExpr(newCond.cond, env)) ==>
      RiskLeq(EvalRiskLevel(rf, ctx, env),
              EvalRiskLevel(RiskFunction(rf.base, rf.conditions + [newCond]), ctx, env))
  }

  predicate Conformance_BaseBound(rf: RiskFunction, ctx: EvalContext, env: TypeEnv) {
    WellFormedRiskFunction(rf, env) ==> RiskLeq(rf.base, EvalRiskLevel(rf, ctx, env))
  }

  predicate Conformance_Determinism(e: Expr, c1: EvalContext, c2: EvalContext, env: TypeEnv) {
    (WellFormedExpr(e, env) && c1 == c2) ==> Eval(e, c1, env) == Eval(e, c2, env)
  }
}
```

---

## Annex C — Disposition of v1.2.0 Peer-Review Findings

| ID | Finding (v1.2.0) | Disposition in v1.3.0 |
| ---- | ------------------ | ---------------------- |
| **C1** | Tier data in two mutually exclusive places; RK-5 protected a copy that did not feed evaluation | **Fixed by construction.** §8.3.2: floor in signed bundle, raise in Context Store, `effective = max`. One lattice, one integrity story. |
| **C2** | §10 claimed Context Store compromise does not violate INV-1-HIGH; tier suppression showed it does | **Fixed by construction.** TR-4/TR-5 + `FloorDominance` (Annex B, Theorem 2). "HIGH-impact" now defined as floor-only-HIGH. §10 row rewritten. |
| **C3** | §8.3.1 prohibited short-circuit evaluation; the artifact implemented it; differential testing could not detect a violation | **Claim retired.** §8.3.1 now requires result-order-independence, not evaluation-order constraint. Timing side channels explicitly out of scope (§4.2). Order-independence proved (Theorem 6). |
| **C4** | "Injection structurally impossible" vs "adversary controls prompt conditioning" | **Fixed.** §7.1 rewritten to distinguish instruction injection (eliminated for F-HIGH) from value conditioning (eliminated for neither). RES-6. |
| **C5** | Access/network ops assigned to Door A in §2.1 and Door B in §8.8 | **Fixed.** Door binary retired (§2.4). CP-4 states provider class is orthogonal to fidelity class. |
| **HA-1** | Approval-rendering layer trusted but absent from TCB; humans sign a hash they cannot read | **Named, partially mitigated.** A-8 + Attestation Presentation Service in TCB (§4.3). AT-3 requires floor-derived display and hash display. §12.6 device re-render as SHOULD. Residual disclosed (RES-5, §10 row). |
| **HA-2** | Bundle repository integrity and rollback-resistant "current bundle" unspecified | **Fixed.** §9.1.1 step 3 specifies isolation stronger than filesystem permissions; Bundle Repository in TCB; RAD-3 replaced by monotonic epoch. |
| **HA-3** | Nonce atomicity assumed target idempotency, false for in-scope non-idempotent HIGH actions | **Fixed by honest restatement.** §9.5: exactly-once only where the target supports it; at-most-once default otherwise; DS-4 forbids at-least-once for floor-HIGH non-idempotent. RES-3. |
| **HA-4** | INV-1-HIGH's preconditions omitted no-cross-operator-collusion | **Fixed.** A-9 added at the point the invariant is stated. |
| **TG-1** | Issuance→execution TOCTOU: Executor never re-queried Context; revoked authority exercisable ~2 min | **Fixed for floor-HIGH.** §9.3 step 9 adds execution-time capability recheck for floor-HIGH. MEDIUM residual disclosed. |
| **TG-2** | "Constraint narrowing" undefined; net-widening changes could take the expedited path | **Fixed.** SR-3 defines narrowing decidably over the bounded lattice; undecidable defaults to widening. |
| **TG-3** | RAD-3 permitted replay of a genuine but superseded permissive bundle | **Fixed.** RAD-3 replaced by durable monotonic `bundle_epoch` high-water mark. T-15. |
| **TG-4** | Output-weakness rationale mislocated for Door A | **Fixed** with C4. |
| **FG-1** | Order-independence asserted; no commutativity, no permutation theorem | **Fixed.** `RiskMax_Commutative` (Theorem 5) and `Permutation_Invariance` (Theorem 6) added. Conformance suite 4 tests it. |
| **FG-2** | `EvalTerminates` postcondition was a tautology | **Fixed.** Lemma removed; B.3 states termination is discharged by the `decreases` clause, which is where it always lived. |
| **FG-3** | Append-only monotonicity presented as "no rule combination lowers risk" | **Fixed by rewording + proving the gap.** Append (Theorem 3), base floor (Theorem 4), reorder (Theorem 6) are proved. Removal and base-lowering *can* lower risk — correctly, and are RK-5-governed procedurally. §14.4 reworded. |
| **FG-4** | CIDR boundedness disconnected from evaluator and accumulator; ≤10⁶ precondition unenforced | **Fixed.** AC-1a mandates arbitrary precision; `BreadthAccumulate` models the real fold; int64 bound retained as optional with explicit deployment obligation. |
| **FG-5** | `WellFormed*` weaker than §8.3.1 static constraints; no declared-field env, no CIDR typing | **Fixed.** `TypeEnv`, `WellTypedContext`, and CIDR-typing in `WellFormedComparison` added. |
| **FG-6** | Dafny-3 syntax vs `--function-syntax:4`; artifact could not parse under the stated command; line count wrong | **Fixed.** Artifact rewritten in v4 syntax. Line-count claim removed (artifact is inline; the document is authoritative). §1.1 discloses it remains unexecuted. |
| **FG-7** | B.2 claimed no empty bodies for non-trivial properties while load-bearing lemmas had comment-only bodies | **Fixed by honest restatement.** B.2 now states finite-enumeration lemmas are SMT-discharged with comment-only bodies, and says so plainly. |
| **RR-A** | Attestation amplification: one quorum → many HIGH executions under single-component compromise | **Fixed by construction.** `attestation_id` (AT-1) consumed in the ledger (CL-3); Executor step 7; reconciliation check (c). T-14. |
| **RR-B** | Induced fail-closed → ESCALATE flood → rubber-stamping, never discussed | **Named and mitigated.** §8.6a queue isolation; T-17; RES-2. Composition disclosed rather than hidden behind the availability exclusion. |
| **RR-C** | Untagged payload union; no envelope/payload `task_type` agreement check | **Fixed.** V-11 + discriminated union + `triple_matches_payload` validator in §6.3. |
| **RR-D** | Reference schemas omitted the V-7 handling they should exemplify | **Fixed.** `StrictBase` implements NFC normalization and bidi/zero-width rejection in §6.3. |
| **RR-E** | Door A gave no intent protection while Door B mandated DB-1 — strong door weaker than weak door | **Fixed by construction.** Confirmation unified as an attestation kind available to any adapter (AT-2), mandatory for F-LOW at T2+, configurable for F-HIGH. A-1 narrowed accordingly. |

**Summary.** Of 25 v1.2.0 findings: 15 fixed by construction (the defect becomes structurally impossible), 6 fixed by retiring or narrowing an overclaim, 4 named as explicit residuals with mitigations (RES-1 through RES-5). Three components entered the TCB. Net normative surface decreased.

### C.2 — Findings against v1.3.0

| ID | Finding (v1.3.0) | Disposition in v1.3.1 |
| ---- | ------------------ | ---------------------- |
| **X1** | **Derived-risk forgery.** `risk_level_floor_only` and `fidelity` were transmitted in the receipt and consumed by the Executor to decide whether attestation was required. A single compromised KMS could assert `LOW` on a genuinely floor-T3 action with no attestations and execute it — a single-component break of INV-1-HIGH, and the same defect class as v1.2.0's C2 relocated from the Context Store to the receipt. | **Fixed by construction.** TR-8 requires Executor recomputation from the signed bundle and canonical Proposal; §9.3 steps 7/7a recompute and fail closed on disagreement; §9.2 marks the fields diagnostic; T-18 added; conformance suite 3 tests both forgeries; §10 KMS row corrected. Generalized as RES-8. |
| **X2** | AQ-2 `cap_escalated` marking may create an adversary-influenceable queue channel. | **Open.** Added to §15 open problems. Not yet analysed. |

**Note on review provenance.** The v1.3.0 review that confirmed the v1.2.0 fixes worked through Annex C in order and validated each disposition. That method can only surface defects already labelled; X1 sat in the new machinery and was not found by it. An independent adversarial review — by a party that did not author or revise this document — remains outstanding and is a conformance prerequisite (§14, suite 11).

### C.3 — Findings against v1.3.1, disposed in v1.3.2

| ID | Finding (v1.3.1) | Disposition in v1.3.2 |
| ---- | ------------------ | ---------------------- |
| **X3** | **The published artifact did not verify.** The inline Annex B copy produced `45 verified, 6 errors` under its own stated command — four lemmas (`EvalRiskLevelAcc_ExtensionBound`, `Transposition_Invariance`, `Permutation_Invariance`, `BreadthFitsInt64`) had bodies insufficient for their statements. The same defect *shape* as v1.2.0's FG-6/FG-7 (artifact claims vs artifact behavior), caught this time because §1.1 had honestly labelled the artifact unexecuted. | **Fixed — body-only.** Seven helper lemmas added; all four failing bodies completed; signature-level diff shows additions only, every statement byte-identical. `62 verified, 0 errors` under Dafny 4.9.1 / Z3 4.12.1. Two independent verification passes converged on the same helper decomposition. Full record §1.1. |
| **X4** | **Decorative proof hint.** `FloorDominance`'s body called `TierMax_GeqLeft`, but mutation testing (B.2a M3) showed the theorem verifies without it — the body overstated manual proof work, the FG-7 defect class recurring in the revision that fixed FG-7. | **Fixed.** Hint deleted; the body now discloses SMT case-enumeration discharge per B.2's convention. Found by, and only findable by, the negative-control method — Annex-C-driven review would never have looked. |
| **X5** | **Version-string collision.** v1.3.1 was edited in place after publication (verification-status and Annex B changes under an unchanged version string), producing two documents labelled v1.3.1 with different content. A stale copy reaching a reviewer produced a false finding — the live demonstration of why SR-1 content-addresses schemas and PB-5 forbids epoch reuse. | **Fixed by rule.** This revision is v1.3.2 despite the small normative delta, and §1 now carries a release-integrity rule: revisions are immutable; any normative or Annex-B change, including verification status, increments the version. |

### C.4 — Findings against v1.3.2, disposed (PROPOSED) in v1.3.3

| ID | Finding (v1.3.2) | Disposition in v1.3.3 |
| ---- | ------------------ | ---------------------- |
| **Y1** | **Attestation misbinding — single-component INV-1-HIGH break.** The receipt carries attestation ids and signatures but not the signed Attestation Object, so §9.3 step 7b verifies signature validity but not binding to the executed proposal. A compromised KMS attaches a genuine quorum (raised for P₁) to a receipt for attacker-chosen floor-HIGH P₂; all Executor checks pass; P₂ executes. Third recurrence of the RES-8 class, in the attestation machinery X1's fix introduced. | **PROPOSED, UNCONFIRMED.** AT-8 (transmit full object), TR-10 (verify relations, not names), §9.3 step 7b rewritten to check `obj.proposal_hash == executed hash` and recompute the id. Mechanized in Annex D: `Y1_CurrentCheckAcceptsMisbinding` (defect real), `Y1_AttackBlocked` + `BindingSound` (fix sound), `Y1b_LedgerConsumesRealId` (second-order hole closed). Drafted by a party in the revision history; **suite 11 confirmation required before normative.** |
| **Y1b** | Second-order: even with binding checked, consuming the *transmitted* id lets a KMS substitute a garbage id and preserve the real id's freshness, reopening T-14. | **PROPOSED.** Step 7b(v): recompute `attestation_id` from the object; never read it from the receipt. Mechanized (`Y1b_LedgerConsumesRealId`). |
| **Y2** | Receipt validity *window length* is KMS-chosen; step 5 checked position, not size; L-14's 120 s lived only in the KMS-written value. Long-lived pre-positioned receipts. | **PROPOSED.** Step 5 adds `expires_at − issued_at ≤ 120 s`, Executor-enforced, fail-closed. |
| **Y3** | DS-3 re-drive issues a *new* attestation id — a new idempotency key — in exactly the lost-outcome case DS-1 exists to handle, enabling a doubled floor-HIGH non-idempotent action. | **Was OPEN in v1.3.3; FIXED in v1.3.4** by DS-6 — see C.5. |
| **Y4** | `operator` drives approver-distinctness and the step-9 recheck but is bound to no structure the Executor verifies. | **PROPOSED (folds into AT-8).** Add `operator` to the AT-1 object; Executor takes it from the verified object. |
| **Y5** | Minors: audit-chain genesis; dual JCS/CBOR canonicalization; reconciliation trust domain; nonce-claim liveness. | **CLOSED in v1.3.10.** Genesis specified (AU-8); canonicalization unified on CBOR with a validating decoder (AT-8a, implemented and tested); reconciliation trust domain stated (§11.3); nonce-claim liveness exercised under partition injection. |

**Note.** Y1 was found by mechanical RES-8 field classification (ACP-AUDIT-001), not narrative review — consistent with X1's lesson that the escaped defect lives in the newest machinery. The reviewing party is disqualified from suite 11; Y1 and its fix require independent confirmation.

### C.5 — Findings against v1.3.3, disposed in v1.3.4

Source: **ACP-REVIEW-002**, an independent adversarial review by a party with no authorship or revision history (the §14 suite 11 qualifying condition), which reproduced the Annex D artifact at its published hash, re-ran the published mutation control, and added three probes of its own.

| ID | Finding / result | Disposition in v1.3.4 |
| ---- | ------------------ | ---------------------- |
| **Y1** | **Independently CONFIRMED.** The attack was reconstructed from the v1.3.3 text without reliance on ACP-AUDIT-001's prose. Annex D reproduced: `4 verified, 0 errors` at `sha256:152b97ee…`-era artifact `binding.dfy`; the published mutation control (removing binding clause (ii)) reproduced exactly. | **NORMATIVE.** AT-8, TR-10, step 7b promoted from PROPOSED. |
| **Z0** | **Proof-strength defect in the fix's own model.** The published `Y1_AttackBlocked` confined the attacker to having observed a signature over *exactly one* message — unrealistic, since attesters sign many objects over their lifetime. | **FIXED.** Replaced by `Y1_AttackBlocked_Generalized` (attacker holds arbitrarily many observed signatures, none binding the executed proposal). Same axioms, same skeleton, verified. |
| **Z0b** | **Vacuity risk.** `Y1_AttackBlocked` is a negative result; it would be worthless if `Verify_v133` were unsatisfiable. Not previously checked. | **FIXED.** `HonestPathAccepted` added as a non-vacuity witness. Independent axiom-consistency smoke test (`assert false`) correctly **fails**, confirming `H_Injective` + `Signed` are not contradictory. |
| **Z0c** | **Clause independence unchecked.** The published mutation removed clause (ii) only; clause (i) was never shown load-bearing. | **FIXED.** Weakening (i) to "attester signed *something*" while retaining (ii) breaks `Y1_AttackBlocked` and `Y1b_LedgerConsumesRealId` (3 errors). Both clauses are independently necessary. |
| **Y2** | **CONFIRMED**; fix present and correct. L-14's enforcement point still read "Receipt" in §13 — the normative rule was right, the table was stale. | **NORMATIVE**; §13 L-14 corrected to "Executor (§9.3 step 5)". |
| **Y3** | **CONFIRMED**, and the most serious *open* item in v1.3.3: dispositioned OPEN with no draft text, on the only path that doubles a floor-HIGH non-idempotent action. | **FIXED — NEW, UNCONFIRMED.** DS-6 (action identity ≠ authorization identity), DS-1/DS-3 revised, L-25, T-20, suite 3 vectors. Mechanized: `Y3_RedriveDefeatsDedup` (defect), `Y3_Fixed_RedriveIsDedupped`, `Y3_Fixed_AuthorizationStillFresh`, `Y3_Fixed_DistinctActionsDistinctKeys`. **Drafted in this revision; requires independent confirmation before it is relied upon.** |
| **Y4** | **CONFIRMED**, and found **dispositioned in prose but not implemented**: C.4 said `operator` folds into AT-8, but neither §8.6's AT-8 text nor §9.3 step 7b listed it. The fix did not exist in the normative sections. | **FIXED.** `operator` added to AT-1; step 7b(iii-a) takes operator from the verified object; receipt body `operator` marked diagnostic; `Y4_OperatorTamperDetected` added. *Disclosed:* the v1.3.3 model had no theorem keying on `operator`, so dropping it from the preimage killed nothing — the mutation gap was found by mutating the reviewer's own model. |
| **Y5.2** | **RE-GRADED from informative minor to binding-path requirement.** AT-8 moved object hashing onto the binding path, where two canonicalizers means two ids for one object — a freshness defect in the mechanism Y1b closes. | **FIXED.** AT-8a: canonical CBOR for the Attestation Object, non-canonical encodings rejected. L-26 added. |
| **Z1** | **NEW — MEDIUM.** §8.3.1 states no precedence or associativity for `&&`/` | | `. Two evaluators written independently from the prose disagree on **493 of 10,000** generated cases (4.9%), minimal witness`action != 'deny' \|\| action == 'allow' && action == 'allow'`. Invisible to Annex B (quantifies over parsed`Expr`) and to B.7 item 4 (generates ASTs, not source text) — squarely the model↔production gap. | **FIXED.** EL-1 precedence and associativity rule; suite 8 parser vectors; `diff_prose.py` published as reference method; RES-10 added. **Residual CLOSED in v1.3.5** by `el1_migrate.py`: exhaustive per-bundle check over the truth-assignment space of each rule's atoms, reporting structural divergence, semantic divergence with a witness, and whether the resulting **risk grade** changes. Exit 1 = RK-5 review required before upgrade. |
| **Z2** | **NEW — LOW.** The normative `risk_functions` example used `∩` and `≠ ∅`, operators absent from the §8.3.1 grammar: the specification's own reference bundle was not admissible under its own expression language. | **FIXED.** Example rewritten to `port in SENSITIVE_PORTS`; RK-2a requires registry admission to reject inexpressible conditions and to expand named constants before hashing. |
| **Negative coverage** | Attacked and **not** broken: floor dominance under adversarial Context Store (TR-4); X1 re-attack (derived-risk forgery, closed by steps 7/7a); epoch rollback (RAD-3 high-water + CL-4 + 11.3(d)); nonce/attestation consumption for the *value* leg (CL-1/2/3). | Residual bounded rather than unexamined. |

**Not covered by ACP-REVIEW-002** (and therefore still unreviewed by a qualified party): §§6–7 ingress and output validation, §8.5 accumulators, §11 anchoring operations, and Annex B's proof bodies beyond the parser boundary. Suite 11 remains **partially** satisfied.

### C.6 — Findings against v1.3.4, disposed in v1.3.5

Source: an adversarial pass over v1.3.4's **own newest machinery** (DS-6, AT-8a), per the standing rule that the next escaped defect lives in whatever the last fix introduced. Both findings are in fixes drafted one revision earlier.

| ID | Finding (v1.3.4) | Disposition in v1.3.5 |
| ---- | ------------------ | ---------------------- |
| **Z3** | **Origin substitution — DS-6's own RES-8 defect.** DS-6b required verifying the claimed `origin_nonce` is "recorded as consumed in the ledger" — a **membership** test, not a **pinning** test. A compromised KMS names any other consumed nonce as origin; every check passes (fresh quorum, honest risk, valid AT-8 binding); the idempotency key moves; the target cannot dedup; the floor-HIGH action doubles. Classified **T** against no disclosed residual — a suite-12 conformance failure in the fix for Y3. Fourth recurrence of the class (C2 → X1 → Y1 → Z3). | **FIXED — NEW, UNCONFIRMED.** DS-6f: the ledger claims an immutable `proposal_hash → origin_nonce` binding atomically with the first receipt nonce; the Executor reads origin from the ledger; a receipt-carried value is diagnostic and must match or fail closed. CL-3 gains an origin-binding class with indefinite retention; L-27, T-22, suite 3 vector. Mechanized: `Z3_MembershipCheckDoesNotPinOrigin`, `Z3_Fixed_DistinctProposalsDistinctKeys`. |
| **Z4** | **Encoding split — AT-8a fixed the canonicalizer, not the schema.** Given any optional Attestation Object field, present-as-null and omitted are **each** canonical CBOR, hash to two ids, and claim two ledger slots: one attestation consumed twice. T-14 amplification reopens through the mechanism Y1b closed. Canonicalization rules cannot close it — the ambiguity is in the field set. | **FIXED — NEW, UNCONFIRMED.** AT-8b: closed schema, every AT-1 field REQUIRED, no defaults, no extension points; unknown or missing field ⇒ reject, never normalize. Object extension becomes a breaking `receipt_version` change. L-26 extended, T-23, suite 3 vector. Mechanized: `Z4_OptionalFieldYieldsTwoIds`. |
| **Z1 residual** | v1.3.4 specified no migration tooling for bundles authored under the ambiguous grammar. | **CLOSED.** `el1_migrate.py` — exhaustive over each rule's atom truth-assignment space; reports structural divergence, semantic divergence with witness, and whether the **risk grade** changes; exit 1 = RK-5 review required. Tested against an ambiguous bundle (correctly reports a MEDIUM→HIGH grade change) and its parenthesized form (correctly reports safe). |
| **Suite 12 artifact** | v1.3.4 made the classification table a conformance requirement without providing one. | **DELIVERED.** `ACP-CLASS-001` — 17 Executor inputs, 12 other-consumer inputs, 10 claimed relations, 0 undisclosed T, 2 undischarged relations (both A-7/A-8 human-boundary, both disclosed). |
| **Proof-body honesty** | Two lemmas drafted for the Z3 fix had **tautological postconditions** (`Key_pinned` does not take the claimed value, so "independent of the receipt" is true by typing, not by proof). | **REMOVED**, and the reason recorded in the artifact. This is the X4 class — a proof body asserting something its statement does not earn — caught this time before publication rather than by mutation testing after. |

**Pattern note (five revisions).** C2 → X1 → Y1 → Z3 are the same defect in four locations, and each was introduced by the fix for the previous one. Z4 is the same shape one layer down: a fix (AT-8a) that closed the stated hole and left an adjacent one open in the machinery it added. The operational conclusion is not that the fixes were poor — each was correct for what it addressed — but that **the review target must always be the newest text, and the newest text is always a fix.** §14 suite 12 and the standing instruction in the review brief both encode this; v1.3.5 is the first revision to apply it to its own previous revision as a matter of routine rather than in response to an external review.

**Summary of C.1–C.3.** All three v1.3.1→v1.3.2 findings are instances of the specification's own named defect classes (FG-6/FG-7, RES-8's "trust nothing derived", SR-1/PB-5) recurring against the document itself. The pattern across four revisions is consistent: the architecture's characteristic failure mode — asserting a property without a mechanism that enforces it — applies to the specification process, not only the pipeline. The mechanisms added in response (executed proof, mutation control, differential harness, release rule) are each an enforcement replacing an assertion.

---

## Annex D — Mechanized Binding, Delivery, Release and Signature-Composition Model

**Executed: `36 verified, 0 errors` under Dafny 4.9.1 / Z3 4.12.1.**

**Status.** Part I (Y1/Y1b/Y4 binding) is **NORMATIVE** following independent confirmation (Annex C.5). Parts II–V are **NEW and UNCONFIRMED**, drafted and mechanized by parties now in this document's revision history; §14 suite 11 confirmation is required before they are relied upon.

**File:** `binding_v1_3_8.dfy` — 651 lines, `sha256:0a50e24e974def28ffa93fd12bef02ddf2542c71d1106b79beb26683c7ea4005`
**Command:** `dafny verify --function-syntax:4 binding_v1_3_8.dfy`
**Result:** `Dafny program verifier finished with 36 verified, 0 errors`

**Scope by part.** I–III model abstract hashing and signatures: protocol reasoning, not cryptography (A-3 stands). IV models the release decision only — acknowledgement enters as an input, never as evidence that a human read anything. **V models signature *composition*, not the primitives**: "broken primitive" is `Forge`, an explicit forgery function producing an accepting signature for every message. Whether ML-DSA or Ed25519 resists anything is A-3; what is proven is that the conjunction survives losing either one.

**Two methodological notes, both learned from defects in this artifact.**

*Avoiding the tautology trap.* v1.3.4 published lemmas asserting a derived key was "independent of the receipt" when the claimed value was **not an argument** — true by typing, worthless as proof. Withdrawn (Annex C.6). Parts IV–V keep the claimed value as a **live parameter** whose body ignores it, so independence lemmas constrain the body. The control is empirical: Part IV mutant M1 makes the body read the receipt and five lemmas break.

*Skolemising the attacker.* `Broken` was first written `forall m :: exists sig :: Verifies(...)`. The nested existential gives the solver no trigger for the outer quantifier, so it could not be instantiated at a specific message and three proofs failed. It is now written with an explicit forgery function `Forge(p, k, m)`. This is a modelling improvement, not a weakening: `Forge` **is** the attacker's algorithm, and naming it is more honest than hiding it behind an existential.

| Part | Lemma | Establishes |
| ------ | ------- | ------------- |
| I–III | (13 lemmas, unchanged) | Y1/Y1b/Y4 binding, Y3/DS-6 delivery identity, Z3 origin pinning, Z4 encoding uniqueness. |
| IV | `RV3_TrustedModeAcceptsDowngrade` → `RV3_ModeIndependentOfReceipt` | The v1.3.6 defect and its closure: release mode identical for every receipt. |
| IV | `RV1_UnclassifiedNeverSilent` | An unclassified action can never release silently. |
| IV | `DR9_IrreversibleRequiresNonOperatorAck`, `DR9_OperatorCannotSelfRelease` | No receipt and no sampling draw releases an irreversible action without a non-operator acknowledgement. |
| IV | `DR11_GrindableDrawIsEvadable` → `DR11_DrawIndependentOfRequester` | A requester-derived draw is evadable; an Executor-supplied one is not. |
| **V** | `CR3_AND_SurvivesPQBreak` | **The theorem that justifies hybridation:** with the post-quantum primitive totally broken, no hybrid signature verifies while the classical one still binds. |
| **V** | `CR3_AND_SurvivesClassicalBreak` | Symmetric — the conjunction survives losing either member. |
| **V** | `CR3_OR_CollapsesOnSingleBreak` | Disjunctive composition falls to a single break. |
| **V** | `CR3_OR_IsWeakerThanEitherAlone` | Stronger and the operational point: under OR, breaking *either* primitive suffices — adding an algorithm **reduces** security. |
| **V** | `CR4_IssuerChosenAcceptsDowngrade` → `CR4_FloorRefusesDowngrade` | An issuer-chosen suite walks down to the weakest; a signed floor refuses. |
| IV–V | `NonVacuity_*` (4 lemmas) | Reversible-unsampled releases; irreversible-with-ack releases; sampling fires; honest hybrid signatures verify. Without these every negative above could hold because nothing ever verifies. |

**Mutation controls (all kill).**

| Mutant | Observed |
| -------- | ---------- |
| Parts I–III (binding clause, signature clause, DS-6 key, `operator`, DS-6f origin) | all kill, as v1.3.5 |
| IV-M1 release mode reads the receipt (revert RV-3) | **5 errors** |
| IV-M2 RV-1 default flipped to `REVERSIBLE` | **1 error** |
| IV-M3 DR-9 accepts the operator's own acknowledgement | **2 errors** |
| IV-M4 sampling draw derived from the task | **2 errors** |
| **V-M1 hybrid composition changed from AND to OR** | **2 errors** |
| **V-M2 suite floor check removed** | **1 error** |

**Axiom consistency.** `assert false` fails to verify against Parts I–V (1 error). Part V introduces one uninterpreted function (`Forge`) and no axioms.

**What is NOT proven.** That any human read a notification (DR-7/DR-9 residual, outside any model). That a deployment's notification path is genuinely independent of its presentation path (DR-2 is a property of code, checked by conformance suite 3). That ML-DSA, Ed25519 or SLH-DSA resist anything (A-3). That reversibility classifications or tier floors are honest (A-7, conceded unprovable).

```dafny
// ============================================================================
// Door A — Attestation Binding + Delivery Identity Model (v1.3.4)
// ============================================================================
// Tool:    Dafny 4.9.1 (Z3 4.12.1)
// Command: dafny verify --function-syntax:4 binding_v1_3_4.dfy
//
// Part I  (v1.3.3, retained): Y1/Y1b attestation binding under AT-8 / TR-10.
// Part II (NEW in v1.3.4):    Y3 delivery identity — proves that DS-1's
//         idempotency key must be derived from ACTION IDENTITY, not from
//         attestation_id, or the DS-3 re-drive path admits a duplicate
//         execution; and that the corrected key preserves authorization
//         freshness (re-drive still consumes a NEW attestation).
//
// Additions vs v1.3.3 Part I:
//   * HonestPathAccepted           — non-vacuity witness for Verify_v133.
//   * Y1_AttackBlocked_Generalized — attacker has observed ARBITRARILY MANY
//                                    legitimate signatures, not exactly one.
// ============================================================================

module ACP_AttestationBinding {

  datatype Preimage =
    | PProposal(fields: seq<int>)
    | PObject(phash: Hash, bhash: Hash, epoch: int,
              risk: int, nonce: int, expires: int, operator: int)

  type Hash = int

  function {:axiom} H(p: Preimage): Hash
  lemma {:axiom} H_Injective(a: Preimage, b: Preimage)
    ensures H(a) == H(b) ==> a == b

  type Key = int
  ghost predicate Signed(key: Key, bytes: Hash)

  // AT-1 object. `operator` added in v1.3.4 (closes Y4: the Executor takes
  // operator from the VERIFIED object, never from the receipt body).
  datatype AttObject = AttObject(
    proposal_hash: Hash,
    bundle_hash: Hash,
    epoch: int,
    floor_risk: int,
    att_nonce: int,
    expires: int,
    operator: int)

  function ObjectPreimage(o: AttObject): Preimage {
    PObject(o.proposal_hash, o.bundle_hash, o.epoch, o.floor_risk,
            o.att_nonce, o.expires, o.operator)
  }

  function AttestationId(o: AttObject): Hash { H(ObjectPreimage(o)) }

  datatype AttEntry_v132 = AttEntry_v132(
    transmitted_id: Hash, attester: Key, sig_over: Hash)

  datatype AttEntry_v133 = AttEntry_v133(obj: AttObject, attester: Key)

  // ---------------- v1.3.2 check (the defect, mechanized) ----------------
  ghost predicate Verify_v132(e: AttEntry_v132, executed_phash: Hash)
  { Signed(e.attester, e.sig_over) }

  lemma Y1_CurrentCheckAcceptsMisbinding(
      attester: Key, legit: AttObject, executed_phash: Hash)
    requires legit.proposal_hash != executed_phash
    requires Signed(attester, AttestationId(legit))
    ensures exists e: AttEntry_v132 ::
              Verify_v132(e, executed_phash)
              && e.sig_over == AttestationId(legit)
  {
    var e := AttEntry_v132(AttestationId(legit), attester, AttestationId(legit));
    assert Signed(attester, e.sig_over);
  }

  // ---------------- v1.3.3+ check (AT-8 / TR-10) ----------------
  ghost predicate Verify_v133(e: AttEntry_v133, executed_phash: Hash,
                              trusted_bhash: Hash, trusted_epoch: int,
                              recomputed_risk: int)
  {
    Signed(e.attester, AttestationId(e.obj))          // (i)
    && e.obj.proposal_hash == executed_phash           // (ii) THE BINDING
    && e.obj.bundle_hash == trusted_bhash              // (iii)
    && e.obj.epoch == trusted_epoch
    && e.obj.floor_risk == recomputed_risk
  }

  function LedgerId_v133(e: AttEntry_v133): Hash { AttestationId(e.obj) }

  lemma BindingSound(e: AttEntry_v133, executed_phash: Hash,
                     tb: Hash, te: int, rr: int)
    requires Verify_v133(e, executed_phash, tb, te, rr)
    ensures Signed(e.attester, AttestationId(e.obj))
    ensures e.obj.proposal_hash == executed_phash
  { }

  // NON-VACUITY (NEW v1.3.4). Verify_v133 is satisfiable, so the negative
  // results below are not true merely because nothing ever verifies.
  lemma HonestPathAccepted(attester: Key, o: AttObject)
    requires Signed(attester, AttestationId(o))
    ensures Verify_v133(AttEntry_v133(o, attester), o.proposal_hash,
                        o.bundle_hash, o.epoch, o.floor_risk)
  { }

  // GENERALIZED ATTACKER (NEW v1.3.4). Replaces the v1.3.3 premise that the
  // attester ever signed exactly one message. Here the attester has signed
  // arbitrarily many objects; the only hypothesis is that none of them binds
  // the executed proposal.
  lemma Y1_AttackBlocked_Generalized(
      attester: Key, executed_phash: Hash, tb: Hash, te: int, rr: int)
    requires forall bytes :: Signed(attester, bytes) ==>
               exists o: AttObject :: bytes == AttestationId(o)
                                      && o.proposal_hash != executed_phash
    ensures forall e: AttEntry_v133 ::
              e.attester == attester ==>
              !Verify_v133(e, executed_phash, tb, te, rr)
  {
    forall e: AttEntry_v133 | e.attester == attester
      ensures !Verify_v133(e, executed_phash, tb, te, rr)
    {
      if Verify_v133(e, executed_phash, tb, te, rr) {
        assert Signed(e.attester, AttestationId(e.obj));
        var o :| AttestationId(e.obj) == AttestationId(o)
                 && o.proposal_hash != executed_phash;
        H_Injective(ObjectPreimage(e.obj), ObjectPreimage(o));
        assert e.obj == o;
        assert e.obj.proposal_hash == executed_phash;
        assert false;
      }
    }
  }

  // ---- Y4 (NEW v1.3.4): operator is signature-covered. --------------------
  // Because `operator` is an AT-1 object field, a KMS cannot substitute a
  // different operator without changing the id the attester signed. This is
  // what makes step 7b's distinctness check and step 9's capability recheck
  // key on a verified value rather than a receipt-body claim.
  lemma Y4_OperatorTamperDetected(o1: AttObject, o2: AttObject)
    requires o1.operator != o2.operator
    ensures AttestationId(o1) != AttestationId(o2)
  {
    if AttestationId(o1) == AttestationId(o2) {
      H_Injective(ObjectPreimage(o1), ObjectPreimage(o2));
      assert o1 == o2;
      assert false;
    }
  }

  lemma Y1b_LedgerConsumesRealId(e: AttEntry_v133, executed_phash: Hash,
                                 tb: Hash, te: int, rr: int)
    requires Verify_v133(e, executed_phash, tb, te, rr)
    ensures LedgerId_v133(e) == AttestationId(e.obj)
    ensures Signed(e.attester, LedgerId_v133(e))
  { }

  // ==========================================================================
  // PART II — Y3: DELIVERY IDENTITY (NEW in v1.3.4)
  // ==========================================================================
  // DS-1 keys target idempotency on `attestation_id`. DS-3 re-drives an
  // `indeterminate` outcome "through a new attestation". A new attestation has
  // a new nonce, hence a new id, hence a NEW idempotency key — in exactly the
  // case where the original call may have SUCCEEDED and only its outcome was
  // lost. The target therefore cannot dedup, and the action doubles.
  //
  // Modelled: an Attempt is (authorizing object, action identity). The
  // idempotency key is a function of the attempt. A target dedups two attempts
  // iff their keys are equal. "Doubled execution" = two attempts of the SAME
  // action with DIFFERENT keys.
  // --------------------------------------------------------------------------

  // Stable identity of the action being driven: fixed at first authorization
  // and carried forward across re-drives (DS-6). Modelled as the first
  // receipt's nonce paired with the proposal hash.
  datatype ActionIdentity = ActionIdentity(proposal_hash: Hash, origin_nonce: int)

  datatype Attempt = Attempt(auth: AttObject, action: ActionIdentity)

  // v1.3.3 key (DS-1 as written): derived from the AUTHORIZATION.
  function Key_v133(a: Attempt): Hash { AttestationId(a.auth) }

  // v1.3.4 key (DS-6, proposed): derived from the ACTION IDENTITY.
  function Key_v134(a: Attempt): Hash
  { H(PProposal([a.action.proposal_hash, a.action.origin_nonce])) }

  ghost predicate SameAction(a: Attempt, b: Attempt) { a.action == b.action }
  ghost predicate Dedupped(k1: Hash, k2: Hash) { k1 == k2 }

  // A re-drive per DS-3: same action, but a FRESH attestation object (fresh
  // nonce ==> different object ==> different id). This is what DS-3 mandates.
  ghost predicate IsRedrive(orig: Attempt, re: Attempt)
  {
    SameAction(orig, re) && re.auth.att_nonce != orig.auth.att_nonce
  }

  // ---- NEGATIVE RESULT: the Y3 defect, mechanized. -------------------------
  // Under DS-1's key, a lawful DS-3 re-drive is NOT dedupped by the target.
  lemma Y3_RedriveDefeatsDedup(orig: Attempt, re: Attempt)
    requires IsRedrive(orig, re)
    ensures !Dedupped(Key_v133(orig), Key_v133(re))
  {
    if Dedupped(Key_v133(orig), Key_v133(re)) {
      // equal ids ==> equal objects (injectivity) ==> equal nonces
      H_Injective(ObjectPreimage(orig.auth), ObjectPreimage(re.auth));
      assert orig.auth == re.auth;
      assert orig.auth.att_nonce == re.auth.att_nonce;   // contradicts IsRedrive
      assert false;
    }
  }

  // ---- POSITIVE RESULT: DS-6 restores exactly-once across re-drives. -------
  lemma Y3_Fixed_RedriveIsDedupped(orig: Attempt, re: Attempt)
    requires IsRedrive(orig, re)
    ensures Dedupped(Key_v134(orig), Key_v134(re))
  { }

  // ---- The fix does NOT weaken authorization freshness. --------------------
  // A re-drive still carries a DISTINCT attestation object, so the Consumption
  // Ledger still consumes a fresh id (CL-3 / AT-5 intact). Key stability and
  // authorization freshness are independent properties.
  lemma Y3_Fixed_AuthorizationStillFresh(orig: Attempt, re: Attempt)
    requires IsRedrive(orig, re)
    ensures AttestationId(orig.auth) != AttestationId(re.auth)
    ensures Key_v134(orig) == Key_v134(re)
  {
    if AttestationId(orig.auth) == AttestationId(re.auth) {
      H_Injective(ObjectPreimage(orig.auth), ObjectPreimage(re.auth));
      assert false;
    }
  }

  // ---- Distinct actions never collide on the stable key. ------------------
  // Guards the obvious way to get DS-6 wrong: a key so coarse that two
  // different actions share it would suppress a LEGITIMATE second action.
  lemma Y3_Fixed_DistinctActionsDistinctKeys(a: Attempt, b: Attempt)
    requires a.action != b.action
    ensures Key_v134(a) != Key_v134(b)
  {
    if Key_v134(a) == Key_v134(b) {
      H_Injective(PProposal([a.action.proposal_hash, a.action.origin_nonce]),
                  PProposal([b.action.proposal_hash, b.action.origin_nonce]));
      assert [a.action.proposal_hash, a.action.origin_nonce]
          == [b.action.proposal_hash, b.action.origin_nonce];
      assert a.action.proposal_hash == b.action.proposal_hash;
      assert a.action.origin_nonce == b.action.origin_nonce;
      assert false;
    }
  }

  // ==========================================================================
  // PART III — Z3 / Z4: ORIGIN PINNING AND ENCODING UNIQUENESS (v1.3.5)
  // ==========================================================================
  // Z3. DS-6b (v1.3.4) required the Executor to verify that the claimed
  // `origin_nonce` is "recorded as consumed in the Consumption Ledger". That
  // is a MEMBERSHIP test: it proves the nonce is *a* consumed nonce, not *the*
  // origin nonce of this proposal. A compromised KMS substitutes any other
  // consumed nonce, the idempotency key changes, the target cannot dedup, and
  // the action doubles. RES-8 class, fourth recurrence, in the machinery the
  // Y3 fix introduced.
  // --------------------------------------------------------------------------

  // The ledger's origin binding: claimed atomically at FIRST receipt issuance
  // for a proposal, immutable thereafter. Modelled as a total map from the
  // proposal hash to the pinned origin nonce.
  datatype Ledger = Ledger(origin: map<Hash, int>, consumed: set<int>)

  // v1.3.4 key: origin taken from the RECEIPT (class T -- the defect).
  function Key_transmitted(phash: Hash, claimed_origin: int): Hash
  { H(PProposal([phash, claimed_origin])) }

  // v1.3.5 key: origin taken from the LEDGER (class R/B -- the fix).
  function Key_pinned(l: Ledger, phash: Hash): Hash
    requires phash in l.origin
  { H(PProposal([phash, l.origin[phash]])) }

  // The v1.3.4 check, modelled faithfully: membership only.
  ghost predicate OriginCheck_v134(l: Ledger, claimed_origin: int)
  { claimed_origin in l.consumed }

  // ---- NEGATIVE RESULT: Z3, mechanized. -----------------------------------
  // A claimed origin that passes the v1.3.4 membership check but is not the
  // pinned origin yields a DIFFERENT idempotency key. Dedup is defeated while
  // every stated check passes.
  lemma Z3_MembershipCheckDoesNotPinOrigin(
      l: Ledger, phash: Hash, claimed_origin: int)
    requires phash in l.origin
    requires OriginCheck_v134(l, claimed_origin)      // check passes
    requires claimed_origin != l.origin[phash]        // but it is the wrong one
    ensures Key_transmitted(phash, claimed_origin) != Key_pinned(l, phash)
  {
    if Key_transmitted(phash, claimed_origin) == Key_pinned(l, phash) {
      H_Injective(PProposal([phash, claimed_origin]),
                  PProposal([phash, l.origin[phash]]));
      assert [phash, claimed_origin] == [phash, l.origin[phash]];
      assert claimed_origin == l.origin[phash];
      assert false;
    }
  }

  // ---- POSITIVE RESULT: DS-6f pins the origin. ----------------------------
  // NOTE ON WHAT IS *NOT* PROVEN HERE. "The key is independent of what the
  // receipt claims" is true BY CONSTRUCTION: `claimed_origin` is not an
  // argument of `Key_pinned`. Stating it as a lemma would be a tautological
  // postcondition -- the proof-body honesty defect this document's own
  // mutation testing caught as X4 -- so it is asserted at the type level and
  // deliberately NOT dressed up as a theorem. What genuinely requires proof is
  // that pinning does not over-collapse; that is the lemma below.

  // Distinct proposals still get distinct keys under pinning (no over-collapse).
  lemma Z3_Fixed_DistinctProposalsDistinctKeys(l: Ledger, p1: Hash, p2: Hash)
    requires p1 in l.origin && p2 in l.origin
    requires p1 != p2
    requires l.origin[p1] == l.origin[p2]   // even on a nonce collision
    ensures Key_pinned(l, p1) != Key_pinned(l, p2)
  {
    if Key_pinned(l, p1) == Key_pinned(l, p2) {
      H_Injective(PProposal([p1, l.origin[p1]]), PProposal([p2, l.origin[p2]]));
      assert [p1, l.origin[p1]] == [p2, l.origin[p2]];
      assert p1 == p2;
      assert false;
    }
  }

  // --------------------------------------------------------------------------
  // Z4. AT-8a fixed the CANONICALIZER but not the SCHEMA. If the Attestation
  // Object admits an optional field, two encodings of one semantic object are
  // each canonical, hash to two ids, and claim two ledger slots -- T-14
  // attestation amplification reopens through the mechanism Y1b closed.
  // Modelled: an encoding choice parameter that must not exist.
  // --------------------------------------------------------------------------

  datatype Encoding = Omitted | ExplicitNull

  // An object whose encoding depends on a choice: two preimages, one meaning.
  function EncodeWithChoice(o: AttObject, c: Encoding): Preimage
  {
    match c
      case Omitted      => PProposal([o.proposal_hash, o.att_nonce, 0])
      case ExplicitNull => PProposal([o.proposal_hash, o.att_nonce, 1])
  }

  // ---- NEGATIVE RESULT: Z4, mechanized. -----------------------------------
  lemma Z4_OptionalFieldYieldsTwoIds(o: AttObject)
    ensures H(EncodeWithChoice(o, Omitted)) != H(EncodeWithChoice(o, ExplicitNull))
  {
    if H(EncodeWithChoice(o, Omitted)) == H(EncodeWithChoice(o, ExplicitNull)) {
      H_Injective(EncodeWithChoice(o, Omitted), EncodeWithChoice(o, ExplicitNull));
      assert [o.proposal_hash, o.att_nonce, 0] == [o.proposal_hash, o.att_nonce, 1];
      assert (0 as int) == (1 as int);
      assert false;
    }
  }
  // Reading: the two ids differ, so ONE attestation claims TWO ledger slots.
  // AT-8b (closed schema, all fields REQUIRED, no extensions) removes the
  // choice parameter entirely, which is why the fix is schema-level and cannot
  // be achieved by canonicalization rules alone.
}

// ============================================================================
// PART IV — DEFERRED RELEASE AND REVERSIBILITY (v1.3.7)
// ============================================================================
// Models §9.6 DR-9/DR-10/DR-11 and §8.3 RV-1/RV-3.
//
// SCOPE AND ITS LIMIT, STATED FIRST. DR-9 requires a human acknowledgement.
// Whether the acknowledging human READ the summary is outside any model, and
// nothing below claims otherwise: acknowledgement is an input, not a proof of
// attention. What IS mechanizable is structural, and that is what is proven --
// that no transmitted value can move the release mode, that an unclassified
// action cannot release silently, that the operator's own acknowledgement does
// not satisfy DR-9, and that the sampling draw is not grindable.
//
// METHODOLOGICAL NOTE (avoiding the X4 tautology trap). A previous revision of
// this artifact stated "the key is independent of the receipt" as a lemma when
// the claimed value was not an argument of the function -- true by typing, not
// by proof, and therefore worthless. Here the receipt and the task are kept as
// EXPLICIT PARAMETERS of the recomputing functions even though their bodies
// ignore the receipt. The independence lemmas therefore quantify over a real
// argument and constrain the function BODY. Removing the parameter would make
// the lemmas trivial; keeping it is what makes them evidence.
// ============================================================================

module ACP_DeferredRelease {

  datatype Reversibility = REVERSIBLE | IRREVERSIBLE
  datatype Mode = Silent | Confirmed

  type Task = int
  type Party = int

  datatype Bundle = Bundle(rev: map<Task, Reversibility>)
  datatype Receipt = Receipt(claimed_rev: Reversibility, claimed_task: Task)
  datatype Pending = Pending(operator: Party, confirmed: set<Party>)

  // ---------------- RV-1: fail-safe default ----------------
  function RevOf(b: Bundle, t: Task): Reversibility
  { if t in b.rev then b.rev[t] else IRREVERSIBLE }

  // ---------------- release mode ----------------
  // v1.3.6 (DEFECTIVE): mode keyed on the transmitted class.
  function Mode_trusted(r: Receipt, sampled: bool): Mode
  { if r.claimed_rev == REVERSIBLE && !sampled then Silent else Confirmed }

  // v1.3.7 (RV-3): mode keyed on the class recomputed from the signed bundle
  // and the independently received task. `r` is a live parameter, deliberately
  // unused in the body -- see the methodological note above.
  function Mode_recomputed(b: Bundle, task: Task, r: Receipt, sampled: bool): Mode
  { if RevOf(b, task) == REVERSIBLE && !sampled then Silent else Confirmed }

  // ---------------- DR-9: what release requires ----------------
  // Confirmed mode requires an acknowledgement from a notified party OTHER
  // than the operator (AT-2 distinctness, restated at the release step).
  ghost predicate ReleaseAllowed(m: Mode, p: Pending)
  { m == Silent || (exists w :: w in p.confirmed && w != p.operator) }

  // =========================================================================
  // NEGATIVE RESULTS — the defects, mechanized
  // =========================================================================

  // RV-3 defect: under v1.3.6 a compromised issuer claiming REVERSIBLE obtains
  // Silent mode for an action the SIGNED BUNDLE classifies IRREVERSIBLE.
  lemma RV3_TrustedModeAcceptsDowngrade(b: Bundle, task: Task)
    requires RevOf(b, task) == IRREVERSIBLE
    ensures exists r: Receipt ::
              Mode_trusted(r, false) == Silent
              && RevOf(b, task) == IRREVERSIBLE
  {
    var r := Receipt(REVERSIBLE, task);
    assert Mode_trusted(r, false) == Silent;
  }

  // DR-11 defect: a draw derived from the requester-supplied task is grindable
  // -- the requester searches for a task value that falls outside the sample.
  function Sample_grindable(task: Task, rate: int): bool
  { if rate <= 0 then false else task % 100 < rate }

  lemma DR11_GrindableDrawIsEvadable(rate: int)
    requires 0 < rate < 100
    ensures exists task: Task :: 0 <= task && !Sample_grindable(task, rate)
  {
    assert !Sample_grindable(99, rate);
  }

  // =========================================================================
  // POSITIVE RESULTS — the fixes
  // =========================================================================

  // RV-3 fixed: the recomputed mode is the SAME for every receipt. `r` is an
  // argument, so this constrains the body, not the signature.
  lemma RV3_ModeIndependentOfReceipt(b: Bundle, task: Task, sampled: bool)
    ensures forall r1: Receipt, r2: Receipt ::
              Mode_recomputed(b, task, r1, sampled)
              == Mode_recomputed(b, task, r2, sampled)
  { }

  // RV-1 fixed: an action absent from reversibility.json can never be Silent.
  lemma RV1_UnclassifiedNeverSilent(b: Bundle, task: Task, sampled: bool)
    requires task !in b.rev
    ensures forall r: Receipt :: Mode_recomputed(b, task, r, sampled) == Confirmed
  { }

  // DR-9 end-to-end: for an IRREVERSIBLE action, no receipt and no sampling
  // draw permits release without an acknowledgement from a NON-OPERATOR party.
  // This is the composition of RV-3 and DR-9 and the statement worth having.
  lemma DR9_IrreversibleRequiresNonOperatorAck(
      b: Bundle, task: Task, p: Pending)
    requires RevOf(b, task) == IRREVERSIBLE
    ensures forall r: Receipt, sampled: bool ::
              ReleaseAllowed(Mode_recomputed(b, task, r, sampled), p) ==>
                exists w :: w in p.confirmed && w != p.operator
  { }

  // Corollary, stated separately because it is the operationally load-bearing
  // one: an operator cannot self-release an irreversible action.
  lemma DR9_OperatorCannotSelfRelease(b: Bundle, task: Task, p: Pending)
    requires RevOf(b, task) == IRREVERSIBLE
    requires p.confirmed <= {p.operator}          // only the operator acked
    ensures forall r: Receipt, sampled: bool ::
              !ReleaseAllowed(Mode_recomputed(b, task, r, sampled), p)
  { }

  // DR-11 fixed: the draw is supplied by the Executor; the task is a live
  // parameter and is ignored, so no requester-chosen value moves the outcome.
  function Sample_isolated(draw: int, task: Task, rate: int): bool
  { if rate <= 0 then false else draw % 100 < rate }

  lemma DR11_DrawIndependentOfRequester(draw: int, rate: int)
    ensures forall t1: Task, t2: Task ::
              Sample_isolated(draw, t1, rate) == Sample_isolated(draw, t2, rate)
  { }

  // =========================================================================
  // NON-VACUITY WITNESSES
  // Every theorem above is a negative or an equality. Without these, they
  // could all hold because nothing ever releases.
  // =========================================================================

  lemma NonVacuity_ReversibleUnsampledReleasesSilently(
      b: Bundle, task: Task, r: Receipt, p: Pending)
    requires RevOf(b, task) == REVERSIBLE
    ensures Mode_recomputed(b, task, r, false) == Silent
    ensures ReleaseAllowed(Mode_recomputed(b, task, r, false), p)
  { }

  lemma NonVacuity_IrreversibleReleasesWithAck(
      b: Bundle, task: Task, r: Receipt, operator: Party, approver: Party)
    requires approver != operator
    ensures ReleaseAllowed(Mode_recomputed(b, task, r, true),
                           Pending(operator, {approver}))
  {
    var p := Pending(operator, {approver});
    assert approver in p.confirmed && approver != p.operator;
  }

  // Sampling actually fires for some draw -- DR-10 is not a dead rule.
  lemma NonVacuity_SamplingCanFire(rate: int, task: Task)
    requires 0 < rate
    ensures Sample_isolated(0, task, rate)
  { }
}

// ============================================================================
// PART V — HYBRID SIGNATURE COMPOSITION (v1.3.8)
// ============================================================================
// Models CR-3/CR-4 per the ANSSI hybridation doctrine: a post-quantum
// algorithm is combined with a well-studied classical one, and BOTH must
// verify. The theorem worth having is that the composition survives the total
// break of either primitive -- which is the entire reason to pay for two.
//
// This models COMPOSITION, not cryptography. "Broken primitive" is modelled as
// "the attacker can produce an accepting signature for any message under that
// primitive". Whether ML-DSA or Ed25519 actually resists anything is A-3.
// ============================================================================

module ACP_HybridSignature {

  datatype Primitive = Classical | PostQuantum
  type Key = int
  type Msg = int

  // Per-primitive verification, uninterpreted.
  ghost predicate Verifies(p: Primitive, k: Key, m: Msg, sig: Msg)

  datatype HybridSig = HybridSig(classical: Msg, pq: Msg)

  // CR-3: composition is AND.
  ghost predicate VerifyHybrid_AND(k: Key, m: Msg, s: HybridSig)
  { Verifies(Classical, k, m, s.classical) && Verifies(PostQuantum, k, m, s.pq) }

  // The tempting-but-wrong composition, mechanized so the difference is not a
  // matter of opinion.
  ghost predicate VerifyHybrid_OR(k: Key, m: Msg, s: HybridSig)
  { Verifies(Classical, k, m, s.classical) || Verifies(PostQuantum, k, m, s.pq) }

  // "Primitive p is broken": there is a forgery procedure producing an
  // accepting signature for every message under p. Modelled with an explicit
  // Skolem function rather than a nested existential -- the nested form gives
  // the solver no trigger for the outer quantifier, so it cannot be
  // instantiated at a specific message. This is a modelling choice, not a
  // weakening: `Forge` IS the attacker's algorithm.
  ghost function Forge(p: Primitive, k: Key, m: Msg): Msg

  ghost predicate Broken(p: Primitive, k: Key)
  { forall m: Msg :: Verifies(p, k, m, Forge(p, k, m)) }

  // =========================================================================
  // THE THEOREM: AND survives a single broken primitive.
  // =========================================================================
  // If the post-quantum primitive is broken but the classical one still binds
  // (the attacker cannot sign message m classically), no hybrid signature
  // verifies for m. Symmetrically below.
  lemma CR3_AND_SurvivesPQBreak(k: Key, m: Msg)
    requires Broken(PostQuantum, k)
    requires forall sig: Msg :: !Verifies(Classical, k, m, sig)
    ensures forall s: HybridSig :: !VerifyHybrid_AND(k, m, s)
  { }

  lemma CR3_AND_SurvivesClassicalBreak(k: Key, m: Msg)
    requires Broken(Classical, k)
    requires forall sig: Msg :: !Verifies(PostQuantum, k, m, sig)
    ensures forall s: HybridSig :: !VerifyHybrid_AND(k, m, s)
  { }

  // =========================================================================
  // THE COUNTER-THEOREM: OR does not. One break is total.
  // =========================================================================
  lemma CR3_OR_CollapsesOnSingleBreak(k: Key, m: Msg)
    requires Broken(PostQuantum, k)
    ensures exists s: HybridSig :: VerifyHybrid_OR(k, m, s)
  {
    var forged := Forge(PostQuantum, k, m);
    assert Verifies(PostQuantum, k, m, forged);
    var s := HybridSig(0, forged);
    assert Verifies(PostQuantum, k, m, s.pq);
    assert VerifyHybrid_OR(k, m, s);
  }

  // Corollary, and the operational point: an OR composition is WEAKER than
  // either primitive alone -- the attacker picks whichever is weaker, so
  // adding a second algorithm under OR strictly reduces security.
  lemma CR3_OR_IsWeakerThanEitherAlone(k: Key, m: Msg)
    requires Broken(Classical, k) || Broken(PostQuantum, k)
    ensures exists s: HybridSig :: VerifyHybrid_OR(k, m, s)
  {
    if Broken(PostQuantum, k) {
      var f := Forge(PostQuantum, k, m);
      assert Verifies(PostQuantum, k, m, f);
      assert VerifyHybrid_OR(k, m, HybridSig(0, f));
    } else {
      assert Broken(Classical, k);
      var f := Forge(Classical, k, m);
      assert Verifies(Classical, k, m, f);
      assert VerifyHybrid_OR(k, m, HybridSig(f, 0));
    }
  }

  // =========================================================================
  // NON-VACUITY: the AND composition does accept honest signatures.
  // Without this, the theorems above hold because nothing ever verifies.
  // =========================================================================
  lemma NonVacuity_HonestHybridVerifies(k: Key, m: Msg, sc: Msg, sq: Msg)
    requires Verifies(Classical, k, m, sc)
    requires Verifies(PostQuantum, k, m, sq)
    ensures VerifyHybrid_AND(k, m, HybridSig(sc, sq))
  { }

  // =========================================================================
  // CR-4: suite downgrade. A verifier that accepts the suite named by the
  // message's own issuer can be walked down to the weakest suite; a verifier
  // holding a signed floor cannot.
  // =========================================================================
  datatype Suite = ClassicalOnly | Hybrid
  function Rank(s: Suite): int { match s case ClassicalOnly => 0 case Hybrid => 1 }

  // `claimed` is a live parameter of both, so the independence lemma below
  // constrains the BODY, not the signature (see Part IV methodological note).
  ghost predicate Accept_issuerChosen(floor: Suite, claimed: Suite)
  { true }

  ghost predicate Accept_floorEnforced(floor: Suite, claimed: Suite)
  { Rank(claimed) >= Rank(floor) }

  lemma CR4_IssuerChosenAcceptsDowngrade(floor: Suite)
    requires floor == Hybrid
    ensures Accept_issuerChosen(floor, ClassicalOnly)
  { }

  lemma CR4_FloorRefusesDowngrade(floor: Suite)
    requires floor == Hybrid
    ensures !Accept_floorEnforced(floor, ClassicalOnly)
    ensures Accept_floorEnforced(floor, Hybrid)
  { }
}

```

*End of ACP-SPEC-001 v1.3.8.*
