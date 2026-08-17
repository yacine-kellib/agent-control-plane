# ACP-CLASS-001 — Field-and-Relation Classification Table
**Conformance artifact for ACP-SPEC-001 §14 suite 12**
**Against:** ACP-SPEC-001 **v1.3.11** (regenerated; the prior instance stopped at v1.3.6)
**Method:** RES-8 / RES-9 mechanical classification. Every input any component consumes for a **control decision** is enumerated and classified. Every claimed **binding** on which a control decision depends is enumerated with the verification that discharges it.
**Date:** August 2026

> **Why this regeneration exists.** The prior table classified the Executor's receipt-consumption path and stopped at v1.3.6. Everything built afterwards — the deferred-release gate (DR-\*), reversibility recomputation (RV-\*), and the v1.3.11 audit machinery (AC-5, AU-6/7/8) — introduced **new inputs to control decisions that had never been run through the method**. Running it found two undisclosed **T** entries. By this document's own rule, an unlisted T is a conformance failure, so v1.3.6–v1.3.10 were **non-conformant against suite 12** and did not know it.

---

## 0. Classification key

| Class | Meaning | Conformance status |
|-------|---------|--------------------|
| **R** | **Recomputed** by the consumer from inputs it already trusts | Sound |
| **B** | **Cryptographically bound** to something the consumer already trusts | Sound |
| **T** | **Trusted as transmitted** from the party under verification | **MUST** map to a §10 disclosed residual. Any unlisted **T** is a conformance failure. |

---

## 1. Executor, consuming the Decision Receipt (§9.3)

Re-verified against the current reference implementation: **17 inputs, 13 sound (R/B), 2 disclosed-and-bounded T (`decision`, `tenant_id`), 0 undisclosed T.** No row changed class between v1.3.6 and v1.3.11; see the archived v1.3.6 instance for the row-by-row detail.

> **AMENDMENT (post-v1.3.14) — the sentence above was wrong, and wrong in the way that matters.** An eighteenth input existed and had never been enumerated: the **quorum threshold**, which §9.3 step 7b read as `entries[0]["obj"]["required_count"]` — out of the Attestation Object, i.e. out of the artifact under verification. "0 undisclosed T" was true only because the input was never written down. The failure was one of **enumeration, not classification**; the method cannot classify a row nobody listed, and this row sat in the *oldest* surface the document covers, the one §1 declared settled. See **T-33**.

| # | Input | Consumed for | Class | Disposition |
|---|-------|--------------|-------|-------------|
| 17b | **Quorum threshold** | AT-3: how many distinct approvals a floor-HIGH action requires | **R** (was an unenumerated **T**) | Recomputed from `Bundle.quorum_k`, which is inside `Bundle.hash()`. Mutation-proven load-bearing (Suite 2, `quorum threshold RECOMPUTATION [AT-3]`). |
| 17c | `obj.required_count` | *Nothing.* | — | Retained in AT-1 as signature-covered evidence of what the attester was shown (AT-3), but it is no longer an input to any control decision, so it has no class rather than a class of **T**. |

---

## 2. Deferred-release gate (§9.6, DR-1..DR-12) — **NEWLY CLASSIFIED**

This surface had never been classified. Both findings are here.

| # | Input | Consumed for | Class | Disposition |
|---|-------|--------------|-------|-------------|
| 18 | `pr.risk` | Whether to defer at all | **R** | Recomputed at §9.3 step 7 before the gate is entered. |
| 19 | `pr.reversibility` | Whether DR-9 acknowledgement is mandatory | **R** | RV-3: recomputed from the signed bundle; receipt value ignored. Mutation-proven load-bearing (Suite 2). |
| 20 | `pr.release_at` | Hold-window expiry (DR-1) | **R** | Derived by the Executor as `verified_at + hold`; never transmitted. |
| 21 | `pr.receipt.expires_at` | DR-6 receipt-outlives-hold | **B** | Field of the signature-covered receipt, verified at step 5. |
| 22 | `pr.sampled` | DR-10 mandatory-confirmation draw | **R** | Executor-local CSPRNG (DR-11); not derivable or influenceable by the requester. |
| 23 | `pr.operator` | DR-9 self-confirmation bar | **B** | Taken from the verified Attestation Object (field 13, Y4 fix). |
| 24 | **`note.from_canonical`** | **DR-2 rendering provenance** | **T** | **FINDING T-32 — see §4.** |
| 25 | **`note.source_path`** | **DR-2 path independence** | **T** | **FINDING T-32 — see §4.** |
| 26 | **`delivered` (notifier return)** | **DR-8 delivery completeness** | **T** | **FINDING T-32 — see §4.** |
| 27 | `ack.obj.acknowledger` (confirm / repudiate) | DR-9 acknowledgement identity, DR-5 recipient membership | **B** (v1.3.12+) | ACK-2/ACK-4: signature verified over the canonical object against the bundle-registered key; identity read from the signed bytes. Was **T** through v1.3.11 (**T-31**). |

---

## 3. Audit and accumulators (v1.3.11: AC-5, AU-6/7/8) — **NEWLY CLASSIFIED**

| # | Input | Consumed for | Class | Disposition |
|---|-------|--------------|-------|-------------|
| 28 | Anchor publish result | AU-7 anchor-before-release | **T, bounded** | The anchor service reports its own success. A lying anchor defeats AU-7 at the moment of release. **Bounded**: reconciliation (§11.3 g) runs outside the production trust domain (AU-4) and detects the absence afterwards — prevention degrades to detection, now **disclosed** rather than assumed. |
| 29 | `anchor.up` (outage state) | AU-6 sampling suspension | **R** | The Executor's own view of reachability, not a peer's assertion. |
| 30 | `action_id` for AC-5 dedup | At-most-one increment per logical action | **R** | Derived from `proposal_hash` + ledger-pinned origin nonce (DS-6f); never read from the receipt. |
| 31 | Accumulator count | AC-5 operator lockout | **R** | Executor-local; incremented only at release, after every DR-\* check. Mutation-proven. |
| 32 | Chain head / `prev` | AU-3 hash-chain continuity | **R** | Recomputed over the stored records; reconciliation compares against published anchors. |

---

## 4. Findings

### T-31 — the acknowledgement identity is unauthenticated *(new; the most serious)*

**What the system claims.** DR-9: an irreversible action MUST NOT release without positive acknowledgement from a party that is not the operator. `DR9_IrreversibleRequiresNonOperatorAck` proves exactly this; Suites 1 and 2 both exercise it.

**What the implementation does.** `confirm(proposal_hash, who)` accepts `who` as a **string**. It is checked for membership in `pr.notified` and for inequality with `pr.operator`. **No signature is verified, no key is consulted, no credential is presented.** An irreversible action releases with `human_verified: True` on the strength of a claimed name.

**Why the proof did not catch it.** §04 states that "human acknowledgement enters as an input, never as evidence that a human read anything." The theorem is therefore *sound*: it proves the protocol **given an authentic acknowledgement**. Nothing in the specification or the implementation ever **discharges that assumption**. The model's precondition became the implementation's blind spot.

**Why this is the documented pattern, again.** This is **Y4 restated one layer up**. Y4 was "the operator identity was trusted"; the fix made `operator` a signature-covered AT-1 field. Attestations are signed objects verified against attester keys. **Acknowledgements are not.** The same defect, in machinery introduced by a later fix — the signature this dossier names about itself, occurring again.

*Disposition (normative, v1.3.12):* an acknowledgement MUST be a signed object — `{proposal_hash, acknowledger, timestamp, decision}` — verified against the attester key registered in the signed bundle, with `proposal_hash` compared to the Executor's recomputed hash and the identity taken from the signed bytes, exactly as AT-8/TR-10 already require for attestations. Until then T-31 is a **disclosed T**, and DR-9's guarantee is conditional on the transport authenticating the caller — which the specification does not state and no conformance test checks.

### T-32 — the notifier self-certifies its own independence *(new)*

`from_canonical`, `source_path` and the delivered-recipients set are all **produced by the notification service** and consumed by the Executor as evidence *about that same service*. A compromised notifier that renders through the approval path, labels itself `notify-mobile`, sets `from_canonical = True` and reports full delivery **passes every DR-2 and DR-8 check**. Demonstrated in `reference/suites/class_findings.py`.

This is RES-8 verbatim: *a verifier must never accept a derived security value from the party it is verifying.*

**What was already known, and what was not.** That DR-2 independence is an architectural property not provable by the model is disclosed (§04, §07, conformance suite 3). What was **not** disclosed is that the **runtime check provides no assurance whatsoever** against a compromised notifier — it is a lint against accidental misconfiguration, not a control. The A-8 "two independent compromises" claim therefore rests entirely on build-time and organisational checks, never on anything checked at run time.

*Disposition:* keep the runtime check (it catches honest misconfiguration), relabel it in §9.6 as a **hygiene check, not a control**, and move the DR-2 assurance claim explicitly onto conformance suite 3, with an attestation of separate build provenance for the two render paths.

### T-33 — the quorum threshold was taken from the attestation *(post-v1.3.14; a working exploit, not a theoretical one)*

**What the system claims.** INV-1-HIGH: no single compromised component can cause execution of a floor-HIGH action without a fresh, single-use, quorum-satisfying set of attestations bound to that action's canonical hash.

**What the implementation did.** §9.3 step 7b computed the threshold as `entries[0]["obj"]["required_count"]`. The holder of **one** registered attester key signs a single object that is genuine in every checked respect — correct `proposal_hash`, correct `policy_bundle_hash`, correct `bundle_epoch`, correct recomputed risk, unexpired, correctly signed — and that says the quorum required is **one**. The action executes. Nothing is forged. INV-1-HIGH does not hold, under exactly the adversary it names.

**Why it survived.** Not because the surrounding code was careless: because it was careful. The line sat four lines below `operators`, which *is* cross-checked, inside a loop that verifies every other field of the object meticulously. Density of nearby checking reads as coverage. And the classification method, which exists precisely to catch this, had recorded §1 as needing no row-by-row re-examination — so the enumeration that would have surfaced it was the step that got skipped.

**Why this is the documented pattern, again.** RES-8 verbatim, and the **sixth** recurrence of the class (C2 → X1 → Y1 → Z3 → W1 → T-33). The five before it were each found in machinery a previous fix had introduced, which supported a comforting reading: the class recurs at the frontier. T-33 does not fit that reading. It was in the receipt-consumption path all along.

*Disposition (fixed):* `Bundle.quorum_k` is a required, un-defaulted field inside `Bundle.hash()`, and the threshold is recomputed from it. `required_count` stays in AT-1 as evidence of what the attester was shown, consumed by nothing. An equality check between the two was considered and **not** added: `quorum_k` is inside the bundle hash and every entry's `policy_bundle_hash` is already checked against it, so each attester's signature covers the enforced threshold transitively and the extra check kills no mutant. A check that kills no mutant is not a control.

---

## 5. Relation table (TR-10)

R1–R8 unchanged and **verified**; R9 (rendered screen ↔ canonical proposal) remains a **reduced residual**; R10 (floor ↔ true sensitivity) remains **undischarged and disclosed** (A-7).

**New relations, undischarged:**

| # | Claimed binding | Depended on by | Discharged by | Status |
|---|-----------------|----------------|---------------|--------|
| R11 | Acknowledgement ↔ acknowledging key-holder | DR-9, and the entire irreversible-action guarantee | ACK-2/3/4/5: signature over the canonical object, bound to the recomputed proposal hash, id recomputed and consumed single-use | **Verified** (v1.3.12+; was the **T-31** break). Note the relation is to a *key-holder*, not to a human reading a screen — that remains A-8. |
| R12 | Notification ↔ an independent render path | DR-2, and the A-8 two-compromise claim | Build-time provenance only; the runtime check is self-asserted | **Undischarged at run time — T-32** |

---

## 6. Conformance statement

Against ACP-SPEC-001 v1.3.11 as implemented:

- **32 classified inputs.** With the v1.3.12 fix: 27 sound (R/B), 3 disclosed-and-bounded T (`decision`, `tenant_id`, anchor result), **1 disclosed T remaining (T-32)**. T-31 promoted T→B.
- **Undisclosed T before this regeneration: 2.** Both in machinery added after the last classification. **v1.3.6 through v1.3.10 were non-conformant against suite 12.**
- **10 of 12** claimed relations verified; R9 partially discharged; R10, R11 and R12 undischarged and disclosed.

**The method's own lesson, restated.** Every classification pass has found something, always in the newest machinery: the v1.3.6 pass found the receipt-path defects, and this pass found the gate-path defects the v1.3.6 pass could not have seen because they did not yet exist. **The classification must be regenerated on every release that adds a control input, not once.** Suite 12 is amended to require it.

**And the lesson that lesson got wrong (post-v1.3.14).** "Always in the newest machinery" was the reassuring half of the finding, and T-33 refutes it: an unenumerated **T** sat in the receipt-consumption path — the oldest surface here, and the one §1 declared settled — through every pass. Regenerating on every release is necessary and is not sufficient. **A regeneration must re-enumerate the inputs of a surface, not re-affirm a previous enumeration of it**; a row that was never listed cannot change class, and the count of undisclosed T's is only ever a count of the ones somebody wrote down.

*End of ACP-CLASS-001 (v1.3.11 regeneration).*
