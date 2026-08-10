# ACP-REVIEW-002 — Independent Adversarial Review
**Target:** ACP-SPEC-001 v1.3.3 (`sha256:ddb5a401cb222d37a1403e8f09a85e0792a36dd53280c113f82a2d656fd29741`)
**Against brief:** ACP-REVIEW-BRIEF (§14 suite 11 output requirements)
**Artifacts reviewed:** `binding.dfy` (`sha256:9ac7ae4d78f7cba07865adcf37f726e6a1ee4fa873449fc31c4c0518672f4ee4`), ACP-AUDIT-001
**Date:** August 2026
**Result:** Y1–Y4 confirmed. Three defects found in the Y1 fix's own proof artifact. One new finding (**Z1**, MEDIUM) and one minor (**Z2**). Disposition drafted as v1.3.4.

---

## 1. Independence statement (brief §6.1)

The reviewing party has **no authorship and no revision history** on ACP-SPEC-001, any of its annexes, ACP-AUDIT-001, or the review brief. This satisfies the qualifying condition in §14 suite 11.

**Counter-caveat, stated because the brief asks for judgment about the brief.** This review was performed by a language model. That is not what "independent adversarial party" contemplates for a *publishable* conformance artifact, and this report should be read as narrowing the residual and confirming the mechanized claims — not as closing suite 11. Specifically: every claim below that rests on **execution** (proof runs, mutation kills, differential counts) is reproducible from the published artifacts and commands and should be re-executed by the reader; every claim that rests on **judgment** (severity grading, whether a surface was adequately attacked) carries the weight of the reviewer's standing, which here is limited. Suite 11 needs a human party for the judgment half.

**Coverage boundary.** Attacked: §8.3/§8.3.1/§8.3.2 (expression language, floor/raise), §8.6 (attestation protocol), §9 (receipts, ledger, executor, delivery), §10 (compromise table), §11 (audit), Annex D. **Not attacked:** §§6–7 ingress and output validation, §8.5 accumulators, §11.2/11.3 anchoring *operations*, Annex B proof bodies beyond the parser boundary. Those surfaces are **unreviewed, not clean** — the same warning the brief correctly attaches to ACP-AUDIT-001.

---

## 2. Method per surface (brief §6.2)

| Surface | Method | Result |
|---------|--------|--------|
| Annex D artifact | **Proof re-run** at published hash, plus three probes not in the published control set | Reproduced `4 verified, 0 errors`; 3 defects found in the model |
| §9.3 receipt fields | **Compromise-walk** + independent **RES-8 field classification**, built from the spec text without reading ACP-AUDIT-001's table first | Y1, Y2, Y4 reconstructed independently |
| §9.5 delivery | **Crash-interleaving model**, mechanized in Dafny | Y3 confirmed; fix derived and verified |
| §8.3.1 expression language | **Prose-derived differential**: two evaluators written from the specification text alone, diffed on generated source | **Z1 — new finding**, 493/10,000 disagreements |
| §8.3 reference bundle | Grammar-conformance check of the document's own examples | **Z2 — new minor** |
| §8.3.2, §10 rows | Compromise-walk against the disclosed residuals | No break found (see §5) |

**Method note.** The brief instructed: *redo the RES-8 table yourself from scratch — do not trust ours.* I did, and reached the same three findings by the same mechanical route. Independent rediscovery by an identical method is weaker evidence than rediscovery by a *different* method, so the Z1 result — found by a method **not** in the brief's ranked list — is the more informative outcome of this pass.

---

## 3. Confirm / refute on Y1–Y4 (brief §6.5)

**Y1 — CONFIRMED (critical, as stated).** Reconstructed from the v1.3.3 text alone: the receipt carries `{attestation_id, kind, attester, sig}`; the AT-1 object additionally binds fields the receipt omits (`att_nonce`, object `expires_at`); therefore the Executor cannot reconstruct the signed bytes and step 7b-as-written can verify *that* an attester signed, never *what*. A compromised KMS attaches P₁'s genuine quorum to attacker-chosen floor-HIGH P₂ — recomputed risk is honestly HIGH, so TR-8 is satisfied without a lie, which is precisely why the attack routes around X1's fix. Single component, unauthorized floor-HIGH execution, INV-1-HIGH broken as written.

**Y2 — CONFIRMED.** Fix present and correct in v1.3.3 step 5. §13's L-14 row still named "Receipt" as enforcement point — stale table, correct rule. Corrected in v1.3.4.

**Y3 — CONFIRMED, and it was the most serious *open* item.** DS-1 keys idempotency on `attestation_id`; DS-3 mandates re-drive "through a new attestation", which necessarily carries a new nonce, hence a new id, hence a **new idempotency key** — presented to the target in exactly the case where the original call may have committed and only its outcome was lost. v1.3.3 dispositioned this OPEN with no draft text, on the one path that doubles a floor-HIGH non-idempotent action (§2.1 rows 5–6). Mechanized both directions and drafted DS-6; see §4.

**Y4 — CONFIRMED, and found to be *dispositioned but not implemented*.** Annex C.4 stated `operator` "folds into AT-8". It does not: neither AT-8's text in §8.6 nor step 7b in §9.3 listed `operator` among the object fields. The fix existed in the disposition table and nowhere in the normative sections. This is worth flagging as a process observation — a disposition table entry is a claim about the document, and nothing was checking it.

---

## 4. Findings (brief §6.3)

### Z0 / Z0b / Z0c — Three defects in the Y1 fix's own proof artifact

Per the brief's instruction to attack the *proposed fix* as the newest machinery:

- **Z0 — the attacker premise was too strong.** `Y1_AttackBlocked` confined the attacker to having observed a signature over **exactly one** message (`forall bytes :: Signed(attester,bytes) ==> bytes == AttestationId(legit)`). Real attesters sign many objects. Replaced by `Y1_AttackBlocked_Generalized`: the attacker holds **arbitrarily many** observed signatures, hypothesis only that none binds the executed proposal. Same axioms, same skeleton, verified.
- **Z0b — vacuity was unchecked.** `Y1_AttackBlocked` is a negative result and would be worthless if `Verify_v133` were unsatisfiable. Added `HonestPathAccepted` (an honest entry does verify) and an axiom-consistency smoke test: `assert false` against `H_Injective` + `Signed` **correctly fails**, so the axioms are not jointly contradictory. Without this, all ten theorems could be vacuously true.
- **Z0c — clause independence was unchecked.** The published mutation removed binding clause (ii) only. Weakening clause (i) to "the attester signed *something*" while retaining (ii) breaks `Y1_AttackBlocked` and `Y1b_LedgerConsumesRealId` (3 errors). Both clauses are independently load-bearing.

### Z1 — Expression grammar states no operator precedence (NEW — MEDIUM)

**Component:** Policy Engine and Executor evaluators (not a compromised-component finding; a specification-ambiguity finding).

**Claim broken.** §8.3.1's production `Expr ::= Term (("&&" | "||") Term)*` places both connectives at one level with **no precedence and no associativity rule**. "The" evaluated meaning of a mixed rule is therefore not a property of the specification — it is a property of whichever parser reads it.

**Evidence.** Two evaluators written from the prose alone (`diff_prose.py`): one a literal left-to-right fold of the flat production, one the C-family default (`&&` tighter). **493 disagreements in 10,000 cases across two seeds (4.9%).** Minimal witness:

```
action != 'deny' || action == 'allow' && action == 'allow'      with action = 'delete'
  flat left fold            -> false
  && binds tighter than ||  -> true
```

Metamorphic checks (Annex B Theorems 2/3/4/6 — permutation invariance, base bound, extension monotonicity, floor dominance) pass **0 violations under both readings**, which is the point: the ambiguity is invisible to every property the document proves.

**Why the assurance apparatus missed it.** Annex B quantifies over an already-parsed `Expr` datatype, so the parser is outside the proof TCB (B.4). B.7 item 4's harness generates well-formed triples as **ASTs**, never as source text, so it structurally cannot observe a parse divergence. Z1 sits exactly in the model↔production gap the brief nominated as where a formal reviewer adds value.

**Consequences.** (a) Independently-built Engine and Executor evaluators compute different floor-only risk for one bundle; §9.3 step 7a then fires a critical alert **indistinguishable from KMS compromise** — which P-5 names as the exact confusion the differential suite exists to prevent. Safety holds (fail-closed), the alert channel does not. (b) Worse, where both evaluators share one parser there is **no observable disagreement at all**, and the bundle author's intent silently diverges from evaluated meaning: a rule meant as `(X && Y) || Z` may evaluate as `X && (Y || Z)` and grade a floor-HIGH action MEDIUM. Nothing detects this. It is an A-7-class governance defect enabled by an ambiguous normative grammar.

**Disposition (v1.3.4).** EL-1 — `&&` binds tighter than `||`, both left-associative, production refined. Suite 8 gains **source-text** parser vectors run against the deployment's own parser. RES-10 added. `diff_prose.py` published as reference method.

**Residual — read this before upgrading.** EL-1 fixes the grammar prospectively. **Bundles authored under the ambiguous grammar may already encode the wrong meaning.** Every existing bundle must be re-parsed under EL-1 and the resulting risk grades diffed against production behaviour; a silent grade change is a floor-honesty event requiring RK-5 review, not a routine deploy. No migration tooling is specified.

### Z2 — The reference bundle is not expressible in the reference grammar (NEW — LOW)

§8.3's normative `risk_functions` example used `port_range ∩ SENSITIVE_PORTS ≠ ∅`. Neither `∩` nor `≠ ∅` appears in the §8.3.1 grammar, and named `constants` have no resolution rule in the expression language. The document's own example bundle would be rejected by a conformant registry. Fixed by rewriting to `port in SENSITIVE_PORTS` and adding RK-2a (admission MUST reject inexpressible conditions; constants expand before hashing, so a constant-table change is a bundle change under PB-4/RK-5).

### Y5.2 re-graded — dual canonicalization is now on the binding path (MEDIUM, was informative)

ACP-AUDIT-001 filed JCS/CBOR duality as an informative minor. **AT-8 promotes it.** The id the ledger consumes is now `SHA-256(canonical(obj))`; two canonicalizers means two ids for one object, so a re-encoded object claims a fresh ledger slot — a freshness and single-use defect **in the mechanism Y1b exists to close**. Fixed by AT-8a (canonical CBOR for the Attestation Object; non-canonical encodings rejected, not re-serialized) and L-26.

This is the pattern worth naming: **the Y1 fix moved a minor onto the critical path.** C2→X1→Y1 each lived in machinery the previous fix introduced; Y5.2 is now sitting in that seat.

---

## 5. Negative coverage (brief §6.4)

Surfaces attacked that **did not** break. The brief is right that a report without this section is worthless.

| Surface | Attack attempted | Outcome |
|---------|------------------|---------|
| **Floor dominance (TR-4, §8.3.2)** | Adversarial Context Store; sought any raise sequence evaluating below the signed floor | **Held.** Raises are max-combined and floor comes from the signed bundle; step 7 ignores raises entirely for floor-only recomputation. Metamorphic 4×4 lattice: 0 violations under both parser readings. |
| **X1 re-attack (derived-risk forgery)** | KMS asserts lower `risk_level_floor_only` / stronger `fidelity` | **Closed.** Steps 7/7a recompute and fail closed on disagreement. This is *why* Y1 had to attack the binding instead of the value. |
| **Epoch rollback (RAD-3, T-15)** | Single-KMS replay of a genuine superseded bundle | **Closed.** Durable high-water mark, indefinite retention (CL-4), reconciliation 11.3(d). |
| **Attestation replay (T-14) — value leg** | Reuse a consumed attestation on a second receipt | **Closed** by CL-3. The *binding* leg is Y1; the replay leg is sound. |
| **Y3 fix over-collapse** | Make DS-6's key coarse enough to suppress a legitimate second identical action | **Guarded.** `Y3_Fixed_DistinctActionsDistinctKeys` proves distinct actions never share a key; DS-6d makes a coarser key a conformance failure. |
| **Y3 fix freshness regression** | Use key stability to reuse an authorization | **Guarded.** `Y3_Fixed_AuthorizationStillFresh` — the re-drive still consumes a distinct attestation (AT-5/CL-3). |

Two composition attempts also failed to produce anything beyond the disclosed residuals: RES-2 (induced fail-closed → attestation flood) composed with AQ-2's `cap_escalated` marking, and the AT-4 re-run racing a Context sync. Neither reached floor-HIGH execution. **These were attacked shallowly and should not be treated as cleared** — §8.6a's own open problem about `cap_escalated` as an adversary-influenceable channel remains the right place to look.

---

## 6. Verification record

All commands reproducible; toolchain `dafny 4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2`, Z3 4.12.1.

| Run | Command | Result |
|-----|---------|--------|
| Reproduce published Annex D | `dafny verify --function-syntax:4 binding.dfy` | `4 verified, 0 errors` — matches |
| Published mutation control | remove binding clause (ii) | `2 verified, 2 errors` — kills, as claimed |
| **New probe** — clause (i) weakened | "signed something", (ii) retained | `1 verified, 3 errors` — kills |
| **New probe** — axiom consistency | `assert false` | **fails to verify** — axioms consistent |
| **New probe** — non-vacuity | `HonestPathAccepted` | verifies |
| v1.3.4 model | `dafny verify --function-syntax:4 binding_v1_3_4.dfy` | `10 verified, 0 errors` |
| v1.3.4 mutation set | 4 mutants (binding clause, sig clause, DS-6 key reverted, `operator` dropped) | **4/4 kill** |
| Prose differential | `python3 diff_prose.py` | 10,000 cases, **493 disagreements**; metamorphic 0 violations |

**Self-disclosure.** The `operator` mutant did **not** kill against my first v1.3.4 model: no theorem keyed on `operator`, so the Y4 fix was structurally present but formally unexercised. `Y4_OperatorTamperDetected` was added in response. Recorded because it is the document's own recurring class — an assertion without an enforcing mechanism — occurring inside the proof artifact written to close it.

---

## 7. Recommendation

**Ship v1.3.4 as Draft.** Y1/Y1b/Y2/Y4/Y5.2/Z1/Z2 are fixed and mechanized where mechanizable. Two items block a Final label:

1. **DS-6 (the Y3 fix) is new and unconfirmed.** It was drafted and mechanized by this reviewer, who is now — by the document's own release rule — disqualified from confirming it. Independent confirmation required before it is relied upon.
2. **Suite 11 remains partially satisfied.** §§6–7 ingress, §8.5 accumulators, and §11 anchoring operations were not attacked here, and the judgment half of the review needs a human party.

**Highest-value next pass, by this document's own pattern:** attack DS-6 and AT-8a. They are the newest machinery, and the pattern across C2 → X1 → Y1 → Y5.2 is that the next escaped defect lives in whatever the last fix introduced. DS-6b in particular introduces a new receipt field (`idempotency_key`) and a new ledger query (origin-nonce consumption), both of which are TR-10 obligations that a careless implementation will get wrong in the familiar direction — by trusting the transmitted value.

*End of ACP-REVIEW-002.*
