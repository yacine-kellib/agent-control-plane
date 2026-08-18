# Vector classification — which suite cases can become shared data, and which cannot

**Against ACP-SPEC-001 v1.3.15 · 85 cases across four suites · ACP-1 (VEC-1)**

This file classifies every case in the four suites that a shared vector corpus could
plausibly cover. It is the derivation behind [`OBLIGATIONS.md`](OBLIGATIONS.md); read that
one first if you only want to know what the corpus does **not** prove.

Nothing here is extracted yet. `spec/vectors/` contains this analysis and nothing else.
The count of vector-expressible cases is what sizes extraction (VEC-3/VEC-5); the
obligation list is what sizes VEC-6.

---

## The criterion

A case is **vector-expressible** when all three hold:

1. **Its discriminating input is serialisable.** The thing that decides the outcome lives
   in the bundle tree, the proposal, or the receipt and its attestations — as canonical
   bytes plus at most one declared mutation. Executor-local state, injected objects and
   environment availability do not qualify.
2. **It reaches the decision in one call.** One `execute`, or one `confirm`/`release`
   against a declared starting state. A case that must run twice is testing a
   *transition*, and a transition is not an input.
3. **Its expected outcome is a verdict.** Executes, or fails closed on a named rule.
   Not a ledger record, not a counter, not the identity of a code path.

Otherwise it is an **obligation**: something a conformant implementation must still
prove, on its own, with its own test.

The three tests are separable and it is worth saying which one fires, because they cost
different things to relax. Failing (2) or (3) is structural — no vector schema fixes it.
Failing (1) is sometimes a schema decision that has not been taken yet, and where that
is so the row says which decision.

**Binary, with notes.** There is no third bucket. Where a case is expressible only if the
vector schema grows a feature, it is classified vector-expressible and the note names the
feature — that is a VEC-2 input, not a hedge.

---

## What the corpus cannot carry, and what replaces it

**Signatures are not transportable, so no vector carries one.** This is not new — CLAUDE.md
has said so since v1.3.14 — but it is load-bearing here, because 66 of the 85 cases involve
a signed artifact. If it had no answer, the extractable count would be near zero rather
than 47.

That 66 is the whole set minus the two suites that build no signed artifact at all: the
8 canonical-CBOR cases, which are literal bytes with no keys anywhere, and the 11 audit
cases, which construct held actions directly. Every case in the conformance and
acknowledgement suites signs something.

The answer the repository already uses: **`HybridKey` derives both halves from its seed**,
so declared seed material reproduces the same keypair in any process, in any
implementation. A vector names seeds, not keys, and the consumer signs locally and
verifies locally. `HybridPub.fingerprint` gives the cross-implementation anchor that says
two implementations really did derive the same key:

```
HybridKey(b"k1").public().fingerprint
  == "sha256:38a223bddb2ee525211f7353bc4f578bf025996eeee3a550dc7ead5d0fdce7eb"
```

Verified across two processes while writing this — which is weaker than the sentence
above it claimed. Two Python processes are the same two libraries run twice, and cannot
detect a disagreement *between* libraries; "in any implementation" was an extrapolation.
It has since been carried across. `crates/acp-crypto/tests/python_interop.rs` derives from
the same seeds with `fips204` and `ed25519-dalek`, and gets Python's public key bytes back
on both halves, `k1`'s fingerprint `38a223bd…` included. So the claim holds — but it holds
because two crate stacks implement FIPS 204 Algorithm 6 and RFC 8032 faithfully, not
because a seed is self-describing.

That distinction is the corpus's problem, not the crypto's. **A vector that names a seed
and not the derivation names nothing.** `sha256(seed || "ed")` and `sha256(seed ||
"mldsa")` are wire format: an implementation that hashes the bare seed, or chooses its own
domain separators, derives a different identity and refuses every signature in the vector
— which at the verifier is indistinguishable from a forgery, and in a corpus report is
indistinguishable from a conformance failure it did not commit. VEC-2 must publish the
derivation beside the seed, and the seed alone is not a portable input.

That property is required by `sim.supervise` for an unrelated reason and CLAUDE.md forbids
removing it; the corpus now depends on it too.

This leaves a real limit. ML-DSA signing is hedged, so a vector can say *"sign this object
with the key from seed `k1`"* but never *"the signature is these bytes"*. Cases whose
discriminator is a signature therefore need a **declared mutation vocabulary** — `strip
primitive pq`, `replace primitive pq with zeros`, `add undeclared primitive`, `collapse to
scalar`, `re-sign with an unregistered seed`, `mutate field after signing`. Eight cases
depend on that vocabulary existing. They are marked `sig-mutation` below.

---

## Suite 1 — conformance (52 cases: 9 positive, 43 attacks)

Where a case fails closed, the rule and the raising function were taken from a run, not
from the docstring.

### Positive path (9)

| Case | Class | Why |
| --- | --- | --- |
| `t_honest_high` | **vector** | One `execute`; verdict is executes + risk `HIGH`. Needs declared seeds for the quorum. |
| `t_honest_low` | **vector** | One `execute`, no attestations, verdict is executes + risk `LOW`. |
| `t_honest_redrive` | obligation | Two `execute` calls, and the assertion is that both return the **same** idempotency key. Equality across calls, not a verdict. |
| `t_deferred_holds_then_releases` | obligation | `execute` then `release`, and it asserts the gate's `unverified_releases` counter. Fails (2) and (3). |
| `t_deferred_low_risk_unaffected` | **vector** | One `execute`; verdict is executes with no hold. The gate is present but decides nothing. |
| `t_lying_screen_is_caught_by_notification` | obligation | Compares two rendered texts, then repudiates, then releases. The claim is about two code paths disagreeing — no artifact carries it. |
| `t_irreversible_requires_confirmation` | obligation | `execute` → `confirm` → `release`. |
| `t_sampling_forces_confirmation` | obligation | Injects a sampler (`lambda: 0.0`) to force a probabilistic branch, then runs a sequence. |
| `t_dr13_irreversible_below_high_is_noticed` | obligation | One `execute`, but the assertion is that a notice record exists in the Executor's own ledger with the right recipients. State, not a verdict — fails (3). |

**3 vector · 6 obligation.**

### Attacks (43)

| Case | Class | Rule | Why |
| --- | --- | --- | --- |
| `a_Y1_misbinding` | **vector** | `9.3-7b-ii` | Receipt for P2 carrying P1's genuine quorum. Both artifacts. |
| `a_Y1b_garbage_id` | **vector** | `Y1b` | `attestation_id` field value. |
| `a_Y2_long_window` | **vector** | `L-14` | `expires_at` in the receipt; `_now` is already a declared receipt input. |
| `a_Y4_operator_swap` | **vector** | `AT-2` | Attestation `operator` vs receipt `operator`. Verified to fail closed under the *default* capability context, so the fixture's context change is scene-setting, not the discriminator. |
| `a_Z3_origin_substitution` | obligation | `DS-6f` | Two `execute` calls; the second is a re-drive whose claimed origin is compared against the ledger. |
| `a_Z4_optional_field` | **vector** | `AT-8b` | `sig-mutation`: add a null-valued field and re-sign. |
| `a_X1_risk_downgrade` | **vector** | `TR-8` | Receipt claims `risk_level_floor_only: LOW`. |
| `a_no_attestation` | **vector** | `INV-1-HIGH` | Empty attestation list. |
| `a_epoch_rollback` | obligation | `RAD-3` | Two `execute` calls with the Executor's bundle epoch rolled back between them. The control is a durable high-water mark — a property of the ledger across time. |
| `a_nonce_replay` | obligation | `CL-2` | Same receipt executed twice. |
| `a_T14_attestation_replay` | obligation | `CL-3` | Same attestations under two receipts, executed in sequence. |
| `a_AT2_self_approval` | **vector** | `AT-2` | Operator appears among approvers. |
| `a_AT3_partial_quorum` | **vector** | `AT-3` | One approval where the bundle requires two. |
| `a_ACP28_single_key_asserts_its_own_quorum` | **vector** | `AT-9` | Object states `required_count: 1`. |
| `a_AT9_attesters_signed_for_a_larger_quorum` | **vector** | `AT-9` | Object states `required_count: 3`; two presented. |
| `a_PBDISTINCT_one_key_two_identities` | **vector** | `PB-DISTINCT` | Refuses at bundle construction — zero Executor calls. Needs a **bundle-load verdict class**: the input is a bundle tree alone and the outcome is "refused at load". |
| `a_capability_revoked` | obligation | `9.3-9` | The discriminator is the Executor's live capability context. Nothing in any artifact distinguishes it. Fails (1) structurally — capability state is exactly what must *not* come from the party being verified. |
| `a_tampered_proposal` | **vector** | `9.3-3` | Proposal bytes differ from the receipt's `proposal_hash`. |
| `a_tampered_proposal_low` | **vector** | `9.3-3` | Same, at floor-LOW, where no quorum masks the missing rehash. |
| `a_DR_release_before_window` | obligation | `DR-1` | `execute` → `confirm` → `release`. |
| `a_DR_notification_from_approval_chain` | obligation | `DR-2` | Discriminator is the notifier object's render path. Deployment structure, not data. |
| `a_DR_shared_render_library` | obligation | `DR-2` | Renders honestly but via the approval UI's path. Path identity — the T-32 row in the classification table, classified `T`. |
| `a_DR_notification_undeliverable` | obligation | `DR-8` | Discriminator is a notifier double whose `deliver()` returns fewer recipients than `recipients()`. |
| `a_DR_no_recipients` | obligation | `DR-8` | Notifier double returning an empty recipient list. |
| `a_DR_repudiation_by_outsider` | obligation | `DR-5` | `execute` then `repudiate`. |
| `a_DR_hold_outlives_receipt` | obligation | `DR-6` | Three calls, plus gate hold configuration. |
| `a_DR_hold_exceeds_l14_ceiling` | obligation | `DR-6` | Three calls, plus a 130 s hold configured on the gate. |
| `a_DR9_irreversible_silent_release` | obligation | `DR-9` | `execute` then `release`. |
| `a_DR9_operator_confirms_own_action` | obligation | `DR-9` | `execute` then `confirm`. |
| `a_DR10_sampled_silent_release` | obligation | `DR-9` | Sampler injection plus a sequence. |
| `a_RV3_receipt_claims_reversible` | **vector** | `RV-3` | Receipt claims `REVERSIBLE`. Verified to refuse inside `execute` with **no gate present**, so despite its deferred-gate fixture this is a single-call artifact case. |
| `a_RV1_unclassified_action_defaults_irreversible` | obligation | `DR-9` | Bundle mutation, but the refusal only arrives at `release` — `execute` then `release`. |
| `a_DR13_no_notice_recipients` | **vector** | `DR-13` | Bundle omits `notice_targets` for an irreversible action graded below HIGH. One `execute`. Verified to fail closed under the default capability context too. |
| `a_CR4_receipt_suite_downgrade` | **vector** | `CR-4` | Receipt `alg` is classical-only. |
| `a_CR4_attestation_suite_downgrade` | **vector** | `CR-4` | Attestation objects' `alg` is classical-only. |
| `a_CR4_incomparable_floor` | **vector** | `CR-4` | Bundle field `min_suite: slhdsa128s`; an ordinary hybrid receipt must not satisfy it. |
| `a_CR3_pq_signature_stripped` | **vector** | `9.3-1` | `sig-mutation`: strip the `pq` primitive. |
| `a_CR3_classical_signature_stripped` | **vector** | `9.3-1` | `sig-mutation`: strip the `classical` primitive. |
| `a_CR3_pq_forged_classical_genuine` | **vector** | `9.3-1` | `sig-mutation`: replace the `pq` primitive with zeros. |
| `a_CR3_extra_primitive` | **vector** | `9.3-1` | `sig-mutation`: add an undeclared third primitive. |
| `a_CR2_legacy_scalar_signature` | **vector** | `9.3-1` | `sig-mutation`: collapse the signature map to a bare string. |
| `a_CR1_unknown_suite` | **vector** | `CR-4` | Receipt `alg: rot13`. |
| `a_PBKEY_swapped_attester_registry` | **vector** | `9.3-4` | `sig-mutation`: the receipt is issued under a bundle whose attester registry differs, so its `policy_bundle_hash` no longer matches the Executor's. Needs the vector to carry two bundle trees, or one plus a declared registry mutation. |

**26 vector · 17 obligation.**

---

## Suite 5 — canonical CBOR (8 cases)

The most extractable suite in the repository: literal bytes in, accept or refuse out, no
keys and no state.

| Case | Class | Why |
| --- | --- | --- |
| `t1_canonical_roundtrip_accepted` | **vector** | Canonical bytes accepted and decoding to a stated value. |
| `t2_key_order` | **vector** | Map keys out of canonical order. |
| `t3_non_shortest_argument` | **vector** | Integer with a non-shortest argument. |
| `t4_indefinite_length` | **vector** | Indefinite-length array. |
| `t5_trailing_bytes` | **vector** | Valid item plus trailing garbage. |
| `t6_duplicate_keys` | **vector** | Two identical keys in one map. |
| `t7_floats_refused_both_ways` | obligation | Half of it is a vector — the decoder must refuse a `0xFB` double. The other half is that the **encoder must refuse to produce** a float, which no input-bytes vector can express. The case is listed as an obligation so the encoder duty is not lost; its decoder half should also be extracted. |
| `t8_two_encodings_one_value` | **vector** | Two vectors that must be read as a pair: the canonical encoding accepted, its non-canonical twin refused. Expressible, but the corpus must record the pairing or the point is lost. |

**7 vector · 1 obligation.**

---

## Suite 9 — signed acknowledgement (14 cases)

Every case here starts from an action already held at the gate, and drives one
`confirm` or `release`. **All 14 therefore need the vector schema to admit a declared
`pending_release` precondition** — its fields are plain data, so this is a schema
decision for VEC-2, not a barrier. Cases below are classified on the assumption that the
decision goes that way; if it does not, all 14 become obligations.

| Case | Class | Why |
| --- | --- | --- |
| `t_honest_signed_ack_releases` | obligation | `confirm` then `release`. |
| `t_honest_repudiation_blocks` | obligation | `repudiate` then `release`. |
| `t_T31_bare_string_refused` | **vector** | The acknowledgement is a bare string rather than a signed object. |
| `t_T31_unregistered_identity_refused` | **vector** | `sig-mutation`: signed by a seed the bundle does not register. |
| `t_T31_forged_signature_refused` | **vector** | `sig-mutation`: right identity, unregistered seed. |
| `t_T31_identity_swap_refused` | **vector** | `sig-mutation`: rewrite `acknowledger` after signing. |
| `t_T31_operator_cannot_self_confirm` | **vector** | The acknowledger is the operator named in the held action. |
| `t_ACK3_wrong_proposal_refused` | **vector** | Acknowledgement bound to a different proposal hash. |
| `t_ACK5_replay_refused` | obligation | The same acknowledgement presented twice. Single-use is a transition. |
| `t_ACK6_expired_refused` | **vector** | Declared `now` past the acknowledgement's expiry. |
| `t_ACK6_long_window_refused` | **vector** | `sig-mutation`: over-long `expires_at`, re-signed. |
| `t_ACK1_open_schema_refused` | **vector** | `sig-mutation`: extra field added and re-signed. |
| `t_ACK1_decision_confusion_refused` | **vector** | A `REPUDIATE` object presented to `confirm`. |
| `t_timeout_still_fails_closed` | **vector** | One `release` with no acknowledgement present; verdict `DR-9`. |

**11 vector · 3 obligation.**

---

## Suite 7 — audit, anchor, accumulator (11 cases)

**None of the eleven is vector-expressible, and this is the clearest result in the file.**
The audit layer's claims are all of the form *"after this sequence, the count is N"*,
*"the anchor was published before the release"*, or *"the chain reconciles against the
anchor"*. Every one fails test (2) or (3), and several also fail (1) because the
discriminator is whether an external anchor service is reachable.

| Case | Class | Why |
| --- | --- | --- |
| `t_honest_release_counts_once` | obligation | Asserts an accumulator count **and** that the anchor covers the record before release. Ordering. |
| `t_redrive_increments_once` | obligation | Two hold/release cycles sharing one action id; asserts the count is 1. |
| `t_T28_repudiated_does_not_increment` | obligation | Five cycles with repudiations, then a sixth to prove the victim is not locked out. |
| `t_T28_timeout_does_not_increment` | obligation | Asserts a counter stayed at zero after a refusal. |
| `t_T29_no_anchor_no_release` | obligation | Discriminator is anchor reachability — environment, not data. |
| `t_T29_anchor_drops_mid_release` | obligation | Monkeypatches the anchor to fail between the pre-check and the terminal publish. Timing. |
| `t_T29_post_anchor_rewrite_detected` | obligation | Rewrites committed chain records, then reconciles. |
| `t_T30_outage_suspends_sampling` | obligation | Eleven holds during an outage; counts acknowledgement demands. |
| `t_AU8_genesis_survives_chain_destruction` | obligation | Destroys a chain and checks the anchor still holds evidence. |
| `t_AU8_genesis_anchor_down_fails_closed` | obligation | Tenant construction with the anchor down. |
| `t_reconciliation_clean_on_honest_run` | obligation | Full cycle, then reconciliation returns no findings. |

**0 vector · 11 obligation.**

---

## Totals

| Suite | Cases | Vector-expressible | Obligation |
| --- | ---: | ---: | ---: |
| Conformance (Suite 1) | 52 | 29 | 23 |
| Canonical CBOR (Suite 5) | 8 | 7 | 1 |
| Signed acknowledgement (Suite 9) | 14 | 11 | 3 |
| Audit / anchor / accumulator (Suite 7) | 11 | 0 | 11 |
| **Total** | **85** | **47** | **38** |

Plus **35 mutation cases** — 25 executor, 6 ack, 4 audit — which are obligations by
definition and get no per-case rows: a mutant deletes a line of the implementation's own
source, and no data file can ask another implementation to do that. They are the
repository's evidence that its checks are load-bearing, and that evidence does not
transfer. VEC-6 must ask each implementation to produce its own.

**47 of 85 cases, or 55%, could become shared data.** Every one of the 47 depends on the
seed-declaration mechanism above; eight further depend on a declared signature-mutation
vocabulary; eleven further depend on a `pending_release` precondition block; and one needs
a bundle-load verdict class. None of that is built.

---

## Out of scope, deliberately

Four suites were classified because those four are what ACP-1 names. The gate runs more,
and their absence here is a scope boundary, not a judgement that they are covered:

- **`attack_registry.py` (80)** — the consolidated registry, which re-runs cases from the
  suites above. Classifying it would double-count.
- **`partition_suite.py` (9)** and **`partition_integration.py` (6)** — ledger partition
  behaviour. Sequences and failure injection throughout; expect close to 0 vectors.
- **`llm_agent_suite.py` (44)** — the live-agent client, not the Executor's decision path.
- **`research_bundle.py --attacks` (4)** and **`art_harness.py`** — domain and external
  corpus. The harness reports findings rather than asserting verdicts.
- **`cbor_suite.py` mutation counterparts** — there are none; Suite 5 has no mutants.

If the corpus is meant to cover the partition suites, that is a separate classification
and should be its own ticket.
