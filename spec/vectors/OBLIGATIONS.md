# Obligations — what passing the vector corpus does not prove

**First draft · against ACP-SPEC-001 v1.3.15 · produced by ACP-1 (VEC-1)**
**Completed by VEC-6 (ACP-3), which this draft exists to size.**

Read this before the corpus, not after it.

A shared conformance corpus expresses **input → verdict**. It hands an implementation a
set of bytes and asks what it decides. That is a real and useful thing to check across
languages, and it is a **minority of the evidence this repository actually relies on**.

**Of 85 cases in the four suites, 47 could become shared data and 38 could not.** The
whole audit suite is in the second group: **0 of 11.** On top of those 38 sit **35
mutation cases**, which no data file can ever carry.

Passing every vector in the corpus is therefore a **partial** claim. An implementation
that passes all of them and does nothing else has demonstrated that it refuses the inputs
it was handed. It has not demonstrated that its checks are load-bearing, that its
orderings hold, that its notification path is genuinely a second path, or that its
accumulators count what they claim. Those are the obligations below, and they are
**per-implementation duties**: each implementation must discharge them with its own tests
and publish the result.

The derivation for every line here — which of three tests each case fails, and the run
that established it — is in [`CLASSIFICATION.md`](CLASSIFICATION.md).

---

## The reason this file is not a formality

Mutation testing cannot find a check that was never written. Suite 2's sixth lesson in
`dossier/05-TEST-EVIDENCE.md` records the case: for four releases, 24 mutants ran green
against a real gap in the handling of irreversible actions below floor-HIGH — **correctly**,
because there was no check present to delete. Only an external adversarial corpus found it.

The same limit applies here, one level up. A vector corpus is a set of inputs somebody
thought of. It says nothing about the input nobody thought of, and it cannot notice that a
rule is missing rather than wrong.

Concretely, and worth stating because it is recent and checkable: **three of the six
defects fixed on the `feat/rule-store` branch would have been invisible to any vector in
this corpus.** A bundle hash that silently dropped a field, a published file count that
had drifted from the signer's, and a fail-safe default that set a value nothing read — none
of them changes a verdict on any input. A corpus that had existed and been green
throughout would have been green through all three.

---

## Obligation 1 — sequences

The corpus presents one input and reads one verdict. These cases are about what happens
on the **second** call, and a transition is not an input. There is no way to write them as
data without the vector format becoming a scripting language, at which point it is no
longer a portable artifact.

| Case | Suite | Rule | The transition |
| --- | --- | --- | --- |
| `a_nonce_replay` | conformance | `CL-2` | The same receipt executed twice. |
| `a_T14_attestation_replay` | conformance | `CL-3` | The same attestations under two receipts. |
| `a_Z3_origin_substitution` | conformance | `DS-6f` | A re-drive whose claimed origin is checked against the ledger's pinned one. |
| `a_epoch_rollback` | conformance | `RAD-3` | A genuine but superseded bundle, refused by a durable high-water mark. |
| `t_honest_redrive` | conformance | `DS-6` | Two executions must return the **same** idempotency key. |
| `a_DR_release_before_window` | conformance | `DR-1` | Execute, confirm, then release too early. |
| `a_DR_repudiation_by_outsider` | conformance | `DR-5` | Execute, then a non-recipient repudiates. |
| `a_DR_hold_outlives_receipt` | conformance | `DR-6` | A hold longer than the receipt's validity. |
| `a_DR_hold_exceeds_l14_ceiling` | conformance | `DR-6` | A hold above the L-14 ceiling that no legal receipt can outlive. |
| `a_DR9_irreversible_silent_release` | conformance | `DR-9` | Silence is not consent for an irreversible action. |
| `a_DR9_operator_confirms_own_action` | conformance | `DR-9` | The operator confirms their own action. |
| `a_DR10_sampled_silent_release` | conformance | `DR-9` | A sampled reversible action released on silence. |
| `a_RV1_unclassified_action_defaults_irreversible` | conformance | `DR-9` | An unclassified action must not be releasable by silence. |
| `t_irreversible_requires_confirmation` | conformance | `DR-9` | Positive acknowledgement releases; nothing else does. |
| `t_honest_signed_ack_releases` | ack | — | Confirm, then release. |
| `t_honest_repudiation_blocks` | ack | `DR-4` | Repudiate, then release must fail. |
| `t_ACK5_replay_refused` | ack | `ACK-5` | An acknowledgement is single-use. |
| `t_sampling_forces_confirmation` | conformance | `DR-10` | A sampled reversible action inherits the confirmation duty, so an approver cannot learn that ignoring notifications is always safe. Injects a sampler to force the branch, then runs the sequence. |

**18 cases.**

---

## Obligation 2 — assertions about state, not verdicts

These reach their decision in one call, and then assert something about the
implementation's own records. A verdict is portable; a ledger is not.

| Case | Suite | What is asserted |
| --- | --- | --- |
| `t_dr13_irreversible_below_high_is_noticed` | conformance | The action **executes**, and a notice record naming the right recipients exists in the Executor's ledger beforehand. The verdict alone is indistinguishable from the defect it closes. |
| `t_deferred_holds_then_releases` | conformance | Released on silence **and** counted as an unverified release. |

**2 cases.** Both are worth reading closely by anyone building a second implementation:
in each, the verdict is "it executed", which is exactly what the pre-fix code also did.
The whole content of the check is in the record.

---

## Obligation 3 — structural properties of the deployment

The discriminator is which **code path** produced something, or how the deployment is
wired. No byte in any artifact carries it. This is the family the corpus is least able to
touch, and the one where the residual risk is highest.

| Case | Suite | Rule | The structure |
| --- | --- | --- | --- |
| `a_DR_notification_from_approval_chain` | conformance | `DR-2` | A notifier that sources its text from the approval chain is not a second channel. |
| `a_DR_shared_render_library` | conformance | `DR-2` | The realistic trap: renders honestly from canonical bytes, but through the approval UI's own path. One compromise lies to both channels at once. |
| `a_DR_notification_undeliverable` | conformance | `DR-8` | Delivery reaches fewer recipients than were named. |
| `a_DR_no_recipients` | conformance | `DR-8` | No reachable recipient at all. |
| `t_lying_screen_is_caught_by_notification` | conformance | `DR-4` | The positive form: a compromised approval screen is caught **because** the second channel renders the canonical bytes independently. |

**5 cases.** These are the rows classified `T` — trusted as transmitted — in
`dossier/02b-CLASSIFICATION-TABLE.md`, and they are why **T-32 is open**. The Executor
currently takes the notifier's word for the notifier's own independence. A vector cannot
fix that, and neither can splitting the two services into separate codebases: closing T-32
means the Executor checking two distinct signed service identities named in the signed
bundle. Until then this obligation is discharged by construction and by review, not by
test.

---

## Obligation 4 — environment and executor-local state

The discriminator is something the Executor knows or can reach, not something it was
handed. Note that this is not a weakness in the vector format — it is the **point** of
RES-8. A capability that could be asserted by an artifact would be a security value
accepted from the party being verified.

| Case | Suite | Rule | The state |
| --- | --- | --- | --- |
| `a_capability_revoked` | conformance | `9.3-9` | Authority revoked between issuance and execution. Live context, deliberately not transmissible. |
| `t_T29_no_anchor_no_release` | audit | `AU-7` | The anchoring service is unreachable. |
| `t_T29_anchor_drops_mid_release` | audit | `AU-7` | Reachable at the pre-check, gone before the terminal publish. |
| `t_AU8_genesis_anchor_down_fails_closed` | audit | `AU-8` | A tenant cannot be created without an anchored genesis. |

**4 cases.** `t_T29_anchor_drops_mid_release` also carries a timing element no data file
expresses: the anchor must fail *between* two points in one release.

---

## Obligation 5 — the audit layer, in full

Beyond the three anchor-reachability cases above, the remaining audit cases assert counts
and orderings over sequences. **All 11 audit cases are obligations**; these are the other
seven.

| Case | Rule | What must be shown |
| --- | --- | --- |
| `t_honest_release_counts_once` | `AU-7`, `AC-5` | The record is anchored **before** the release, and the operator's accumulator increments exactly once. Ordering is the whole claim. |
| `t_redrive_increments_once` | `DS-3` | Two releases of one logical action increment once. |
| `t_T28_repudiated_does_not_increment` | `AC-5` | Five actions attributed to a victim and repudiated leave the deny-effect accumulator at zero — and the victim is not locked out afterwards. |
| `t_T28_timeout_does_not_increment` | `AC-5` | A refusal does not increment. |
| `t_T29_post_anchor_rewrite_detected` | `AU-4` | The one rewrite that anchoring leaves possible is detected on reconciliation. |
| `t_T30_outage_suspends_sampling` | `AU-6` | During an anchoring outage, reversible actions demand zero acknowledgements while irreversible ones still demand theirs. |
| `t_AU8_genesis_survives_chain_destruction` | `AU-8` | A destroyed tenant chain still leaves evidence in the anchor. |
| `t_reconciliation_clean_on_honest_run` | — | An honest run reconciles with no findings. |

**8 cases here; 11 across the suite**, the other three being the anchor-reachability cases
in Obligation 4. An implementation may pass every vector in the corpus while having no
audit chain at all.

---

## Obligation 6 — duties on the encoder

A vector supplies bytes and asks whether they are accepted. It cannot ask whether an
implementation **refuses to produce** something.

| Case | Suite | Rule | The duty |
| --- | --- | --- | --- |
| `t7_floats_refused_both_ways` | CBOR | `WE-1` | The decoder must refuse a float — that half **is** extractable and should be. The encoder must refuse to *emit* one, and that half is an obligation. |

**1 case.** Small, and listed because dropping it would silently halve a check that was
deliberately written to run in both directions.

---

## Obligation 7 — the mutation suites

**35 mutants: 25 executor, 6 acknowledgement, 4 audit.**

These work by reading the implementation's own source, deleting a named check, rebuilding
it in a temp directory and asserting that the matching attack now **succeeds**. They are
the repository's evidence that its checks are load-bearing rather than decorative — the
answer to "how do you know that `if` does anything?"

**No data file can ask another implementation to delete a line of its own source.** A
second implementation must build its own mutation harness against its own source, or state
that it has not.

This is the largest single body of evidence that does not transfer, and it is the one most
likely to be quietly skipped, because a corpus-green implementation looks finished. Three
cautions carry over with it:

- **A check that kills no mutant is not a control** — but redundancy claims are claims
  about the attacks you enumerated.
- **Deletion mutants cannot catch a check that is present and means the wrong thing.**
- **Nothing at all catches a check that was never written.** Only an adversary who is not
  you does that.

---

## Summary

| Obligation | Cases |
| --- | ---: |
| 1 — sequences | 18 |
| 2 — assertions about state | 2 |
| 3 — structural properties of the deployment | 5 |
| 4 — environment and executor-local state | 4 |
| 5 — the audit layer (remainder) | 8 |
| 6 — duties on the encoder | 1 |
| 7 — mutation suites | *(35 mutants, no case rows)* |
| **Total cases** | **38** |

Vector-expressible: **47**. Obligations: **38**. Mutants, additionally: **35**.

---

## What an implementation should publish

Until VEC-6 (ACP-3) settles the format, the honest minimum is that a second
implementation claiming conformance states, separately:

1. Which vectors in the corpus it passes, and which it does not.
2. Which of the obligations above it has discharged, with what test, and where that test
   can be read.
3. Which it has **not** discharged. An unclaimed obligation is a disclosed gap. An
   undisclosed one is the defect this whole document exists to prevent.

A conformance claim that reports only (1) is reporting the smaller half.
