# 05 — Test evidence

Each suite states the invariant it targets, its method, and what it does not cover. Raw output is in `artifacts/test-output.txt` and `artifacts/dafny-output.txt`.

## The criterion

The system works if and only if:

**(A)** the honest path **executes**, and
**(B)** every historical defect, replayed as a live attack, **fails closed** with the right rule firing.

(B) without (A) is trivially satisfied by an executor that refuses everything. That is why the honest path is a first-class test, not a formality.

And (A)+(B) remain insufficient without **(C)**: every check is deleted one at a time, and the corresponding attack must then **succeed**. A passing suite proves nothing until you show it can fail.

---

## Suite 1 — Conformance (44/44)

`python3 artifacts/conformance.py`

Every defect in the history mounted as a live attack against the reference implementation: attestation misbinding (Y1), forged identifier (Y1b), over-long validity window (Y2), operator substitution (Y4), origin substitution (Z3), encoding split (Z4), risk downgrade (X1), nonce and attestation replay, epoch rollback, self-approval, revoked capability, tampered proposal, signature suite downgrade, stripped hybrid signature.

Eight positive paths, which is why the suite total is 44 and not 36: floor-HIGH executes, floor-LOW requires no attestation, DS-6 re-drive is dedupped, a reversible hold releases on silence, floor-LOW is not deferred, a lying screen is caught by repudiation, an irreversible action executes only after acknowledgement, and a sampled action is treated as irreversible. **36 attacks must fail closed; 8 honest paths must execute.**

**Not covered:** attacks nobody thought of. That is the structural limit of any test suite, and the reason the mechanized proofs (§04) exist.

## Suite 2 — Implementation mutation (19/19 kill)

`python3 artifacts/mutate_executor.py`

For each check: delete it, then require the corresponding attack to succeed **and** the honest path to still work — otherwise the mutant is a syntax break, not a weakening.

**Three test-design defects were found by this suite**, and they are worth more than the green result:

- **X1 "survived"**: the attack was blocked upstream by the absence of attestations, not by the check under test. What is load-bearing is that risk is **recomputed and used**, not that it is compared to the receipt — the comparison is detection, not prevention.
- **B-1a "survived"**: defense-in-depth masking; the attestation binding caught the tampered proposal before the rehash mattered. Visible only on a **floor-LOW** action where no quorum exists. *Generalisation: the high-risk path is so heavily defended that it hides whether the low-risk path is sound.*
- **DR-2 "survived"**: the realistic trap is not a notifier proxying the approval UI, but one that renders **honestly** from canonical bytes **through the same formatting library**. It looks independent and is not.

## Suite 3 — Ledger partition (9/9)

`python3 artifacts/partition_suite.py`

CL-6 ("fail closed on partition") could not be exercised against an in-memory ledger that is linearizable by construction. Quorum ledger, 5 replicas, fault injection: minorities refuse, the majority side keeps serving, consumption survives a heal, replica loss is tolerated to the bound then refused. **Quorum intersection is verified by exhaustive enumeration of all 32 splits**, not asserted.

**A real defect found by this suite:** origin binding wrote before checking. Under partition it mutated replicas before detecting disagreement, splitting the binding permanently — a durable denial of service triggered by an ordinary network event, **with no attacker**. Same shape as what CL-6 guards against elsewhere: mutate-then-check. Fixed with two-phase binding (CL-7).

## Suite 4 — Executor × distributed ledger integration (6/6)

`python3 artifacts/partition_integration.py`

Closes the last gap: suites 1 and 3 tested the Executor and the ledger **separately**, so nothing exercised a CL-6 failure landing mid-checklist in §9.3. Covers in particular a partition arriving **between** the nonce claim (step 6) and the attestation claim (7b): the receipt is permanently burned — the documented liveness cost, now exercised.

## Suite 5 — Canonical encoding (8/8)

`python3 artifacts/cbor_suite.py`

RFC 8949 §4.2.1 canonical CBOR with a **validating decoder**: it re-encodes what it parsed and refuses anything not byte-identical. A permissive decoder silently normalises and reopens Z4. Covers key ordering, non-shortest integer arguments, indefinite lengths, trailing bytes, duplicate keys, floats, and the two-encodings-one-value case.

*Traceability note (v1.3.11).* Through v1.3.10 this row was asserted from the decoder in `artifacts/acp_crypto.py`, which implements every refusal path but shipped **no test asserting them**: the 8/8 was a claim without an artifact. `cbor_suite.py` supplies the eight cases. The finding is recorded because a green number with no replay is exactly what §07 tells the reader not to believe.

## Suite 6 — Prose-derived differential

`python3 artifacts/diff_prose.py`

Two evaluators written from the **specification text alone**, then diffed. Produced defect **Z1**: the grammar stated no precedence for `&&` / `||`, and the two faithful readings diverge on **493 of 10,000 cases**. Invisible to the proofs (which quantify over already-parsed expressions) and to the official differential harness (which generates trees, not text).

`artifacts/el1_migrate.py` closes the residual: exhaustive per-bundle check, with a witness and the resulting risk-grade impact.

## Suite 7 — Audit, anchoring and accumulators (11/11, 4/4 mutants)

`python3 artifacts/audit_suite.py` and `python3 artifacts/audit_suite.py --mutate`

Closes the §06 row "normative text written, mechanism not implemented". AC-5, AU-6 (revised), AU-7 and AU-8 existed as clauses only; `artifacts/acp_audit.py` mechanizes them by **extending** the frozen reference gate, so all 19 original mutants and 44 vectors still pass unchanged.

T-28, T-29 and T-30 are replayed as live attacks: repudiated and timed-out Decisions increment nothing and a victim operator is never locked out; a floor-HIGH release with an unreachable anchor fails closed; a post-anchor chain rewrite is detected by reconciliation; an anchoring outage suspends DR-10 sampling so the ATTEST cap cannot compound with DR-9 into approver saturation. AU-8 genesis is anchored at tenant creation and survives destruction of the entire chain. Reconciliation checks §11.3 (g) and (h).

**Three defects were found while building this suite**, and they are the finding, not the 11/11:

- **Anchor-then-mutate.** The first implementation anchored the release record as `pending` and then set it to `executed`. The anchor committed to a superseded chain and reconciliation failed. This is the CL-7 shape — mutate after the commitment point — reintroduced one layer up, by an author who had just read the CL-7 fix. Fixed by anchoring only the terminal record.
- **A masked mutant.** The first AC-5 mutant claimed to isolate the counter, but the T-28 repudiation attack is blocked upstream by DR-4 and never reaches it. Structurally identical to the X1 and B-1a masking in Suite 2. Re-isolated on the re-drive path, the only one that calls the counter twice.
- **A redundant check.** An up-front anchor-reachability pre-check **survived** mutation: deleting it changed no attack outcome, because the terminal guard already fails closed. It was removed rather than retained as decorative defence in depth. A check that kills no mutant is not a control.

**Status.** This is the newest machinery in the dossier. By the document's own pattern the next defect is here. Mechanized and mutation-tested is not independently reviewed; Suite 7 sits inside RR-1 with everything after DS-6.

## Suite 8 — classification findings (4/4 reproduced)

`python3 artifacts/class_findings.py`

Produced by regenerating ACP-CLASS-001 against v1.3.11 (`02b`). Both findings are **undisclosed T** entries — inputs consumed for a control decision, taken as transmitted from the party under verification, never enumerated against a residual. By 02b's own rule that is a conformance failure: **v1.3.6 through v1.3.10 were non-conformant against suite 12 and did not know it.**

These tests pass when the defect is *present*; they invert once the v1.3.12 fixes land.

**Why the regeneration was necessary.** The prior classification stopped at v1.3.6 and covered only the Executor's receipt path. The deferred-release gate, reversibility recomputation and the v1.3.11 audit machinery added 15 new control inputs that had never been classified. Every classification pass this project has run has found something, always in the newest machinery. Suite 12 is amended to require regeneration on every release that adds a control input.

## Suite 9 — ACK-1..ACK-6, the T-31 fix (14/14, mutants 6/6)

`python3 artifacts/ack_suite.py` and `--mutate`

The T-31 tests in Suite 8 pass when the defect is present; these are their inversions. Bare-string acknowledgement, unregistered identity, forged signature, identity swap, operator self-confirmation, cross-action acknowledgement, replay, expiry, over-long window, open schema and decision confusion all fail closed. The honest path still releases, and silence still fails closed for irreversible actions.

**Two mutants survived the first attempt**, and both were findings rather than passes:

- **ACK-4 was masked.** The identity-swap attack is caught upstream by ACK-2, because rewriting `acknowledger` invalidates the signature — the same masking Suite 2 documents for X1 and B-1a. Re-isolated on the operator self-confirmation, where the signature is valid and the returned identity is the only thing deciding the outcome.
- **ACK-5 was redundant.** A gate-local consumed-set duplicated the ledger's CL-3 refusal and killed nothing. Removed; the ledger is now **mandatory**, which is what actually carries single-use. Same disposition as the AU-7 pre-check in Suite 7: a check that kills no mutant is not a control.

## Suite 10 — consolidated registry and composition (73/73, 4/4)

`python3 artifacts/attack_registry.py` and `--compose`

All 73 attacks and positive paths, declared once, each tagged with the rule it targets. `--coverage` renders the clause matrix and, more usefully, what no attack covers: A-7, A-8, T-32, RR-1.

**A defect in the registry itself, disclosed.** The first coverage classifier matched substrings without boundaries, so `AC` matched inside "accepted" and filed the encoding tests under AC-5. A classifier with no boundaries produces confident nonsense; fixed by tagging at collection time instead of guessing from names.

**New coverage: acknowledgement × distributed ledger (4/4).** ACK-5's single-use guarantee depends on the ledger, and no test had put the two together. An acknowledgement arriving with no reachable majority now fails closed (CL-6) rather than being accepted unrecorded; replay is refused on the quorum (CL-2); a heal does not resurrect a consumed acknowledgement.

## Performance measurement

`python3 artifacts/acp_crypto.py`

Floor-HIGH receipt, real cryptography (Ed25519 + ML-DSA-65):

| Metric | Classical | Hybrid | Factor |
|--------|-----------|--------|--------|
| Signature, one signer | 64 B | **3,373 B** | **53×** |
| Signatures on the wire, floor-HIGH receipt (4 signers: receipt + 3 attestations) | 256 B | **13,492 B** | **53×** |
| Verification p99 | ~0.5 ms | **40.7 ms** | ~80× |

**Scientific caveat:** `dilithium-py` is a pure-Python reference implementation; native ML-DSA verifies roughly two orders of magnitude faster. The latency finding is **implementation-bound**. The 53× size factor is **algorithm-bound** and does not go away.
