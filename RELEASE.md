# ACP-SPEC-001 — package release v1.3.14

**Specification version: unchanged at ACP-SPEC-001 v1.3.13.** This release
changes the reference *implementation*, not the normative document. Nothing in
`spec/ACP-SPEC-001.md` moved: PB-KEY below is the reference finally doing what
§8.2 already required. Under the specification's own release rule (X5) a version
string maps to exactly one document, so re-stamping an unchanged document would
be its own collision — the package version and the spec version are therefore
allowed to differ, and are.

**Date:** August 2026
**Package:** `spec/` + `dossier/` + `reference/` + `crates/` + `services/` + `packages/` + `orchestrator/` + `sim/` + `deploy/` + `tools/`
**Integrity:** `MANIFEST.sha256`, Ed25519 detached signature `MANIFEST.sha256.sig`
**Release key fingerprint:** `SHA256:c6334fda510760d9125e94ce8c900e56` *(verify out of band)*

Reproduce everything in one command:

```bash
./tools/verify.sh            # integrity + signature + proofs + all 14 suites
./tools/verify.sh --suites   # proofs + suites only, no release key needed
```

---

## Unreleased since v1.3.14 — the live-agent client is covered, and a scenario edit is withdrawn

Three changes to `sim/llm_agent.py` and its documentation. None of them touches
the specification, the Executor or any control.

**Suite 10 (44 checks) — the client is no longer untested.** `sim/llm_agent.py`
was the one load-bearing file with no automated check of any kind; its evidence
was hand-runs against the paid API, so a regression in it would have printed
green indefinitely. `call_model()` is split so `parse_model_reply()` can be
handed fixtures, and the suite needs no key and no network. It was mutation-
checked rather than trusted for passing first time. Six mutations, all killed:
disabling the `stop_reason` check kills 5 and reproduces the original defect
verbatim, re-adding a deviation paragraph to the report kills 2, and removing
code-fence stripping, dropping an undecodable `params`, or failing to wrap a
non-list `actions` value kill 1 each. A sixth corrupts an expectation in the
fixture corpus itself, so the data comparison is demonstrably not vacuous. The gate now
prints **16** result lines and covers **118** files.

**A scenario edit is withdrawn.** The poisoned supplier report had been given an
out-of-spec deviation paragraph so that a correct model would have legitimate
work and Phase 1 would stop printing an empty array. That edit was made after
seeing an unwanted result and it produced the wanted one — the shape of changing
the test until it passes. It is reverted; the report is byte-identical to the one
that shipped. The agent's legitimate work now comes from a **separate** document
in the same triage batch, which also gives the demo a property the deviation
never did: the legitimate work and the injected instruction have different
sources, so a reader can see whether text planted in one produces actions
attributed to the other.

**Structured outputs are now disclosed, not just commented.** The client
constrains the *encoding* of the model's reply via a JSON schema on the request.
This is documented as **RES-L1** in §06 with the encoding/content distinction
stated explicitly, and pinned by a suite check that fails if the schema ever
grows an enumeration of permitted actions — which would turn it into a §5.1a
model-side defence. **RES-L2** records the matching limit: no suite can say what
a live model will propose, so Phase 1's outcome is never evidence about the
control plane.

---

## What changed in v1.3.14 — the reference Executor uses real asymmetric signatures

Through v1.3.13 the Python reference modelled signature primitives with
HMAC-SHA256, on a stated and — for almost everything — correct ground:
substituting real COSE changes no control flow, so the protocol properties the
suites test are unaffected by which primitive signs the bytes.

**That ground did not cover the headline claim.** HMAC is symmetric. Verifying a
signature means holding the key that produced it, so `Bundle.attester_keys` and
`Bundle.receipt_key` were *signing* keys, and the Executor held all of them. An
Executor that could verify a quorum could mint one. **INV-1-HIGH — no floor-HIGH
action executes without k independent human attestations — did not hold against a
compromised Executor**, which is one of the adversaries it names. No amount of
protocol testing could have found this, because the defect was key **custody**,
not control flow: all 44 conformance cases passed throughout, and were right to.

What changed:

- **Real primitives.** `classical` → Ed25519 (RFC 8032), `pq` → ML-DSA-65
  (FIPS 204), through `reference/src/acp_crypto.py`, which already implemented
  both. Composition is untouched: CR-1..CR-5 stay conjunctive.
- **The Bundle carries public keys only** (`HybridPub`). No signing key is
  reachable from the verifier, and the type now says so.
- **Deterministic key derivation.** `HybridKey` derived its Ed25519 half from
  its seed but took its ML-DSA half from an *unseeded* `keygen()`. Harmless
  while a key never left one process; fatal across the seven OS processes of
  `sim.supervise`, where each would have minted a different post-quantum key for
  the same identity and every hybrid signature would have failed closed at the
  process boundary. Both halves now derive from the seed (FIPS 204
  `KeyGen_internal`). Seeds are simulation material; a deployment loads keys
  from a KMS.
- **Cost, measured rather than assumed.** `--suites` goes from seconds to
  minutes: pure-Python ML-DSA-65 signs in ~210 ms and verifies in ~34 ms against
  microseconds for HMAC. The gate is a release artifact, not a dev loop, and the
  number is itself the point — `reference/src/acp_crypto.py` prints it.

**Still open, named so it is not mistaken for done:** the carrier is canonical
JSON via `canon()`, not COSE_Sign1 — canonical CBOR is implemented and tested in
`acp_crypto` but is not yet the envelope. And `slhdsa128s` (SLH-DSA, FIPS 205)
is **declared in `SUITES` and not implemented**; it now has its own primitive
name so it cannot be silently satisfied by an ML-DSA key, and it fails closed.

### A correction worth recording — the bundle hash did not cover the key registry

Making the keys asymmetric moved the weight of the design onto the key registry,
and exposed that `Bundle.hash()` never covered it. Spec §8.2 puts `attesters/` —
"approver + confirmer public keys" — inside the bundle tree and signs "SHA-256 of
canonical bundle tree". The reference hashed the floors, the risk functions, the
adapters, the schemas, the reversibility table and the suite floor, and not the
keys.

The honest scope is narrower than it first sounds, and worth stating precisely
because the temptation is to state it larger. It was **not** a live quorum
bypass: an Executor verifies attestations against its own registry, so swapping
one Executor's registry never pushed a forged quorum through another. What broke
is **identity, and therefore audit**. Two bundles authorising different approvers
hashed identically, so `policy_bundle_hash` did not determine who was allowed to
approve — and P-3, "Decisions are replayable bit-for-bit from audit", did not
hold, because the record did not distinguish them. RES-8 family, again: a claimed
binding must be verifiable from the signed bytes of both artifacts.

Closed by **PB-KEY**: the registry is hashed, as a fingerprint over *both*
primitives of each public key — a fingerprint over the classical half alone would
let an ML-DSA key be swapped without moving the bundle hash, which is the
conjunctive CR-3 guarantee undone at the registry rather than at the verifier.
Conformance goes 44 → **45** and the executor mutants 19 → **20**; the new mutant
deletes the coverage and confirms the attack then succeeds, so the check is
load-bearing rather than defence in depth.

---

## What changed in v1.3.13 — the polyglot restructure

A structural release: no rule changed, and every number that replayed in v1.3.12 replays here. The repository was reorganised from a Python-only dossier into a polyglot monorepo so a second implementation surface (Rust, TypeScript) can be held to the same evidence.

- **New layout.** `spec/` (the normative source), `dossier/` (the argument), `reference/` (the Python implementation, `src/ suites/ proofs/`), `crates/` and `services/` (Rust), `packages/`, `orchestrator/`, `deploy/`, `tools/`. `docs/` holds working documents and sits deliberately outside the signed roots.
- **Two gates.** `./tools/verify.sh --suites` runs proofs and all 13 suites without the release key and is the per-commit gate; full `verify.sh` adds integrity and signature and is the release gate. Between releases, sections 1–2 are expected red — a property of offline signing, not a finding. See `dossier/07-REPRODUCTION.md`.
- **Manifest coverage** is now three allowlists (roots, git-tracked, extension) with the signer **halting on an unrecognised file type**, rather than an extension allowlist that silently skipped `.json`, `.rs`, `.ts` and the poisoned `.html` attack fixture. `.gitignore` is itself signed, because the signer derives its file set from it. `sign` builds into temporaries so a mistyped key path cannot destroy the last valid manifest.
- **Five new residuals** from the second implementation surface (RES-P1..P5) are disclosed in `dossier/06-RESIDUAL-RISK.md`. The load-bearing one: splitting the notifier and approval codebases improves build-time provenance but does **not** close T-32, which stays open.
- **Rust and TypeScript are scaffold.** `crates/acp-core` and `acp-crypto` carry the fail-safe defaults and CR-3 hybrid composition with tests; the services exit non-zero so a scaffold cannot be mistaken for a running control plane. `spec/vectors/` — the shared conformance corpus that makes "44/44" mean the same in both languages — is not yet extracted.

### A correction worth recording — the published fingerprint was wrong

For the whole v1.3.13 window, `README.md` published the release-key fingerprint `SHA256:614ea014…`, which belongs to a **superseded key**. `RELEASE.md`, `release-key.pub` and `MANIFEST.sha256.sig` were correct and consistent throughout: the true fingerprint is `SHA256:c6334fda510760d9125e94ce8c900e56`.

Nothing was mis-signed, and no signature ever verified against the wrong value. The damage is narrower and more embarrassing: a reader who performed the out-of-band check the README itself instructs them to perform would have got a **mismatch on an authentic package** — precisely the failure an out-of-band anchor exists to prevent. The document told its most careful readers to distrust it.

Two things are worth noting about how it survived. It was proofread repeatedly without being caught, because a 32-character hex string reads as opaque and correct to a human eye. And it was mechanically derivable from `release-key.pub` the entire time — this repository's own rule is that anything checkable by a command must be checked by a command, and this was not. The rule was right; it had simply never been applied here.

`tools/selftest.sh` now recomputes `sha256(raw pubkey)[:32]` from `release-key.pub` and asserts that **every** `SHA256:` fingerprint in every git-tracked Markdown file matches it, failing also when it finds none, so deleting the line cannot turn the assertion green. The self-test went from 27 assertions to 29, and to **34** in v1.3.14 with the mutant-import guard below and a covered-file-count check. Reintroducing the stale value was confirmed to fail it.

## What changed since v1.3.10

### 1. AC-5, AU-6 (revised), AU-7, AU-8 — implemented

These were normative text with no mechanism: §06 listed them as "closed on paper, not exercised". They are now implemented in `reference/src/acp_audit.py` and attacked in `reference/suites/audit_suite.py` (11/11, plus 4/4 mutants).

The module **extends** the frozen reference gate rather than editing it, so all 44 conformance vectors and all 19 original mutants still pass unchanged.

- **AU-8** — chain genesis is the hash of an anchored tenant-creation record, anchored immediately. A tenant chain destroyed inside its first window still leaves evidence it existed.
- **AU-7** — a floor-HIGH release is covered by an external anchor **before** the action is released; an unreachable anchor fails closed. T-29's pre-anchor rewrite gap is gone; the only rewrite left is post-anchor, which reconciliation detects.
- **AC-5** — accumulators count executions, not Decisions. Repudiated and timed-out actions increment nothing, so T-28's attributed-then-repudiated lockout of a victim operator does not accumulate. A DS-3 re-drive counts once.
- **AU-6** — during an anchoring outage, DR-10 sampling is suspended, so the ATTEST cap cannot compound with DR-9 acknowledgement into approver saturation (T-30 / W2).
- **§11.3 (g)/(h)** reconciliation implemented: executed floor-HIGH records covered by an anchor dated at or before release; every accumulator increment traced to one released execution.

### 2. Suite 5 now has the tests it always claimed

v1.3.10 reported "canonical CBOR 8/8". The validating decoder existed; **no test asserted any of it**. `reference/suites/cbor_suite.py` supplies the eight cases (canonical round-trip, key order, non-shortest argument, indefinite length, trailing bytes, duplicate keys, floats, two-encodings-one-value).

This was a green number with no artifact behind it, in a dossier whose §07 opens by telling the reader not to believe exactly that. Recorded rather than quietly fixed.

### 3. Three defects found while building the above — disclosed

The pattern C2 → X1 → Y1 → Z3 → W1 continues, in the newest machinery, as predicted:

| | Defect | Caught by |
|---|---|---|
| **V1** | **Anchor-then-mutate.** The release record was anchored as `pending`, then set to `executed`; the anchor committed to a superseded chain. The CL-7 shape — mutation after the commitment point — reintroduced one layer up by an author who had just read the CL-7 fix. | reconciliation check (g) |
| **V2** | **A masked mutant.** The first AC-5 mutant did not isolate the counter: the T-28 repudiation attack is blocked upstream by DR-4 and never reaches it. Same masking as X1 and B-1a in Suite 2. Re-isolated on the re-drive path. | mutation harness |
| **V3** | **A redundant check.** An up-front anchor-reachability pre-check survived mutation — the terminal guard already fails closed. Removed rather than retained as decorative defence in depth. | mutation harness |

V3 is the one worth reading twice: the harness refused to credit a check that stopped no attack, and the correct response was deletion, not a better story about it.

### 4. Identifier hygiene

- **RR-n** now denotes residual risks in §06 (was R1/R2, which collided with the R1–R10 *relation* series in `02b`). RR-1 is the absent independent review; RR-2 is A-7 label honesty.
- §01's verification table no longer reads "44/44 fail closed": the suite is 36 attacks failing closed **and** 8 honest paths executing, which is the criterion §05 actually states.
- The 13,492 B figure is identified as a four-signer floor-HIGH receipt (4 × 3,373 B), so it is derivable from what `acp_crypto.py` prints.
- Artifact outputs carry the spec version they were generated against.

### 5. Two concessions added to §06

- **A-8's "two independent compromises" is conditional.** Path independence (DR-2) is an organisational and code-structure property, not one provable from trusted bytes — the same *kind* of assumption as A-7, and Suite 2 already caught an implementation that looked independent and was not.
- **A third composition is named.** On the reversible path the only human control is notification; T-26 says notification degrades through use; A-7 now covers reversibility labels. An action mislabelled `REVERSIBLE` therefore inherits the weakest control in the system, with no attack required.

---

## What has *not* changed

**RR-1 is still open.** No independent adversarial review has taken place. Everything after DS-6 — including all of the above — is mechanized and tested, and **unconfirmed by any party without revision history on this document**. The v1.3.11 machinery is the newest and therefore the most suspect.

**RR-2 is still open and always will be.** No mechanism decides whether a sensitivity or reversibility label matches the world.

This package is sufficient to **evaluate** the architecture. It is not sufficient to deploy it.

---

## Signing

```bash
./tools/sign-release.sh keygen                     # once, on an offline host
./tools/sign-release.sh sign ~/acp-release.key   # regenerate manifest + sign
```

Publish the fingerprint **out of band** — repository README, talk, review brief. A public key that ships only inside the package it authenticates proves nothing, which is the same argument this dossier makes about every other transmitted value.

---

## Open decisions before external publication

Two items need a human decision, not a code change:

1. **ATLAS pinning (§02).** The methodological warning says the ATLAS version and date "must be recorded here" and the field is still blank. Pin it, and resolve `AML.T0110`: it is included with a note that only one source corroborates it, while `AML.T0048` was excluded under a stated two-source rule. Either apply the rule to both or state the exception.
2. **Reviewer selection (RR-1).** The reviewer must read Dafny proof artifacts, not only run a penetration test. §07 names where to start; `acp_audit.py` should be item zero.
