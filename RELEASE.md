# ACP-SPEC-001 — release v1.3.13

**Date:** August 2026
**Package:** `spec/` + `dossier/` + `reference/` + `crates/` + `services/` + `packages/` + `orchestrator/` + `sim/` + `deploy/` + `tools/`
**Integrity:** `MANIFEST.sha256`, Ed25519 detached signature `MANIFEST.sha256.sig` (111 files)
**Release key fingerprint:** `SHA256:c6334fda510760d9125e94ce8c900e56` *(verify out of band)*

Reproduce everything in one command:

```bash
./tools/verify.sh            # integrity + signature + proofs + all 13 suites
./tools/verify.sh --suites   # proofs + suites only, no release key needed
```

---

## What changed in v1.3.13 — the polyglot restructure

A structural release: no rule changed, and every number that replayed in v1.3.12 replays here. The repository was reorganised from a Python-only dossier into a polyglot monorepo so a second implementation surface (Rust, TypeScript) can be held to the same evidence.

- **New layout.** `spec/` (the normative source), `dossier/` (the argument), `reference/` (the Python implementation, `src/ suites/ proofs/`), `crates/` and `services/` (Rust), `packages/`, `orchestrator/`, `deploy/`, `tools/`. `docs/` holds working documents and sits deliberately outside the signed roots.
- **Two gates.** `./tools/verify.sh --suites` runs proofs and all 13 suites without the release key and is the per-commit gate; full `verify.sh` adds integrity and signature and is the release gate. Between releases, sections 1–2 are expected red — a property of offline signing, not a finding. See `dossier/07-REPRODUCTION.md`.
- **Manifest coverage** is now three allowlists (roots, git-tracked, extension) with the signer **halting on an unrecognised file type**, rather than an extension allowlist that silently skipped `.json`, `.rs`, `.ts` and the poisoned `.html` attack fixture. `.gitignore` is itself signed, because the signer derives its file set from it. `sign` builds into temporaries so a mistyped key path cannot destroy the last valid manifest.
- **Five new residuals** from the second implementation surface (RES-P1..P5) are disclosed in `dossier/06-RESIDUAL-RISK.md`. The load-bearing one: splitting the notifier and approval codebases improves build-time provenance but does **not** close T-32, which stays open.
- **Rust and TypeScript are scaffold.** `crates/acp-core` and `acp-crypto` carry the fail-safe defaults and CR-3 hybrid composition with tests; the services exit non-zero so a scaffold cannot be mistaken for a running control plane. `spec/vectors/` — the shared conformance corpus that makes "44/44" mean the same in both languages — is not yet extracted.

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
