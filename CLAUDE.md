# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A security dossier for **ACP-SPEC-001** (Agent Control Plane), a reference implementation, a business simulation, and — as of the polyglot restructure — the beginnings of the control plane as real services.

It is not a product. It is an argument, and its discipline is that **every claim must replay on the reader's machine**. `README.md` says so explicitly: "If a claim here does not replay on your machine, don't believe it."

That framing drives most of the rules below. A change that makes a number in the prose stop matching a number the code prints is a defect, even if the code is correct.

## Commands

```bash
./tools/verify.sh --suites         # proofs + 15 suites + harness — THE PER-COMMIT GATE, no key needed
./tools/verify.sh                  # + integrity and signature — the release gate
./tools/selftest.sh                # tests the tooling itself (76 assertions)
./tools/sign-release.sh list       # what the next signature will cover (no key needed)
./tools/codegen.sh                 # regenerate Rust + TS types from spec/schemas/ (--check to verify)
./tools/sync-counts.sh             # re-derive every published count (--check to report drift)

# individual suites — run from reference/suites/, they use flat imports
cd reference/suites
PYTHONPATH=../src python3 conformance.py          # 52/52
PYTHONPATH=../src python3 attack_registry.py      # 81/81  (--compose → 4/4)
PYTHONPATH=../src python3 mutate_executor.py      # 25/25  deletes each check, asserts the attack succeeds
PYTHONPATH=../src python3 ack_suite.py            # 14/14  (--mutate → 6/6)
PYTHONPATH=../src python3 audit_suite.py          # 12/12  (--mutate → 4/4)
PYTHONPATH=../src python3 partition_suite.py      # 9/9
PYTHONPATH=../src python3 partition_integration.py # 6/6
PYTHONPATH=../src python3 cbor_suite.py           # 8/8
PYTHONPATH=../src python3 research_bundle.py --attacks  # 4/4  Annex D domain attacks
PYTHONPATH=../src python3 llm_agent_suite.py       # 44/44  the live-agent client — no API key, no network
PYTHONPATH=../src python3 bundle_suite.py          # 32/32  the policy bundle: walk, tree hash, verify-on-read
PYTHONPATH=../src python3 art_harness.py           # a HARNESS, not a suite: it reports findings and
                                                   # fails only if it is broken or vacuous. Corpus is
                                                   # fixtures until load_corpus() is wired to real ART.

# the simulation — run from the repo root, it is a package
python3 -m sim.bundle --check      # 15/15 grading table asserted
python3 -m sim.run_day             # the day, one process
python3 -m sim.supervise           # the day, seven real OS processes
python3 -m sim.supervise --checks  # process-isolation properties only
python3 -m sim.scoreboard          # the deliverable
python3 -m sim.acceptance          # 11 pass, 1 partial, 0 fail

cargo check --workspace && cargo test --workspace   # Rust: 116 tests
pnpm install && pnpm -r typecheck                   # TypeScript: 5 projects
```

Dependencies: `cryptography` and `dilithium-py`. Since v1.3.14 **`sim/` needs them too** — it signs with real hybrid keys, so the old "standard library only" claim is dead. Dafny is optional — the proof step is skipped if absent.

**The gate now takes ~2 minutes, not seconds.** Pure-Python ML-DSA-65 signs in ~210 ms. That is the measured cost of real post-quantum signatures and is not a regression to optimise away.

## The two gates

`./tools/verify.sh` sections 1–2 are integrity and Ed25519 signature. **Only the key holder can make them green**, because regenerating the manifest requires the offline release key. Between releases they are expected to be red.

- **`--suites`** — proofs + 15 suite lines + the external-corpus harness. No key. Green at every commit. A clean run prints **18** result lines (1 prerequisites + 1 proofs + 15 suites + 1 harness).
- **full** — the above plus integrity and signature. Green at a tagged release.

**Never "fix" a red integrity line by regenerating `MANIFEST.sha256`.** A regenerated manifest whose signature no longer verifies is strictly worse than a stale one, and nobody but the key holder can repair it.

## Architecture

```
spec/          THE NORMATIVE SOURCE — ACP-SPEC-001.md, schemas/, vectors/
dossier/       THE ARGUMENT — 00–07, annexes/. Not code.
reference/     Python. Permanent. src/ suites/ proofs/
crates/        Rust — acp-core, acp-crypto, acp-conformance
services/      executor policy ledger anchor (Rust) · notifier approval (TS)
packages/      TS — acp-types (generated), acp-client
orchestrator/  TS — advances the clock, decides nothing
sim/           the business simulation (companion to Annex D)
deploy/        docker-compose.yml  (no k8s/ — the substrate is deliberately deferred,
               see `git show main:docs/plans/roadmap.md`)
tools/         verify.sh sign-release.sh selftest.sh codegen.sh sync-counts.sh
docs/          working documents — deliberately OUTSIDE the signed roots
```

**`spec/` is the only normative source.** Rust and TypeScript types are *generated* from `spec/schemas`, never hand-written. A hand-written type is a second definition of the same object, and two definitions of one object is the encoding-split defect at the source level.

**`reference/` is permanent.** Python is the readable artifact — someone can follow the §9.3 checklist line by line in `acp_executor.py`. It is also the differential partner for Rust: the first divergence between the two on a shared vector is a specification ambiguity, which is exactly how Z1 was found.

`reference/suites/conformance.py` is **also a shared fixture library**, imported by 7 other suites as `import conformance as C`. It is not a leaf script.

The suites reach `reference/src` via `PYTHONPATH`, exported by `tools/verify.sh`. Keep sys.path manipulation in the runner, not in library code.

**Most of `crates/`, `services/`, `orchestrator/` and `deploy/` is scaffold.** Every service `main()` exits non-zero so a scaffold cannot be mistaken for a running control plane. What is genuinely implemented: the fail-safe defaults in `acp-core`; in `acp-crypto`, CR-3 hybrid composition, the real Ed25519/ML-DSA-65 primitives, and `custody.rs` (the `Signer` trait and tiers T0–T3, with T2/T3 declared-not-implemented behind the `kms`/`hsm` features); and the canonical tree hash in `acp-bundle`.

**Rust signs now, so both differential directions are checked.** `tests/python_interop.rs` verifies Python's signatures in Rust; `tools/check-rust-signatures.py` verifies Rust's in Python, and `selftest.sh` runs it — a cross-language claim that no gate executes is the `sim/bundle.py` shape that let `ResearchBundle.hash()` drop three fields for several releases.

## Rules specific to this repository

**Never fork `reference/src/*.py`. Import them.** Those modules carry mutation-test markers in comments — `# AU-7-anchor-before-release (mutation target)`, `# AC-5-anchor-release (do not move)`, `# AU-6-suspend-sampling`. `mutate_executor.py`, `ack_suite.py --mutate` and `audit_suite.py --mutate` locate checks by reading the source text and deleting them, then assert the matching attack succeeds. A copied-and-edited executor silently voids the repository's own evidence. When new domain behaviour is needed, subclass and extend (see `sim/release.py:ResearchGate`).

**Mutation suites read source files by path** and rebuild them in a temp dir. They resolve `reference/src` explicitly and **strip `PYTHONPATH` from the mutant subprocess** — if it leaked, a failed copy would silently import the real module and the mutant would report SURVIVE, recording a load-bearing check as redundant. Check these first after any restructure: they break in ways that still print green. 25 + 6 + 4 = **35 mutants** must keep being killed. Each mutant temp dir must also receive `acp_crypto.py`, which `acp_executor` hard-imports; without it the mutant dies at import and is reported **ERROR**, never KILL — an unrun mutant is not a caught one, and `tools/selftest.sh` asserts exactly that.

**Make the code work. Never shape the test around the code.** The failure mode this repository is most exposed to is not a bug, it is a green run that means nothing — and every incentive points at manufacturing one, because the whole argument rests on numbers replaying. So:

- **A test that cannot fail is worthless**, and worse than worthless here, because it is published as evidence. Before claiming a check covers something, *make it fail on purpose*: delete the branch, drop the call, break the copy, and watch the suite go red and name the thing. That experiment is the claim; the passing run is not.
- **Never weaken an assertion, special-case an input, or relax a fixture to get green.** If a suite goes red, the code is wrong until proven otherwise. Changing the expected value is legitimate only when the underlying reality genuinely moved — and then the commit says which reality moved and why.
- **Never resolve a finding by retuning the thing that found it.** `art_harness.py` says this about its own fixture floors, and the rule generalises: raising a floor, loosening a policy or narrowing a corpus until a finding disappears proves only that the instrument is adjustable. Fix what was measured, not the measurement.
- **A check that kills no mutant is not a control** — but read that with the fourth and sixth lessons in `dossier/05-TEST-EVIDENCE.md`. Redundancy claims are claims about the attacks you enumerated. Deletion mutants cannot catch a check that is present and means the wrong thing. And nothing at all catches a check that was never written; only an adversary who is not you does that.
- **Where a branch genuinely cannot carry a mutant, say so and prove the alternative.** DR-13's `record_notice` raises nothing, so no attack succeeds when it is deleted — that was verified by dropping only the commit and confirming conformance goes 51/52 and the harness raises. Label such a branch a positive-path obligation. Do not dress it up as a control, and do not leave the coverage claim unproven.

**`MANIFEST.sha256` is signed with an offline Ed25519 key.** Coverage is three allowlists and no deny-list: **roots** (the ten directories in `ROOTS`), **git-tracked** (`git ls-files`, so build outputs are excluded because they are gitignored), and **extension** (plus `LICENSE` and `Dockerfile` by name). The signer **halts on an unrecognised file type** rather than silently signing or silently skipping it. `.gitignore` is itself signed, because the signer derives its file set from it. Editing *any* covered file invalidates the manifest — this has already happened once to `README.md` via editor auto-format.

`sign` builds into `.tmp` files and moves them into place only after the signature exists, so a mistyped key path cannot destroy the last valid manifest.

**The central discipline: RES-8 / RES-9 / RES-10.** *A verifier must never accept a derived security value from the party it is verifying.* This class of defect has recurred five times in the document's history (C2 → X1 → Y1 → Z3 → W1), each time in machinery the previous fix introduced. Practical consequences:

- A value the consumer needs must be **recomputed** from the signed bundle, never read from the message. See `TR-8` (risk), `RV-3` (reversibility), and `sim/policy.py:_cross_program` (program ownership — both sides come from the bundle, because a compromised agent writes the whole proposal).
- A claimed **binding** between artifacts must be verified from the signed bytes of both. A transmitted identifier is a name for a binding, not evidence of one.
- Conformance suite 12 requires every control input to be classified **R** (recomputed), **B** (bound), or **T** (trusted as transmitted), with every `T` enumerated against a disclosed residual. An unlisted `T` is a conformance failure.

**T-32 is OPEN and must stay open until it is actually closed.** The notifier self-certifies its own independence; `note.source_path`, `note.from_canonical` and `delivered` are classified **T**. Splitting `services/notifier` and `services/approval` into separate codebases improves *build-time* provenance, which R12 already credits — it does **not** move those rows off T, because the Executor still reads them from the party it is verifying. Closing it means the Executor checking two distinct signed service identities named in the signed bundle.

**`services/notifier` and `services/approval` share nothing above the wire format.** `@acp/types` is the one permitted common dependency — it *is* the wire format. No shared template engine, formatter, sanitiser, date helper or component library. Each keeps its own `render.ts`; factoring them together is not a refactor, it is the vulnerability (DR-2). If a linter flags the duplication, the linter is wrong.

**Fail-safe defaults are deliberate and must not be "helpfully" relaxed.** Resource absent from `floors.json` ⇒ `T3`. Action absent from `reversibility.json` ⇒ `IRREVERSIBLE`. Action with no risk function ⇒ refused at `8.4-3`, *not* graded HIGH. IRREVERSIBLE below floor-HIGH with no entry in `notice_targets` ⇒ refused at `DR-13`, because a notice with no addressee is not a detection channel. Unknown is never LOW (P-4).

**A fail-safe default that changes no outcome is documentation, not a control.** RV-1's absent-⇒-`IRREVERSIBLE` rule was reachable only through the floor-HIGH gate for four releases, so below HIGH it set a value nothing read — an unclassified action executed exactly as if it had defaulted to `REVERSIBLE`. DR-13 (v1.3.15) gave it effect on both paths. When adding a default, name the branch that reads it; when reviewing one, check that a branch does.

**Do not add model-side defences.** No filtering, scoring or judging of model output anywhere. The architecture assumes the model is manipulable and its guarantees do not depend on injection failing; adding a content filter and relaxing a Door A control on its strength is an explicit conformance failure (§5.1a). In demos the model must be shown complying fully — simulating a refusal misrepresents the claim.

**Crypto is real in both languages, and the Bundle holds public keys only (v1.3.14).** `classical` → Ed25519, `pq` → ML-DSA-65, via `reference/src/acp_crypto.py`. The *hybrid composition* (CR-1..CR-5, conjunctive — verification requires **every** primitive, never any) lives in `acp_executor`, not in the crypto module, so a mutation of `all` → `any` still has something real to break.

The reason this stopped being a modelling detail is worth keeping: HMAC is symmetric, so the verifier held the signing keys and a compromised Executor could mint its own quorum — INV-1-HIGH did not hold, and no protocol test could have shown it, because the defect was key **custody**. **Never reintroduce a symmetric primitive "just for tests".** The remaining gaps are named in `acp_executor`'s CRYPTO DISCLOSURE: COSE_Sign1 is not the carrier, and `slhdsa128s` is declared but not implemented (its own primitive name `pq-slh`, fails closed — do not alias it to `pq`).

`HybridKey` derives **both** halves from its seed. It must stay that way: `sim.supervise` is seven OS processes, and an unseeded ML-DSA keygen gives each process a different key for the same identity. That was a real defect, found by this rule not existing.

**Conformance vectors are defined over canonical bytes and declared mutations, never over signatures.** Signatures are still not portable across implementations, but the reason changed in v1.3.14 and the old one ("Python signs with modelled HMAC") is dead: both sides now use FIPS 204 / RFC 8032. What remains is that ML-DSA signing is hedged (randomised) unless a deployment pins deterministic signing, and that a vector carrying a signature would have to carry key material to be checkable. Revisit as part of ACP-1/VEC-1. Passing the corpus stays a **partial** claim: vectors express input → verdict, not the 35 mutants, ordering properties such as AU-7 anchor-before-release, partition behaviour, or render-path distinctness. Those are per-implementation obligations.

## Writing style for this repository

The prose is deliberately self-critical and states limits before strengths — `dossier/06-RESIDUAL-RISK.md` comes before the positive claims in the reading order, and `README.md` has a "What this does not claim" section. Match it. Specifically:

- When something does not fully hold, report it as **partial** and say why. `sim/acceptance.py` returns `"PARTIAL"` for criterion 1 rather than a green tick, because the fast path *does* claim a receipt nonce and the criterion as written is not satisfiable by a conformant implementation. A suite that returns all-pass on its first run has usually been written to agree with itself.
- Corrections are published, not quietly fixed. Annex D contains a paragraph beginning "A correction worth recording"; `acp_ack.py` documents a check that mutation testing showed was decorative and was therefore *removed* rather than kept as defence in depth. Follow that pattern: a check that kills no mutant is not a control.
- Comments explain *why a rule exists and what breaks without it*, usually citing the rule id and the defect it closes. Avoid comments that restate the code.

## Testing the tooling

Anything checkable by a command must be checked by a command, not by inspection and not by asking a model. `tools/selftest.sh` exists for that: it proves `list` and `sign` agree, that the signer halts on unknown file types, that a bad key leaves `MANIFEST.sha256` byte-identical, that `--suites` prints 18 result lines with no failures, that a mutation suite whose mutants cannot import reports ERROR rather than KILL, and that every file count published in prose equals the number the signer actually covers. Three real defects have been found by writing those assertions.

## Current state

On `main`: the restructure and scaffold, the Docker demonstrator, the HTTP ingress, the real-signature swap, and `sim/llm_agent.py` with its suite and fixture corpus. `RELEASE.md` is stamped v1.3.14 and carries *Unreleased since v1.3.14* sections for everything after it.

**`feat/rule-store` is open and unpushed**, well ahead of `main` — `git log --oneline main..HEAD` for the count, which is deliberately not published here because it is wrong again on the next commit. It carries the bundle rule store, six defect fixes — four of them live in released v1.3.14 — the specification moving v1.3.13 → **v1.3.15**, and `reference/suites/art_harness.py`, which runs an external adversarial corpus against Door A and found one of the six on its first run. The spec's §1 alert enumerates those six as (a)–(d) and then carries **three published corrections** beneath them, all found by *reading* artifacts nothing executed: the schema that described an artifact nobody builds (ACP-50), AU-1's audit chain disagreeing with the reference so AU-3a could not hold (ACP-57), and `CL-7` naming two different normative rules while both meanings were already cited (ACP-56). The pattern is the point and it recurred three times in one day — **normative text with no executable consumer** — so each correction ships with the check that would have caught it: an AU-1 conformance case in suite 7, and a clause-id uniqueness assertion in `selftest.sh`.

**The rule store is now built end to end**, steps 2–7 (ACP-36 … ACP-41): real Ed25519/ML-DSA-65 primitives, `custody.rs` with the `Signer` trait and tiers T0–T3, the canonical walk and tree hash, verify-on-every-read, the offline `acp-bundle` CLI, and `reference/src/acp_bundle.py`. **Both differential directions run**: Python's signatures verify in Rust (`tests/python_interop.rs`), Rust's verify in Python (`tools/check-rust-signatures.py`), and the two agree on a bundle's tree hash, verdict and *refusal name* across 38 cases with 3 pinned divergences (`tools/check-bundle-differential.py`). The last two need cargo, so they run from `selftest.sh` rather than the gate.

**This paragraph has gone stale twice by naming a branch that no longer exists.** If you are reading it against a `git branch` that disagrees, believe git and fix the sentence.

`MANIFEST.sha256` goes stale the moment any covered file is edited. The release action is `./tools/sign-release.sh sign <keyfile>`, which only the key holder can run. Coverage is 150 files across ten roots.

**Phase 8 is done (ACP-44).** `tools/codegen.sh` generates the Rust and TypeScript wire types from `spec/schemas/bundle/` and is the first thing that ever read those files — it found four defects on its first pass, one a live quorum bypass (ACP-53: PB-7 compared whole registry entries, so changing a `role` string let one key holder satisfy a k=2 quorum alone). **The fail-safe defaults live in the schema as `x-acp-absent` data**, not in a generator table, and the generator halts rather than guessing when a lookup table has no rule. `x-acp-ordered` is applied only where an order is declared — `SuiteId` gets no `Ord`, because CR-4 is containment and not rank. `tools/sync-counts.sh` re-derives every published count, which had been hand-work and had already recurred twice (ACP-42, ACP-43).

**Two things are disclosed and NOT closed**: nothing validates a bundle against the schemas and every fixture is in fact schema-invalid (ACP-52), and the Python reference does not bound integers to the schema's declared domain — three divergences are pinned in the differential, which asserts both sides so the divergence vanishing or moving turns it red (ACP-54).

`spec/schemas/bundle/` has seven schemas and `spec/vectors/` has `CLASSIFICATION.md` and `OBLIGATIONS.md` — 86 cases split 48 vector-expressible / 38 per-implementation obligations. **Extracting the actual vector corpus has not started** (VEC-2), and it is what `crates/acp-conformance` waits on. Note the limit recorded there: a vector names a **seed plus the declared derivation**, never a seed alone — an implementation choosing its own domain separators derives a different identity and refuses every signature in the vector, which at the verifier is indistinguishable from a forgery.
