# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A security dossier for **ACP-SPEC-001** (Agent Control Plane), a reference implementation, a business simulation, and — as of the polyglot restructure — the beginnings of the control plane as real services.

It is not a product. It is an argument, and its discipline is that **every claim must replay on the reader's machine**. `README.md` says so explicitly: "If a claim here does not replay on your machine, don't believe it."

That framing drives most of the rules below. A change that makes a number in the prose stop matching a number the code prints is a defect, even if the code is correct.

## Commands

```bash
./tools/verify.sh --suites         # proofs + all 13 suites — THE PER-COMMIT GATE, no key needed
./tools/verify.sh                  # + integrity and signature — the release gate
./tools/selftest.sh                # tests the tooling itself (27 assertions)
./tools/sign-release.sh list       # what the next signature will cover (no key needed)

# individual suites — run from reference/suites/, they use flat imports
cd reference/suites
PYTHONPATH=../src python3 conformance.py          # 44/44
PYTHONPATH=../src python3 attack_registry.py      # 73/73  (--compose → 4/4)
PYTHONPATH=../src python3 mutate_executor.py      # 19/19  deletes each check, asserts the attack succeeds
PYTHONPATH=../src python3 ack_suite.py            # 14/14  (--mutate → 6/6)
PYTHONPATH=../src python3 audit_suite.py          # 11/11  (--mutate → 4/4)
PYTHONPATH=../src python3 partition_suite.py      # 9/9
PYTHONPATH=../src python3 partition_integration.py # 6/6
PYTHONPATH=../src python3 cbor_suite.py           # 8/8
PYTHONPATH=../src python3 research_bundle.py --attacks  # 4/4  Annex D domain attacks

# the simulation — run from the repo root, it is a package
python3 -m sim.bundle --check      # 14/14 grading table asserted
python3 -m sim.run_day             # the day, one process
python3 -m sim.supervise           # the day, seven real OS processes
python3 -m sim.supervise --checks  # process-isolation properties only
python3 -m sim.scoreboard          # the deliverable
python3 -m sim.acceptance          # 11 pass, 1 partial, 0 fail

cargo check --workspace && cargo test --workspace   # Rust: 7 tests
pnpm install && pnpm -r typecheck                   # TypeScript: 5 projects
```

Dependencies: `cryptography` and `dilithium-py` for signature checks. `sim/` is standard library only. Dafny is optional — the proof step is skipped if absent.

## The two gates

`./tools/verify.sh` sections 1–2 are integrity and Ed25519 signature. **Only the key holder can make them green**, because regenerating the manifest requires the offline release key. Between releases they are expected to be red.

- **`--suites`** — proofs + 13 suite lines. No key. Green at every commit. A clean run prints **15** result lines (1 prerequisites + 1 proofs + 13 suites).
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
deploy/        docker-compose.yml, k8s/
tools/         verify.sh sign-release.sh selftest.sh
docs/          working documents — deliberately OUTSIDE the signed roots
```

**`spec/` is the only normative source.** Rust and TypeScript types are *generated* from `spec/schemas`, never hand-written. A hand-written type is a second definition of the same object, and two definitions of one object is the encoding-split defect at the source level.

**`reference/` is permanent.** Python is the readable artifact — someone can follow the §9.3 checklist line by line in `acp_executor.py`. It is also the differential partner for Rust: the first divergence between the two on a shared vector is a specification ambiguity, which is exactly how Z1 was found.

`reference/suites/conformance.py` is **also a shared fixture library**, imported by 7 other suites as `import conformance as C`. It is not a leaf script.

The suites reach `reference/src` via `PYTHONPATH`, exported by `tools/verify.sh`. Keep sys.path manipulation in the runner, not in library code.

**Most of `crates/`, `services/`, `orchestrator/` and `deploy/` is scaffold.** Every service `main()` exits non-zero so a scaffold cannot be mistaken for a running control plane. What is genuinely implemented: the fail-safe defaults in `acp-core`, and CR-3 hybrid composition in `acp-crypto`.

## Rules specific to this repository

**Never fork `reference/src/*.py`. Import them.** Those modules carry mutation-test markers in comments — `# AU-7-anchor-before-release (mutation target)`, `# AC-5-anchor-release (do not move)`, `# AU-6-suspend-sampling`. `mutate_executor.py`, `ack_suite.py --mutate` and `audit_suite.py --mutate` locate checks by reading the source text and deleting them, then assert the matching attack succeeds. A copied-and-edited executor silently voids the repository's own evidence. When new domain behaviour is needed, subclass and extend (see `sim/release.py:ResearchGate`).

**Mutation suites read source files by path** and rebuild them in a temp dir. They resolve `reference/src` explicitly and **strip `PYTHONPATH` from the mutant subprocess** — if it leaked, a failed copy would silently import the real module and the mutant would report SURVIVE, recording a load-bearing check as redundant. Check these first after any restructure: they break in ways that still print green. 19 + 6 + 4 = **29 mutants** must keep being killed.

**`MANIFEST.sha256` is signed with an offline Ed25519 key.** Coverage is three allowlists and no deny-list: **roots** (the ten directories in `ROOTS`), **git-tracked** (`git ls-files`, so build outputs are excluded because they are gitignored), and **extension** (plus `LICENSE` and `Dockerfile` by name). The signer **halts on an unrecognised file type** rather than silently signing or silently skipping it. `.gitignore` is itself signed, because the signer derives its file set from it. Editing *any* covered file invalidates the manifest — this has already happened once to `README.md` via editor auto-format.

`sign` builds into `.tmp` files and moves them into place only after the signature exists, so a mistyped key path cannot destroy the last valid manifest.

**The central discipline: RES-8 / RES-9 / RES-10.** *A verifier must never accept a derived security value from the party it is verifying.* This class of defect has recurred five times in the document's history (C2 → X1 → Y1 → Z3 → W1), each time in machinery the previous fix introduced. Practical consequences:

- A value the consumer needs must be **recomputed** from the signed bundle, never read from the message. See `TR-8` (risk), `RV-3` (reversibility), and `sim/policy.py:_cross_program` (program ownership — both sides come from the bundle, because a compromised agent writes the whole proposal).
- A claimed **binding** between artifacts must be verified from the signed bytes of both. A transmitted identifier is a name for a binding, not evidence of one.
- Conformance suite 12 requires every control input to be classified **R** (recomputed), **B** (bound), or **T** (trusted as transmitted), with every `T` enumerated against a disclosed residual. An unlisted `T` is a conformance failure.

**T-32 is OPEN and must stay open until it is actually closed.** The notifier self-certifies its own independence; `note.source_path`, `note.from_canonical` and `delivered` are classified **T**. Splitting `services/notifier` and `services/approval` into separate codebases improves *build-time* provenance, which R12 already credits — it does **not** move those rows off T, because the Executor still reads them from the party it is verifying. Closing it means the Executor checking two distinct signed service identities named in the signed bundle.

**`services/notifier` and `services/approval` share nothing above the wire format.** `@acp/types` is the one permitted common dependency — it *is* the wire format. No shared template engine, formatter, sanitiser, date helper or component library. Each keeps its own `render.ts`; factoring them together is not a refactor, it is the vulnerability (DR-2). If a linter flags the duplication, the linter is wrong.

**Fail-safe defaults are deliberate and must not be "helpfully" relaxed.** Resource absent from `floors.json` ⇒ `T3`. Action absent from `reversibility.json` ⇒ `IRREVERSIBLE`. Action with no risk function ⇒ refused at `8.4-3`, *not* graded HIGH. Unknown is never LOW (P-4).

**Do not add model-side defences.** No filtering, scoring or judging of model output anywhere. The architecture assumes the model is manipulable and its guarantees do not depend on injection failing; adding a content filter and relaxing a Door A control on its strength is an explicit conformance failure (§5.1a). In demos the model must be shown complying fully — simulating a refusal misrepresents the claim.

**Crypto is modelled in Python, real in Rust.** Python signature primitives are HMAC-SHA256 over canonical bytes; sites needing real Ed25519/ML-DSA/COSE are marked `CRYPTO-SWAP`. The *hybrid composition* (CR-1..CR-5, conjunctive — verification requires **every** primitive, never any) is modelled faithfully in both, because composition is protocol logic and the downgrade attack it prevents is a control-flow property the suites can test.

**Conformance vectors are defined over canonical bytes and declared mutations, never over signatures.** Python signs with modelled HMAC and Rust with real primitives, so a vector carrying a signature is not portable between them. And passing the corpus is a **partial** claim: vectors express input → verdict, not the 29 mutants, ordering properties such as AU-7 anchor-before-release, partition behaviour, or render-path distinctness. Those are per-implementation obligations.

## Writing style for this repository

The prose is deliberately self-critical and states limits before strengths — `dossier/06-RESIDUAL-RISK.md` comes before the positive claims in the reading order, and `README.md` has a "What this does not claim" section. Match it. Specifically:

- When something does not fully hold, report it as **partial** and say why. `sim/acceptance.py` returns `"PARTIAL"` for criterion 1 rather than a green tick, because the fast path *does* claim a receipt nonce and the criterion as written is not satisfiable by a conformant implementation. A suite that returns all-pass on its first run has usually been written to agree with itself.
- Corrections are published, not quietly fixed. Annex D contains a paragraph beginning "A correction worth recording"; `acp_ack.py` documents a check that mutation testing showed was decorative and was therefore *removed* rather than kept as defence in depth. Follow that pattern: a check that kills no mutant is not a control.
- Comments explain *why a rule exists and what breaks without it*, usually citing the rule id and the defect it closes. Avoid comments that restate the code.

## Testing the tooling

Anything checkable by a command must be checked by a command, not by inspection and not by asking a model. `tools/selftest.sh` exists for that: it proves `list` and `sign` agree, that the signer halts on unknown file types, that a bad key leaves `MANIFEST.sha256` byte-identical, and that `--suites` prints 15 result lines with no failures. Three real defects have been found by writing those assertions.

## Current state

Work is on branch `step0-gate-and-signing-model`. The restructure and scaffold are committed there; `main` is untouched.

`MANIFEST.sha256` is **stale** — every path changed in the restructure. The next release action is `./tools/sign-release.sh sign <keyfile>`, which only the key holder can run. Coverage is 80+ files across ten roots.

Not yet started: `spec/schemas/` and `spec/vectors/` are empty. Extracting the vector corpus, and classifying which of the 44 conformance cases are data-expressible versus per-implementation obligations, is the next step and the thing `crates/acp-conformance` waits on.
