# ACP — polyglot monorepo architecture

**Status:** design, awaiting review. Not committed.
**Date:** 2026-08-10
**Supersedes:** the v1.3.13 `impl/{src,suites,proofs}` reorganisation agreed earlier and never executed. That layout assumed one language. Nothing has moved yet, so nothing moves twice.
**Lands as:** v1.3.13 (restructure), then one release per subsequent step.

---

## 1. What this changes

The repository becomes a polyglot monorepo: a Rust control plane, TypeScript approval and notification surfaces, Docker deployment, and a demo orchestrator, alongside the Python reference implementation and the dossier that argues for all of it.

The discipline does not change. `README.md` still says *"If a claim here does not replay on your machine, don't believe it."* Everything below exists to keep that sentence true when there is more than one implementation.

One consequence is worth stating before the layout, because it is the reason most of the rest is shaped the way it is: **today "44/44 conformance" means one implementation passes its own tests.** That is a weaker claim than it reads as. Language-agnostic vectors make it mean *every implementation passes the same corpus* — but only for the properties a vector can express, which is not all of them (§4.2).

---

## 2. Layout

Directories are created only when they hold real content. An empty `services/` with a "planned" README reads as vapour.

```
acp/
├── README.md  LICENSE  CLAUDE.md  CONTRIBUTING.md
├── MANIFEST.sha256  MANIFEST.sha256.sig  release-key.pub
├── .gitignore                     ← signed; the signer's file set derives from it (§4.4)
│
├── spec/                          THE NORMATIVE SOURCE
│   ├── ACP-SPEC-001.md            was 03-SPECIFICATION.md
│   ├── schemas/                   proposal, receipt, attestation, acknowledgement,
│   │                              bundle (.schema.json) + canonical.cddl
│   └── vectors/                   language-agnostic conformance corpus
│       ├── MANIFEST.json          id, rule, expected verdict, category
│       ├── conformance/  encoding/  audit/  ack/  findings/
│       └── OBLIGATIONS.md         what vectors cannot express (§4.2)
│
├── dossier/                       THE ARGUMENT
│   ├── 00-INDEX.md … 07-REPRODUCTION.md
│   └── annexes/D-research-pipeline.md
│
├── reference/                     Python. Permanent. Readable + differential partner.
│   ├── pyproject.toml             src-layout, installable
│   ├── src/acp/                   executor ack audit ledger crypto
│   ├── suites/                    13 suite entry points, run FROM spec/vectors
│   │                              mutate_executor(19) mutate_ack(6) mutate_audit(4)
│   └── proofs/                    binding.dfy (36 theorems), dafny-output.txt
│
├── crates/                        Rust workspace
│   ├── acp-core/                  types generated from spec/schemas; policy evaluation
│   ├── acp-crypto/                real Ed25519 + ML-DSA-65; validating CBOR decoder
│   └── acp-conformance/           vector runner + Rust's own obligation suites
│
├── services/                      the control plane as running processes
│   ├── executor/  policy/  ledger/  anchor/        Rust
│   └── notifier/  approval/                        TypeScript, independent (§5)
│
├── packages/                      TypeScript
│   ├── acp-types/                 generated from spec/schemas
│   └── acp-client/
│
├── orchestrator/                  TypeScript. Advances the clock. Decides nothing.
├── sim/                           the business simulation (§6)
├── deploy/                        docker-compose.yml, k8s/
├── tools/                         verify.sh sign-release.sh codegen.sh vectors.sh
└── docs/                          working documents. Deliberately OUTSIDE the signed
                                   roots — not release artifacts. Do not "fix" this.
```

### Ecosystem conventions

Each language uses its own ecosystem's standard layout rather than a house invention:

| Language | Convention |
|---|---|
| Python | `src/` layout with `pyproject.toml`; installable, no `sys.path` manipulation anywhere |
| Rust | Cargo workspace at root of `crates/`; `services/*` are workspace members |
| TypeScript | pnpm workspaces; `packages/*` are libraries, `services/*` are deployables |

The Python `src/` layout removes the one `sys.path` hack that exists today (`sim/__init__.py`) and avoids the second that the abandoned reorg would have added (`impl/suites/_bootstrap.py`).

---

## 3. Boundary rules

**`spec/` is the only normative source.** Rust and TypeScript types are *generated* from `spec/schemas`, never hand-written. A hand-written type is a second definition of the same object, and two definitions of one object is the encoding-split defect at the source level.

**`dossier/` is separated from code deliberately.** A reader must not dig through source trees to find `06-RESIDUAL-RISK.md`.

**`reference/` stays permanently.** Python is the readable artifact — someone can follow the §9.3 checklist line by line in `executor.py`. It is also the differential partner for Rust: the first divergence between the two on a shared vector is a specification ambiguity, which is exactly how Z1 was found.

**`orchestrator/` never decides anything.** It advances the clock, generates load, routes proposals, records outcomes. If it can influence an authorisation decision it is a bypass — the same shape as T-32 one layer up.

**Never fork `reference/src/acp/*.py`.** Those modules carry mutation-test markers that the repository's own evidence chain reads by path. Subclass and extend.

---

## 4. The evidence chain under polyglot

### 4.1 What vectors carry

`spec/vectors/` holds input→verdict cases: the 36 attack vectors and 8 positive paths of conformance, the 8 canonical CBOR cases, ACK-1..6, AC-5/AU-6/AU-7/AU-8, and the T-31/T-32 findings. Each is addressable by id so a single vector can be invoked by name — the mutation suites depend on this.

### 4.2 What vectors cannot carry — per-implementation obligations

This is the honest limit of the corpus, and it is enumerated rather than glossed, in the same way conformance suite 12 enumerates every `T` against a disclosed residual.

| Property | Why no vector expresses it | Obligation |
|---|---|---|
| 29 mutants (19 executor, 6 ack, 4 audit) | Requires deleting a check from *source* and re-running | Each implementation ships its own mutation suite |
| Ordering (AU-7 anchor-before-release) | A trace property, not an input→output pair | Per-implementation trace assertion |
| Partition behaviour (CL-1..7) | Stateful and temporal | Per-implementation partition suite |
| Render-path distinctness (DR-2) | Structural introspection of the running program | Per-implementation, and see §5 |
| Prose differential (`diff_prose.py`) | Compares documentation against behaviour | Reference implementation only |

**Therefore:** "Rust passes the corpus" is a partial claim and must be written as one. An implementation that passes every vector and ships no mutation suite has demonstrated that it agrees on inputs, not that its checks are load-bearing.

### 4.3 The gate

`verify.sh` currently runs integrity and signature unconditionally (`verify.sh:24-46`), so it cannot be green on any commit the release-key holder has not personally signed. The constraint "green at every commit" is not satisfiable as written.

Split it:

- **`verify.sh --suites`** — proofs + all 13 suite lines. No key required. **Green at every commit.**
- **`verify.sh`** — integrity + signature + the above. **Green at every tagged release.**

`--suites` must reproduce all 13 lines, not a subset, or it is a weakened gate rather than an achievable one.

### 4.4 Manifest coverage

The current signer covers `.md .py .dfy .txt .sh .pub`. Under the target layout that leaves `.json` (**including the signed vectors**), `.rs`, `.ts`, `.toml`, `.yml`, `.cddl` and `LICENSE` unsigned. The extension allowlist fails open the first time someone adds a file type — the same defect, on a different axis, as the blanket `find .` already replaced this session.

Coverage is defined on three axes, each an allowlist, none a deny-list:

1. **Roots** — `spec dossier reference crates services packages orchestrator sim deploy tools` plus named root files. `docs/` is outside by construction, as is `private/` if it is ever created. The signer fails loudly if a named root is missing, so a mistyped root cannot silently sign nothing.
2. **Tracked-ness** — the file set is `git ls-files`. Build outputs (`target/`, `node_modules/`, `dist/`, `__pycache__/`) are excluded because they are gitignored, not because a deny-list names them. This is why **`.gitignore` must itself be signed**: the signer would otherwise derive its input set from a file outside the signature.
3. **Extension** — `.md .py .rs .ts .json .cddl .dfy .toml .yml .yaml .lock .txt .sh .pub .gitignore`, plus the explicit filenames `LICENSE` and `Dockerfile`.

**The signer halts** if any tracked file under a signed root matches none of these. A new file type stops the release rather than being silently signed or silently skipped.

---

## 5. T-32 and DR-2 independence

`06-RESIDUAL-RISK.md:43` names T-32 "the notifier self-certifies its own independence". `02b-CLASSIFICATION-TABLE.md:39-41` classifies `note.from_canonical`, `note.source_path` and `delivered` as **T**, and R12 records "Build-time provenance only; the runtime check is self-asserted."

**Splitting notifier and approval into separate codebases does not close T-32.** It improves build-time provenance, which R12 already credits. At run time the executor still reads `note.source_path` *from the notifier*, so rows 24–26 stay **T** and a compromised notifier lies exactly as it does today.

This is RES-8 recurring in the machinery a fix introduces — the sixth instance of the pattern (C2 → X1 → Y1 → Z3 → W1). Recognising it here rather than after shipping is the only thing that distinguishes this from the previous five.

- **Reduce** (restructure step): separate dependency trees, separate builds, separate CI jobs. T-32 stays **open**, and the dossier keeps saying so.
- **Close** (own release, later): move `note.source_path` T→**B** by having the executor check two *distinct signed service identities* named in the signed bundle — a value the notifier does not mint. `delivered` may be irreducibly **T**; DR-8 delivery completeness cannot be established from the receiver's own word.

**Independence rule.** Notifier and approval **share nothing above the wire format**. Generated types from `spec/schemas` are permitted — they *are* the wire format. Rendering is not: no shared template engine, formatter, sanitiser, date helper, or component library. Without this carve-out the first shared `formatDate()` is technically compliant and voids the property.

**Disclosed residual.** Both live in one monorepo. Separate organisations with separate release keys would be stronger. A monorepo is chosen because separate repositories would break *one clone, one command, every claim replays*, which is what the dossier is for. That trade is disclosed, not claimed as equivalent.

---

## 6. `sim/` — data, and a declared domain layer

Swapping data files should retarget the simulation to a bank, a hospital, or an infrastructure team. But `sim/policy.py`'s **XPROG-1** cross-program rule and `release.py:ResearchGate` are *logic*, not data. Moving a control into a config file it cannot express would be a regression dressed as a refactor.

- `world.json`, `bundle.json`, `events.json`, `inbound/` carry the domain **data**.
- A thin, explicitly declared domain layer carries XPROG-1 and the gate composition until EL-1 is expressive enough to state XPROG-1 in `bundle.json`. If EL-1 grows that far, the layer shrinks to nothing and that is a spec change with its own evidence.
- **The existing Python `sim/` keeps running until the new path reproduces its numbers** — 146/179, 93.3% release-on-silence, €520,000 counterfactual + 1 unrecallable disclosure. It is working evidence today; it is not retired on the promise of a replacement.

---

## 7. Codegen

`tools/codegen.sh` generates Rust and TypeScript types from `spec/schemas`. Generated output is **committed**, and CI regenerates and diffs: a dirty diff fails the build. This keeps the repo clonable-and-buildable without a codegen toolchain while making drift impossible to merge.

---

## 8. Build order

| # | Step | Ends with |
|---|---|---|
| 0 | `verify.sh --suites` split; manifest coverage model; signer halt-assertion | the gate every later commit is measured against |
| 1 | Extract vectors to `spec/vectors/`; Python suites run from them; `OBLIGATIONS.md` | `--suites` green, no restructure yet |
| 2 | Restructure to target layout; mutation split into three peer files; CI; re-sign | **v1.3.13**, full verify green |
| 3 | `spec/schemas/` + codegen to Rust and TS | schemas validate the existing vectors |
| 4 | `crates/acp-core`, `acp-crypto`, vector runner + Rust obligation suites | Rust passes the corpus *and* its obligations |
| 5 | `services/notifier` + `services/approval` independent | T-32 **reduced**, still open, still disclosed |
| 6 | `services/executor policy ledger anchor`; `deploy/` compose | seven services, one command |
| 7 | `orchestrator/` + `sim/` | A/B run: same seed, control plane off vs on |
| — | T-32 closure (T→B, distinct signed identities) | own release, own evidence |

Steps 0 and 1 are independently valuable and commit to none of the rest.

**Step 2 carries the highest risk in the whole plan.** It moves the three files CLAUDE.md flags as most dangerous — the mutation suites read their targets by path (`open("acp_executor.py")`, `shutil.copy(...)`) and break in ways that still print green. Promoting them to three peer files (`mutate_executor` / `mutate_ack` / `mutate_audit`) is a real change to them, not a side effect of a move. It gets an explicit before/after mutant count: **19 + 6 + 4 = 29 killed**, both sides of the move.

---

## 9. Residuals this design introduces

Stated here rather than discovered later.

- **RES-P1.** Vectors cover input→verdict only. A second implementation can pass the entire corpus while none of its checks are load-bearing (§4.2).
- **RES-P2.** Notifier/approval independence is monorepo-structural, weaker than separate-organisation independence (§5).
- **RES-P3.** Generated types are a shared dependency of two supposedly independent services. Justified as "they are the wire format", but it is a shared artifact and a codegen compromise reaches both.
- **RES-P4.** `--suites` green at every commit means integrity is unverified between releases. A working tree can diverge from signed bytes for the length of a migration.
- **RES-P5.** Real crypto in `acp-crypto` and modelled HMAC in `reference/` means the two implementations are not comparable at the primitive layer. Vectors must be defined over canonical bytes, not over signatures, or the corpus is not portable.

RES-P5 is a live design constraint on step 1, not just a disclosure.

---

## 10. Open questions

1. Does `orchestrator/` use the Vercel AI SDK with a real model (as proposed), and if so does that make model output part of the replay? A recorded-transcript mode is probably required for `--suites` to be deterministic.
2. Does `sim/` keep a Python entry point after step 7, or does the TypeScript orchestrator become the only way to run the day?
3. `CONTRIBUTING.md` is new. Disclosure policy needs deciding before it is written.
