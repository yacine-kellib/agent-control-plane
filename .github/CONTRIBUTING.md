# Contributing

The most valuable contribution is a **finding**, not a patch. See [SECURITY.md](SECURITY.md).

If you are sending code, the rules below are not style preferences. Each one exists because breaking it silently destroys evidence this repository depends on, usually while every test still prints green.

## The gate

```bash
python3 -m pip install --break-system-packages cryptography dilithium-py
./tools/verify.sh --suites      # proofs + 15 suites. Must be green. No key needed.
./tools/selftest.sh             # tests the tooling itself (123 assertions)
```

A clean `--suites` run prints exactly **18** result lines: 1 prerequisites + 1 proofs + 15 suites + 1 external-corpus harness. If it prints 17, Dafny is missing and the proof step was skipped.

Do **not** run `./tools/verify.sh` without `--suites` and treat red integrity as your problem — see below.

## Rules that will get a PR rejected

### Never regenerate `MANIFEST.sha256`

`MANIFEST.sha256` is signed with an offline Ed25519 key that only the maintainer holds. If you edit any file under a signed root, integrity goes red. **That is expected and it is not yours to fix.** A regenerated manifest whose signature no longer verifies is strictly worse than a stale one, because nobody but the key holder can repair it.

Leave it. Say in the PR which signed files you touched.

### Never copy `reference/src/*.py` — import them

Those modules carry mutation-test markers in their comments:

```python
# AU-7-anchor-before-release (mutation target)
# AC-5-anchor-release (do not move)
# AU-6-suspend-sampling
```

`mutate_executor.py`, `ack_suite.py --mutate` and `audit_suite.py --mutate` locate checks by **reading the source text** and deleting them, then assert the matching attack now succeeds. **38 mutants** must keep being killed: 28 executor, 6 ack, 4 audit.

A copied-and-edited executor voids that evidence silently. When you need new behaviour, subclass and extend — `sim/release.py:ResearchGate` is the pattern.

### Do not add model-side defences

No filtering, scoring, or judging of model output, anywhere.

The architecture assumes the model is manipulable and its guarantees do not depend on injection failing. Adding a content filter and relaxing a Door A control on the strength of it is an explicit conformance failure (§5.1a). In demos the model must be shown **complying fully** — simulating a refusal misrepresents the claim.

### DR-2 is not enforceable here any more

`services/notifier` and `services/approval` moved to the private product repository in the two-repository split (ACP-66), and the rule went with them: `@acp/types` is the one permitted common dependency because it *is* the wire format, and factoring the two together is not a refactor but the vulnerability — one compromised shared library lies to both channels at once, which is exactly the attack the second channel exists to catch.

Nothing you can send to *this* repository can violate that, and no check here will fire on a violation elsewhere. It is listed so a contributor reading the specification's DR-2 knows where the code lives, and so the loss of public review over it is not silent. See RES-P2 in `dossier/06-RESIDUAL-RISK.md`.

### Do not relax fail-safe defaults

- Resource absent from `floors.json` ⇒ `T3`
- Action absent from `reversibility.json` ⇒ `IRREVERSIBLE`
- Action with no risk function ⇒ refused at `8.4-3`, **not** graded HIGH

Unknown is never LOW (P-4). These read as over-strict until you consider who benefits from the omission.

### A verifier must never accept a derived security value from the party it verifies

This is the discipline the whole document is organised around (RES-8 / RES-9 / RES-10). It has recurred **five times**, each in machinery the previous fix introduced. In practice:

- A value the consumer needs must be **recomputed** from the signed bundle, never read from the message.
- A claimed **binding** must be verified from the signed bytes of *both* artifacts. A transmitted identifier is a name for a binding, not evidence of one.
- Every control input is classified **R** (recomputed), **B** (bound) or **T** (trusted as transmitted) in `dossier/02b-CLASSIFICATION-TABLE.md`. A new `T` that is not enumerated against a disclosed residual is a conformance failure.

### `spec/` is the only normative source

Rust and TypeScript types are **generated** from `spec/schemas`, never hand-written. A hand-written type is a second definition of one object, which is the encoding-split defect at the source level.

## Rules about prose

**A number in the prose that no longer matches what the code prints is a defect**, even when the code is correct. If your change moves a number, find every place that states it. Several have been missed this way.

**Corrections are published, not quietly fixed.** If you are correcting a published error, record it — `RELEASE.md` has a "A correction worth recording" section for exactly this. Silently swapping a wrong value is the one disposition this project rules out.

**A check that kills no mutant is not a control.** If mutation testing shows your new check is redundant, the correct response is to delete it, not to keep it as defence in depth. Two checks have been removed on these grounds (the AU-7 pre-check, the ACK-5 gate-local set).

**Report partial results as partial.** `sim/acceptance.py` returns `PARTIAL` for criterion 1 rather than a green tick, because the criterion as written is not satisfiable by a conformant implementation. A suite that passes on its first run has usually been written to agree with itself.

## Anything checkable by a command must be checked by a command

Not by inspection, and not by asking a model. `tools/selftest.sh` exists for this and has caught four real defects — including a release-key fingerprint that had been wrong in the README for an entire release, surviving repeated proofreading because 32 hex characters read as opaque and correct to a human eye.

If you add a claim that a command could verify, add the command.

## Commits and PRs

- Branch from `main`. Do not work directly on it.
- Explain **why the rule exists and what breaks without it** in comments — not what the code does.
- Say in the PR which signed files you touched, and leave the manifest alone.
