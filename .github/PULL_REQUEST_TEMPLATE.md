<!--
Sending a finding rather than a patch? Open an issue instead — see .github/SECURITY.md.
The rules below are in .github/CONTRIBUTING.md and each one exists because breaking it
destroys evidence silently, usually while every test still prints green.
-->

## What this changes, and why

<!-- One or two sentences. If it fixes a defect, name the defect. -->

## The gate

```
$ ./tools/verify.sh --suites
paste the last few lines here
```

- [ ] `./tools/verify.sh --suites` is green — **15** result lines, 0 failures
- [ ] `./tools/selftest.sh` passes (29 assertions) — required if you touched anything in `tools/`

<!-- 14 lines instead of 15 means Dafny is not installed and the proof step was skipped. -->

## Signed files

Editing any file under a signed root (`spec dossier reference crates services packages orchestrator sim deploy tools`, or any file at the repository root) invalidates `MANIFEST.sha256`.

- [ ] I have **not** regenerated `MANIFEST.sha256` — only the offline key holder can re-sign, and a manifest whose signature no longer verifies is worse than a stale one
- [ ] Signed files I touched are listed here, so the maintainer knows what to re-sign:

<!-- list them, or write "none — .github/ and docs/ are outside the signed roots" -->

## Rules this PR does not break

- [ ] I did not copy `reference/src/*.py`. Those modules carry mutation markers that 29 mutants locate by reading the source text — a fork voids that evidence silently. Subclass and extend instead.
- [ ] I added no model-side filtering, scoring or judging of model output (§5.1a)
- [ ] I introduced no shared code between `services/notifier` and `services/approval` above `@acp/types` (DR-2)
- [ ] I did not relax a fail-safe default — unknown is never LOW (P-4)
- [ ] No verifier in this change accepts a derived security value from the party it is verifying (RES-8)

## Prose

- [ ] If this changes a number the code prints, I found **every** place the prose states it
- [ ] If this corrects a published error, it is recorded rather than quietly swapped

## Anything checkable by a command

- [ ] Any claim this PR adds that a command could verify, a command now verifies
