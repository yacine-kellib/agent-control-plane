# ACP Step 0 — Gate Split and Signing Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `verify.sh --suites` an achievable green gate that needs no release key, and replace the signer's fail-open extension allowlist with a three-axis coverage model that halts on anything it does not recognise.

**Architecture:** Two shell tools at the repository root gain subcommands and a self-test. `verify.sh` learns `--suites` (proofs + all 13 suite lines, skipping integrity and signature). `sign-release.sh` learns `list` — a key-free dry run that prints exactly what `sign` would cover — which is what makes the coverage model testable without the offline key. A new `selftest.sh` tests the tooling itself.

**Tech Stack:** bash 3.2 (macOS default — no associative arrays, no `mapfile`), git, coreutils `sha256sum`, Python 3.14 for the existing suites.

## Global Constraints

- **No restructure in this step.** No file moves. `artifacts/` stays where it is. The only new directory is none; `spec/vectors/` arrives in step 1.
- **`verify.sh --suites` must reproduce all 13 suite lines plus the Dafny proof step.** Not a subset. A weakened gate is worse than no gate.
- **29 mutants must still be killed**: 19 executor, 6 ack, 4 audit. Verified by the suite lines, not separately.
- **Never regenerate `MANIFEST.sha256` in this plan.** Only the holder of the offline Ed25519 key can re-sign, and an unsigned-but-regenerated manifest is strictly worse than a stale one. Every task here is verified through `sign-release.sh list`, never `sign`.
- **Never fork `artifacts/*.py`.** Three mutation suites read those files by path and delete checks from their source text.
- `sha256sum` must remain the hashing tool — `verify.sh:25` consumes the same format via `sha256sum -c`.
- Bash target is **3.2**: no `declare -A`, no `${var,,}`, no `mapfile`.

---

## File Structure

| File | Responsibility |
|---|---|
| `verify.sh` (modify) | Argument parsing; `--suites` skips §1–2. Suite list unchanged. |
| `sign-release.sh` (modify) | `list` subcommand; three-axis coverage; halt-assertion; correct roots. |
| `selftest.sh` (create) | Tests the two tools above. The only new file. |
| `.gitignore` (modify) | Add `docs/` decision, build outputs. Becomes signature-relevant. |

`selftest.sh` is deliberately separate from `verify.sh`: `verify.sh` proves claims about ACP, `selftest.sh` proves claims about the tooling. Merging them would let a tooling bug print a green ACP result.

---

### Task 1: `sign-release.sh list` — key-free coverage dry run

Nothing else in this plan is testable until the coverage model can be inspected without the offline key. This task comes first for that reason.

**Files:**
- Modify: `sign-release.sh:39-52` (the `sign` case and the `case` dispatch)
- Test: `selftest.sh` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `./sign-release.sh list` → newline-separated repo-relative paths on stdout, sorted, exit 0. `covered_files()` shell function, used by both `list` and `sign`.

- [ ] **Step 1: Write the failing test**

Create `selftest.sh`:

```bash
#!/usr/bin/env bash
# selftest.sh — tests the repository's own tooling.
#
# verify.sh proves claims about ACP. This proves claims about verify.sh and
# sign-release.sh. They are separate files so that a bug in the tooling cannot
# print a green ACP result.
set -uo pipefail
cd "$(dirname "$0")"
FAIL=0
OUT=""
ok()  { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=1; }
chk() { if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }
# One idiom for every content assertion against $OUT. Writing these inline as
# `grep -q X; [ $? -ne 0 ]; chk $?` works but reads as a bug, and the next
# person to "fix" it inverts a test silently.
has()    { if echo "$OUT" | grep -qE "$1"; then ok "$2";  else bad "$2"; fi; }
hasnot() { if echo "$OUT" | grep -qE "$1"; then bad "$2"; else ok "$2"; fi; }

printf '\n\033[1m== sign-release.sh list ==\033[0m\n'

OUT=$(./sign-release.sh list 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "list exits 0 (got $rc)"

has '^README\.md$'                 "covers README.md"
has '^LICENSE$'                    "covers LICENSE (no extension)"
has '^\.gitignore$'                "covers .gitignore (signer input set derives from it)"
has '^artifacts/acp_executor\.py$' "covers artifacts/*.py"
has '^verify\.sh$'                 "covers verify.sh (the tool that checks the claims)"
has '^06-RESIDUAL-RISK\.md$'       "covers the numbered dossier documents"

hasnot '^docs/'          "does NOT cover docs/ (working documents, not release artifacts)"
hasnot 'MANIFEST\.sha256' "does NOT cover the manifest or its signature"
hasnot '__pycache__'      "does NOT cover build outputs"

printf '\n\033[1m== Result ==\033[0m\n'
[ $FAIL -eq 0 ] && echo "  tooling self-test passed." || echo "  tooling self-test FAILED."
exit $FAIL
```

- [ ] **Step 2: Run it to verify it fails**

```bash
chmod +x selftest.sh && ./selftest.sh
```

Expected: FAIL. `sign-release.sh` has no `list` subcommand, so it prints usage and exits 2.

- [ ] **Step 3: Implement `covered_files()` and the `list` subcommand**

Replace the `sign)` case in `sign-release.sh` (currently lines 39-52, including the ROOTS block added earlier this session, which names directories from an abandoned layout and must go) with:

```bash
# Coverage is three allowlists and no deny-list. Each axis independently
# refuses to admit something unrecognised:
#
#   1. roots     -- only these directories are eligible at all
#   2. tracked   -- only files git tracks; build outputs are excluded because
#                   they are gitignored, not because a list names them
#   3. extension -- only these types, plus two explicit filenames
#
# A deny-list fails open: the next thing someone adds is covered by default.
# That is how the previous blanket `find .` would have swept private/ and a
# stray .venv into a public manifest. Axis 2 is why .gitignore must itself be
# signed -- otherwise the signer derives its input set from an unsigned file.
# ROOTS is the CURRENT tree. Step 2 replaces it with the target layout:
#   spec dossier reference crates services packages orchestrator sim deploy tools
ROOTS="artifacts sim"
EXTS="md py rs ts json cddl dfy toml yml yaml lock txt sh pub"
NAMED="LICENSE Dockerfile .gitignore"

covered_files() {
  # Universe: every tracked file at the repository root, plus every tracked
  # file under a signed root directory. Enumerating root files by name was
  # tried and rejected -- it silently dropped the eleven numbered dossier
  # documents and both tools. Depth-1 plus an extension allowlist keeps the
  # fail-safe property without a list that rots every time a document is added.
  { git ls-files | grep -v '/'
    for r in $ROOTS; do [ -d "$r" ] && git ls-files -- "$r"; done
  } | grep -vE '^MANIFEST\.sha256(\.sig)?$' | sort -u
}

# Halt if any covered file has a type we do not recognise. A new file type
# must stop the release, not be silently signed and not be silently skipped.
assert_all_recognised() {
  local bad=""
  for f in $(covered_files); do
    local base=${f##*/} ext=""
    case "$base" in *.*) ext=${base##*.} ;; esac
    case " $NAMED " in *" $base "*) continue ;; esac
    case " $EXTS " in *" $ext "*) continue ;; esac
    bad="$bad $f"
  done
  if [ -n "$bad" ]; then
    echo "unrecognised file type under a signed root:" >&2
    for f in $bad; do echo "    $f" >&2; done
    echo "  add its extension to EXTS, or its name to NAMED, or exclude it." >&2
    exit 4
  fi
}
```

Add `list` to the `case` dispatch, before `sign)`:

```bash
list)
  for r in $ROOTS; do
    [ -d "$r" ] || { echo "missing signed root: $r" >&2; exit 3; }
  done
  assert_all_recognised
  covered_files
  ;;
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
./selftest.sh
```

Expected: all seven `list` assertions OK.

- [ ] **Step 5: Confirm nothing else changed**

```bash
./verify.sh
```

Expected: unchanged from the pre-task baseline — integrity OK, signature OK, proofs OK, 13 suite lines OK. `sign-release.sh` is not invoked by `verify.sh`, so this must be identical.

- [ ] **Step 6: Commit**

```bash
git add selftest.sh sign-release.sh
git commit -m "tools: add sign-release.sh list, a key-free coverage dry run

Coverage becomes three allowlists (roots, git-tracked, extension) with a
halt-assertion on unrecognised file types. Replaces an extension allowlist
that would have left .json, .rs, .ts and LICENSE unsigned, and a roots list
naming directories from an abandoned layout."
```

---

### Task 2: The signer halts on an unrecognised file type

**Files:**
- Modify: `selftest.sh` (add the halt assertions)
- Verify: `sign-release.sh` `assert_all_recognised` from Task 1

**Interfaces:**
- Consumes: `covered_files()`, `assert_all_recognised()` from Task 1.
- Produces: exit code 4 with the offending paths on stderr.

- [ ] **Step 1: Write the failing test**

Append to `selftest.sh` before the Result block:

```bash
printf '\n\033[1m== signer halt-assertion ==\033[0m\n'

# A new file type must stop the release rather than be silently signed or
# silently skipped. Uses a tracked file, because axis 2 is git-tracked-ness.
trap 'git rm -q --cached artifacts/scratch.bin 2>/dev/null; rm -f artifacts/scratch.bin' EXIT
printf 'x' > artifacts/scratch.bin
git add -N artifacts/scratch.bin

OUT=$(./sign-release.sh list 2>&1); rc=$?
[ $rc -eq 4 ]; chk $? "unrecognised extension halts the signer (exit 4, got $rc)"
has 'artifacts/scratch\.bin' "names the offending file"

git rm -q --cached artifacts/scratch.bin; rm -f artifacts/scratch.bin; trap - EXIT

OUT=$(./sign-release.sh list 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "clean tree lists successfully again (got $rc)"
```

- [ ] **Step 2: Run it**

```bash
./selftest.sh
```

Expected: PASS if Task 1's `assert_all_recognised` is correct. If it FAILs with exit 0 instead of 4, the assertion is not wired into `list` — fix `sign-release.sh`, not the test.

- [ ] **Step 3: Verify the missing-root guard**

```bash
sh -c 'ROOTS="nope" ; ./sign-release.sh list' ; echo "exit=$?"
```

Expected: this does **not** test the guard, because `ROOTS` is set inside the script. Instead confirm by inspection that the `for r in $ROOTS` loop in the `list` case exits 3, and that `sign` shares it. Add a comment in `sign-release.sh` recording that the guard is inspected, not executed, by `selftest.sh` — an untested guard should be declared as such rather than counted as covered.

- [ ] **Step 4: Commit**

```bash
git add selftest.sh sign-release.sh
git commit -m "tools: prove the signer halts on an unrecognised file type"
```

---

### Task 3: `sign` uses the same coverage model as `list`

The risk this task closes: `list` and `sign` computing different sets would make every dry run a lie.

**Files:**
- Modify: `sign-release.sh` (the `sign` case)
- Test: `selftest.sh`

**Interfaces:**
- Consumes: `covered_files()`, `assert_all_recognised()`.
- Produces: `MANIFEST.sha256` written from exactly `covered_files()` output. **Not run in this plan** — it needs the offline key.

- [ ] **Step 1: Write the failing test**

Append to `selftest.sh`:

```bash
printf '\n\033[1m== list and sign agree ==\033[0m\n'

# sign must hash exactly what list prints. If these diverge, every dry run
# is a lie. Compared by source inspection because sign needs the offline key.
n_list=$(./sign-release.sh list | wc -l | tr -d ' ')
n_call=$(grep -c 'covered_files' sign-release.sh)
[ "$n_call" -ge 3 ]; chk $? "covered_files is defined once and called by both list and sign ($n_call refs)"
grep -q 'covered_files | xargs sha256sum > MANIFEST.sha256' sign-release.sh
chk $? "sign hashes exactly covered_files output"
grep -q 'assert_all_recognised' sign-release.sh
chk $? "sign runs the halt-assertion too"
[ "$n_list" -gt 30 ]; chk $? "list covers a plausible number of files ($n_list)"
```

- [ ] **Step 2: Run it to verify it fails**

```bash
./selftest.sh
```

Expected: FAIL on "sign hashes exactly covered_files output" — the `sign` case still contains the old `find` pipeline.

- [ ] **Step 3: Rewrite the `sign` case**

```bash
sign)
  KEY="${2:?usage: ./sign-release.sh sign /path/to/acp-release.key}"
  for r in $ROOTS; do
    [ -d "$r" ] || { echo "missing signed root: $r" >&2; exit 3; }
  done
  assert_all_recognised
  covered_files | xargs sha256sum > MANIFEST.sha256
  python3 - "$KEY" <<'PY'
import sys
from cryptography.hazmat.primitives.serialization import load_pem_private_key
sk = load_pem_private_key(open(sys.argv[1], "rb").read(), password=None)
open("MANIFEST.sha256.sig", "wb").write(sk.sign(open("MANIFEST.sha256", "rb").read()))
print("signed -> MANIFEST.sha256.sig")
PY
  echo "files covered: $(wc -l < MANIFEST.sha256)"
  ;;
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
./selftest.sh && ./verify.sh
```

Expected: `selftest.sh` all OK. `verify.sh` unchanged — still green, because `MANIFEST.sha256` has not been touched.

- [ ] **Step 5: Record the coverage delta for the release**

```bash
./sign-release.sh list > /tmp/acp_new_coverage.txt
awk '{print $2}' MANIFEST.sha256 | sed 's|^\./||' | sort > /tmp/acp_old_coverage.txt
diff /tmp/acp_old_coverage.txt /tmp/acp_new_coverage.txt
```

Expected, measured against the current tree on 2026-08-10: the old manifest covers **39** files; `covered_files()` returns **41**; with `selftest.sh` committed, **42**. Additions are exactly `LICENSE`, `.gitignore` and `selftest.sh`. Removals: **none** — if anything disappears, the coverage model has regressed and the task is not done.

`CLAUDE.md` and `sim/**` are untracked today, so `git ls-files` does not return them and they will **not** appear. That is correct behaviour, not a gap: a release covers what is committed. They join coverage on the commit that tracks them, which is a decision for the user, not this plan.

Paste the diff into the commit message — it is the record of what the next signature starts covering.

- [ ] **Step 6: Commit**

```bash
git add sign-release.sh selftest.sh
git commit -m "tools: sign and list share one coverage function

Records the coverage delta the next signature will introduce. Regenerating
and signing the manifest remains the key holder's action."
```

---

### Task 4: `verify.sh --suites`

**Files:**
- Modify: `verify.sh:7-29` (argument parsing, integrity, signature sections)
- Test: `selftest.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: `./verify.sh --suites` → proofs + 13 suite lines, exit 0 on a clean tree with no key present. `./verify.sh` unchanged.

- [ ] **Step 1: Write the failing test**

Append to `selftest.sh`:

```bash
printf '\n\033[1m== verify.sh --suites ==\033[0m\n'

OUT=$(./verify.sh --suites 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "--suites exits 0 (got $rc)"

hasnot '1\. Integrity'      "--suites skips integrity (no release key needed)"
hasnot 'Manifest signature' "--suites skips signature"
has    'Formal proofs'      "--suites still runs the proof step"

# One counting rule, shared with Task 5 Step 3: 13 suite lines + 1 proof line.
# Counting green/red result lines is exact; matching on labels like "Suite "
# breaks the moment a label is reworded.
n=$(echo "$OUT" | grep -cE '^  (OK|FAIL)')
[ "$n" -eq 14 ]; chk $? "--suites reports 14 result lines: 13 suites + proofs (got $n)"

OUT=$(./verify.sh --bogus 2>&1); rc=$?
[ $rc -eq 2 ]; chk $? "unknown flag exits 2 with usage (got $rc)"
```

- [ ] **Step 2: Run it to verify it fails**

```bash
./selftest.sh
```

Expected: FAIL. `verify.sh` ignores arguments; `--suites` runs integrity, which is green today, so "skips integrity" fails.

- [ ] **Step 3: Add argument parsing to `verify.sh`**

Insert after `cd "$(dirname "$0")"` (line 8). Note `${1:-}` — `set -u` is active and `$1` may be unset:

```bash
# --suites is the gate that does not need the offline release key: proofs and
# every suite, but not integrity or signature. It is what CI and every commit
# are measured against. Full verify.sh -- which additionally proves the bytes
# are the signed ones -- is the gate for a tagged release. Splitting these is
# not a weakening: sections 1-2 can only ever be green on a commit the key
# holder personally signed, so requiring them per-commit would make the gate
# unachievable rather than strict.
SUITES_ONLY=0
case "${1:-}" in
  --suites) SUITES_ONLY=1 ;;
  "")       ;;
  *)        echo "usage: $0 [--suites]" >&2; exit 2 ;;
esac
```

Guard sections 1 and 2 — wrap lines 24-46 (`hdr "1. Integrity"` through the end of the signature block):

```bash
if [ $SUITES_ONLY -eq 0 ]; then
  hdr "1. Integrity"
  ...existing body unchanged...
fi
```

Leave the header numbering as-is. Renumbering sections would break every dossier cross-reference to "§1 Integrity".

Then fix the closing message at `verify.sh:81`. `FAIL` is initialised to 0 at `:9` and sections 1–2 never run under `--suites`, so a clean `--suites` currently prints *"All replayed claims hold on this machine."* — which is false in that mode, because integrity was never replayed. In this repository a sentence the run does not prove is a defect:

```bash
if [ $FAIL -eq 0 ]; then
  if [ $SUITES_ONLY -eq 1 ]; then
    echo "  All suites and proofs replay on this machine."
    echo "  Integrity and signature NOT checked — run without --suites for those."
  else
    echo "  All replayed claims hold on this machine."
  fi
  echo "  This does NOT mean the system is reviewed: see §06 RR-1."
else

- [ ] **Step 4: Run the test to verify it passes**

```bash
./selftest.sh
```

Expected: all six `--suites` assertions OK.

- [ ] **Step 5: Prove the two modes agree on the suites**

```bash
./verify.sh --suites > /tmp/acp_suites.txt 2>&1; echo "suites exit=$?"
./verify.sh          > /tmp/acp_full.txt   2>&1; echo "full exit=$?"
diff <(grep -E '^  (OK|FAIL)' /tmp/acp_suites.txt) \
     <(grep -E '^  (OK|FAIL)' /tmp/acp_full.txt | grep -v 'MANIFEST\|signature')
```

Expected: no differences. `--suites` must be the same 13 lines plus proofs, not a reduced set.

- [ ] **Step 6: Commit**

```bash
git add verify.sh selftest.sh
git commit -m "verify: add --suites, the gate that needs no release key

Proofs plus all 13 suite lines. Integrity and signature remain in the full
run, which is the release gate. Sections 1-2 can only be green on a commit
the key holder signed, so per-commit full verify was never achievable."
```

---

### Task 5: Record the gate in the dossier

A gate nobody knows about is not a gate. This task is what stops the next contributor running full `verify.sh`, seeing red integrity mid-migration, and concluding the repository is broken.

**Files:**
- Modify: `07-REPRODUCTION.md` (the reproduction commands)
- Modify: `CLAUDE.md` (the Commands section)

**Interfaces:**
- Consumes: `verify.sh --suites`, `sign-release.sh list`.
- Produces: prose only.

- [ ] **Step 1: Add the gate distinction to `07-REPRODUCTION.md`**

Insert near the existing `./verify.sh` instructions:

```markdown
### Two gates

`./verify.sh --suites` runs the formal proofs and all 13 suite lines. It needs
no release key and is what every commit is measured against.

`./verify.sh` additionally checks that the bytes on your disk are the signed
release bytes. It is the gate for a tagged release. Between releases — during
a migration, or on any working tree — sections 1 and 2 are expected to be red,
because only the holder of the offline key can make them green. That is a
property of offline signing, not a failure.
```

- [ ] **Step 2: Update the `CLAUDE.md` Commands block**

Replace the first line of the bash block:

```bash
./verify.sh --suites               # proofs + all 13 suites — the per-commit gate, no key needed
./verify.sh                        # + integrity and signature — the release gate
./sign-release.sh list             # what the next signature will cover (no key needed)
sha256sum -c MANIFEST.sha256       # integrity only
```

- [ ] **Step 3: Verify the docs match the tools**

```bash
./verify.sh --suites 2>&1 | grep -cE '^  (OK|FAIL)'
```

Expected: `14` — 13 suite lines plus the proof line. If the prose says 13 suites and this prints something else, the prose is wrong and is a defect under this repository's rules.

- [ ] **Step 4: Commit**

```bash
git add 07-REPRODUCTION.md CLAUDE.md
git commit -m "docs: record the two gates and why integrity is red between releases"
```

---

## Step 0 exit criteria

- [ ] `./selftest.sh` — all assertions OK
- [ ] `./verify.sh --suites` — exit 0, proofs + 13 suite lines
- [ ] `./verify.sh` — unchanged from baseline (integrity green, because `MANIFEST.sha256` was never regenerated)
- [ ] `./sign-release.sh list` — exit 0; coverage delta recorded in a commit message
- [ ] `git status --short` — no unintended modifications to `artifacts/`

Manifest regeneration and signing are **not** part of step 0. They happen once, at the v1.3.13 release in step 2, by the key holder.

---

## Step 1 — planned separately, and why

Step 1 (extract `spec/vectors/`, make the Python suites run from it, write `OBLIGATIONS.md`) is **not** planned here.

The reason is a finding, not a scheduling preference. The 44 conformance cases are not data today — they are perturbation functions. Each builds an honest scenario from shared fixtures and mutates one thing:

```python
def a_CR1_unknown_suite():
    b, ex = fresh(); p = proposal()
    r = receipt(b, p, atts=quorum(b, p))
    r["alg"] = "rot13"          # <- the whole attack
    ex.execute(r, p)
```

That shape extracts cleanly to *scenario + mutation + expected rule*. But a real subset does not extract at all:

| Case | Why it resists |
|---|---|
| `a_DR_shared_render_library` | Passes one function *object* to both render paths — object identity, not data |
| `a_DR_notification_undeliverable` | Needs a notifier that raises |
| `a_nonce_replay`, `a_T14_attestation_replay` | Two `execute` calls — a sequence, not a case |
| `a_capability_revoked` | Mutates the context store between calls |
| `t_sampling_forces_confirmation` | Depends on DR-10 CSPRNG sampling |

**The size and shape of step 1's task list depends on how many of the 44 fall on each side of that line, and that classification is itself the first task.** Writing task-by-task steps for extraction before knowing which cases are extractable would mean inventing detail — the failure this repository exists to argue against.

Step 1 therefore opens with one discovery task:

> Classify all 44 conformance cases (8 positive, 36 attacks) plus the 8 encoding, 14 ack and 11 audit cases as **extractable** (scenario + mutation + expected verdict) or **obligation** (behavioural, sequential, or structural). Emit the split as `spec/vectors/OBLIGATIONS.md`, with every obligation naming the property it carries and why no vector expresses it.

Once that file exists, step 1's remaining tasks — vector format, extractor, runner, per-suite migration — can be planned against a known corpus size. Design constraint **RES-P5** from the design doc binds this: vectors must be defined over canonical bytes and declared mutations, never over signatures, or the corpus is not portable to a Rust implementation using real Ed25519 and ML-DSA where the reference uses modelled HMAC.
