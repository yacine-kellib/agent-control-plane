#!/usr/bin/env bash
# sync-counts.sh — re-derive the published counts THIS FILE HAS A RULE FOR, and
# write them back into the prose that publishes them.
#
#   ./tools/sync-counts.sh           rewrite the published counts
#   ./tools/sync-counts.sh --check   report drift, change nothing
#
# WHY THIS EXISTS. `tools/selftest.sh` already DETECTS published-count drift and
# fails on it — that is its job and it has caught three real defects. What it
# does not do is repair it, so every time a count moved, the numbers were hunted
# down and substituted BY HAND. That is a deterministic, repetitive edit driven
# entirely by values a command already prints, and it had been done by hand
# often enough to become its own defect class: ACP-42 and ACP-43 are both
# published-count drift, the second a recurrence of the first.
#
# So detection and repair are now both commands. Anything checkable by a command
# must be checked by a command; anything derivable by a command should not be
# retyped by a person or by a model.
#
# WHAT IT WILL NOT TOUCH, deliberately:
#
# - RELEASE.md's historical prose. Sentences like "went from 27 assertions to 29,
#   and to 34 in v1.3.14" are a RECORD of what was true at a past release. A
#   script that helpfully updated those would rewrite history to match the
#   present, which is the opposite of what a release note is for.
# - Numbers written as words ("across sixteen cases"). They are prose and they
#   are rewritten by whoever changes the sentence around them.
# - Anything no rule below names. Coverage is exactly the target lists in the
#   sync rules: there is no directory sweep, no default and no deny-list, so a
#   count in a file no rule names has no generator at all.
#
#   A correction worth recording: this bullet used to read "anything under
#   spec/ or dossier/ — those are the argument, not the readme". It was false
#   ONE COMMIT after it was written: the very next change to this file added
#   four dossier targets, and spec/ followed later. So it stood for its whole
#   life describing a boundary the rules below did not have, and nobody
#   re-read it, because a comment has no gate. It read like a fence and was
#   really a roster kept by hand — the defect class this script exists to
#   close, recurring one level up, inside the closer.
#
#   The zone genuinely outside is docs/: no rule reaches it. So
#   docs/plans/roadmap.md went on publishing "52 conformance cases" while the
#   suite printed 53 — the ACP-42 / ACP-43 drift shape, alive outside the
#   fence and undetected. Detection does not rescue it: selftest.sh scans
#   every tracked .md, docs/ included, but for the single phrase
#   "(N assertions)" and for nothing else, so a conformance count there is
#   read by neither tool.
#
#   Publishing a count in a file no rule names is choosing to maintain it by
#   hand; the honest repair is a rule here, not a careful hand edit there.
#
# It therefore reduces the hand-editing rather than eliminating it, and
# `selftest.sh` remains the authority on whether anything was missed. Run this,
# then run selftest.sh: if selftest is still red, the miss is real and belongs
# either in this script or in a hand edit.
set -uo pipefail
cd "$(dirname "$0")/.."

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

DRIFT=0
# ACP-83. A MISS is NOT drift and must not be folded into it. Drift is
# expected in write mode -- writing is the whole point -- so DRIFT only
# reaches the exit code under --check. A MISS is never expected: it means the
# pattern matched nothing, so the sync is VACUOUS and the count it claims to
# keep in step is unchecked. Counted separately, and it fails BOTH modes.
#
# It went unnoticed for a day because the script said 'this sync is vacuous'
# and exited 0, and a handoff recorded that exit 0 as a green result. A
# detector whose failure does not fail the build is documentation.
VACUOUS=0

# Rewrite one sed pattern across the named files, reporting whether it moved.
#
# Takes the DERIVED value and a sed expression carrying a \1-style capture, so a
# pattern that matches nothing is visible as "0 occurrences" rather than
# silently succeeding. A substitution that matches nothing is the shape of a
# check that cannot fail.
sync() {
  local label="$1" want="$2" pattern="$3" replacement="$4"; shift 4
  local files=("$@")
  # '|' is the sed delimiter chosen below, so a '|' anywhere in the pattern or
  # the replacement closes the expression early. That surfaces as a bare
  # "sed failed", which says nothing about the cause -- it has cost two HALTs
  # and one clobbered dossier row already. Name it instead of discovering it.
  case "$pattern$replacement" in
    *"|"*)
      printf '  \033[31mHALT\033[0m  %-28s pattern or replacement contains "|",\n' "$label"
      printf '        which is this function'"'"'s sed delimiter. Anchor on\n'
      printf '        surrounding prose, or match the pipe with ".".\n'
      exit 2 ;;
  esac
  local hits=0 moved=0 f before after
  for f in "${files[@]}"; do
    [ -f "$f" ] || continue
    before=$(grep -cE "$pattern" "$f" 2>/dev/null || true)
    hits=$((hits + before))
    [ "$before" -eq 0 ] && continue
    # '|' as the delimiter, not '/': several of these patterns contain a
    # slash ("32/32", "bundle_suite.py"), which silently terminated the
    # expression early and produced "bad flag in substitute command".
    #
    # sed writes to a TEMP FILE, not to a shell variable. $( ) strips EVERY
    # trailing newline, so a file ending in a blank line came back one line
    # short and tripped the guard below -- a HALT on a perfectly correct
    # substitution, which made spec/ACP-DEPLOY-001.md permanently unsyncable
    # and would have done the same to any future file ending in a blank line.
    # Comparing files rather than strings also makes the write byte-exact.
    TMP=$(mktemp)
    if ! sed -E "s|$pattern|$replacement|g" "$f" > "$TMP" 2>/dev/null; then
      rm -f "$TMP"
      printf '  \033[31mHALT\033[0m  %-28s sed failed on %s\n' "$label" "$f"
      exit 2
    fi
    # Every substitution here is IN-LINE, so the line count is invariant. This
    # assertion exists because the check below is "did the bytes change?", which
    # answers YES to a sed that produced garbage: a '|' in a replacement string
    # closed the expression early and this script wrote a 134-line dossier file
    # back as one blank line, printing SYNC. A destructive edit that reports
    # success is worse than the drift the script exists to remove, so it halts
    # (exit 2, distinct from 1 = drift) rather than writing.
    if [ "$(wc -l < "$TMP")" -ne "$(wc -l < "$f")" ]; then
      printf '  \033[31mHALT\033[0m  %-28s %s: line count would change\n' "$label" "$f"
      printf '        (%s -> %s) — the pattern or replacement is malformed;\n' \
        "$(wc -l < "$f")" "$(wc -l < "$TMP")"
      printf '        refusing to write. Nothing was modified.\n'
      rm -f "$TMP"
      exit 2
    fi
    if ! cmp -s "$TMP" "$f"; then
      moved=$((moved + 1))
      DRIFT=1
      if [ $CHECK -eq 1 ]; then
        printf '  \033[33mDRIFT\033[0m %-28s %s would change\n' "$label" "$f"
      else
        cat "$TMP" > "$f"
        printf '  \033[32mSYNC\033[0m  %-28s %s -> %s\n' "$label" "$f" "$want"
      fi
    fi
    rm -f "$TMP"
  done
  if [ "$hits" -eq 0 ]; then
    printf '  \033[31mMISS\033[0m  %-28s pattern matched nothing — the published\n' "$label"
    printf '        claim moved or was deleted, so this sync is vacuous\n'
    DRIFT=1
    VACUOUS=$((VACUOUS + 1))
  elif [ "$moved" -eq 0 ]; then
    printf '  \033[32mOK\033[0m    %-28s %s (%d occurrence(s))\n' "$label" "$want" "$hits"
  fi
}

printf '\n\033[1m== deriving ==\033[0m\n'

COVERED=$(./tools/sign-release.sh list | wc -l | tr -d ' ')

# ACP-66 shrank ROOTS from ten entries to eight and nothing caught the five
# places that still said "ten", because the number was published as a WORD and
# no derivation can match a word. Publishing it as a numeral is what makes it
# checkable at all. Same defect as ACP-42 and ACP-43: a count kept by hand is a
# count that drifts, and the fix is to derive it, not to be more careful.
ROOTS_N=$(sed -n 's/^ROOTS="\(.*\)"$/\1/p' tools/sign-release.sh | wc -w | tr -d ' ')
printf '  signed roots       %s   (sign-release.sh ROOTS)\n' "$ROOTS_N"
printf '  covered files      %s   (sign-release.sh list)\n' "$COVERED"

RUST=$(cargo test --workspace 2>&1 \
  | grep -E '^test result:' \
  | awk -F'[ ;]' '{p+=$4} END {print p+0}')
printf '  rust tests         %s   (cargo test --workspace)\n' "$RUST"

BUNDLE=$(cd reference/suites && PYTHONPATH=../src python3 bundle_suite.py 2>/dev/null \
  | grep -oE 'RESULT: [0-9]+/[0-9]+' | grep -oE '[0-9]+/[0-9]+')
printf '  suite 11           %s (bundle_suite.py)\n' "$BUNDLE"

# ACP-74. Suites 1 and 2 were never sync targets, and one added conformance case
# moved "52/52" across six published sites and the 43/9 split across three more
# -- every one found by grep and edited by hand, which is exactly the drift this
# script exists to remove. It had simply never been pointed at the two suites the
# dossier quotes most often.
#
# BOTH ARE DERIVED ONLY FROM A CLEAN RUN. A failing mutation run prints
# "25/26 killed" in the same shape as a passing one, and syncing that would
# publish a partial result as the expected value -- the instrument rewriting its
# own answer, which is why the gate-line count above refuses the same trick.
CONFORM=$(cd reference/suites && PYTHONPATH=../src python3 conformance.py 2>/dev/null \
  | grep -oE 'RESULT: [0-9]+/[0-9]+' | grep -oE '[0-9]+/[0-9]+')
[ -n "$CONFORM" ] && [ "${CONFORM%%/*}" = "${CONFORM##*/}" ] || CONFORM=""
printf '  suite 1            %s (conformance.py)\n' "${CONFORM:-? (not clean)}"

# The 43/9 split is published separately from the total, in three places, and it
# is the half that goes stale silently: 52 stays right while "43 attacks" quietly
# becomes 44. Taken from the lists themselves rather than parsed out of prose.
CONF_SPLIT=$(cd reference/suites && PYTHONPATH=../src python3 -c \
  'import conformance as C; print(len(C.ATTACKS), len(C.POSITIVE))' 2>/dev/null)
CONF_ATK=${CONF_SPLIT%% *}; CONF_POS=${CONF_SPLIT##* }
[ -n "$CONF_ATK" ] && CONF_TOTAL=$((CONF_ATK + CONF_POS)) || CONF_TOTAL=""
printf '  suite 1 split      %s attacks + %s positive = %s\n' \
  "${CONF_ATK:-?}" "${CONF_POS:-?}" "${CONF_TOTAL:-?}"

MUTEXEC=$(cd reference/suites && PYTHONPATH=../src python3 mutate_executor.py 2>/dev/null \
  | grep -oE 'RESULT: [0-9]+/[0-9]+ killed' | grep -oE '[0-9]+/[0-9]+')
[ -n "$MUTEXEC" ] && [ "${MUTEXEC%%/*}" = "${MUTEXEC##*/}" ] || MUTEXEC=""
printf '  suite 2            %s (mutate_executor.py)\n' "${MUTEXEC:-? (not clean)}"

# The AGGREGATE "N mutants" claim, published in ten files including the
# Dockerfile, the compose file and both .github templates. It is a sum of three
# lists that live in three suites, so it is the number most exposed to one of
# them moving -- and adding a single mutant moves it everywhere at once.
MUT_SPLIT=$(cd reference/suites && PYTHONPATH=../src python3 -c \
  'import mutate_executor as M, ack_suite as A, audit_suite as U;
print(len(M.MUTANTS), len(A.MUTANTS), len(U.MUTANTS))' 2>/dev/null | tr -d '\n')
MUT_E=$(printf '%s' "$MUT_SPLIT" | cut -d' ' -f1)
MUT_A=$(printf '%s' "$MUT_SPLIT" | cut -d' ' -f2)
MUT_U=$(printf '%s' "$MUT_SPLIT" | cut -d' ' -f3)
if [ -n "$MUT_E" ] && [ -n "$MUT_A" ] && [ -n "$MUT_U" ]; then
  MUT_TOTAL=$((MUT_E + MUT_A + MUT_U))
else
  MUT_TOTAL=""
fi
printf '  mutants, all three %s executor + %s ack + %s audit = %s\n' \
  "${MUT_E:-?}" "${MUT_A:-?}" "${MUT_U:-?}" "${MUT_TOTAL:-?}"

# Suite 7 joined this script when ACP-57 added the AU-1 conformance case and
# moved 11/11 -> 12/12 across SEVEN published sites. Suite 11 needed two. The
# dossier replays this one by name, and README's "if a claim here does not
# replay on your machine, don't believe it" is only true if that number is
# derived rather than remembered.
AUDIT=$(cd reference/suites && PYTHONPATH=../src python3 audit_suite.py 2>/dev/null \
  | grep -oE 'RESULT: [0-9]+/[0-9]+' | grep -oE '[0-9]+/[0-9]+')
printf '  suite 7            %s (audit_suite.py)\n' "$AUDIT"

# The consolidated registry iterates `audit_suite.TESTS` (and cbor's, ack's and
# class_findings') wholesale, so it is DOWNSTREAM of suite 7: adding the AU-1
# case moved it 80 -> 81 and turned the gate red on a line nobody had touched.
# Deriving it is the only way that coupling stays visible -- the alternative is
# discovering it from a FAIL after every suite edit.
REGISTRY=$(cd reference/suites && PYTHONPATH=../src python3 attack_registry.py 2>/dev/null \
  | grep -oE 'RESULT: [0-9]+/[0-9]+' | grep -oE '[0-9]+/[0-9]+')
printf '  attack registry    %s (attack_registry.py)\n' "$REGISTRY"

# selftest LAST: it runs the gate and is the slowest, and its own assertion
# count is what we publish. The printed TOTAL already includes the
# self-counting final assertion, so it is the published figure directly — see
# the comment above that block in selftest.sh before changing this.
# One selftest run, two derivations. It used to be run once for ASSERTIONS; the
# gate line count is measured inside the same run, so taking both from one
# invocation costs nothing and cannot disagree with itself.
SELFOUT=$(./tools/selftest.sh 2>/dev/null || true)
ASSERTIONS=$(printf '%s\n' "$SELFOUT" \
  | grep -oE 'tooling self-test (passed|FAILED) \([0-9]+ assertions\)' \
  | grep -oE '[0-9]+')
printf '  selftest assertions %s  (selftest.sh)\n' "${ASSERTIONS:-?}"

# ACP-68. The gate's line count is taken from the MEASURED figure selftest prints
# as "(got N)", never from the constant it compares against -- syncing prose to
# the expectation would let a wrong expectation propagate itself, which is the
# instrument rewriting its own answer.
#
# tools/selftest.sh and this file are NEVER sync targets for the same reason.
LINES=$(printf '%s\n' "$SELFOUT" | grep -oE 'result lines: prereqs \+ proofs .*\(got [0-9]+\)' \
  | grep -oE 'got [0-9]+' | grep -oE '[0-9]+')
SUITES=$((LINES - 3))          # minus prerequisites, proofs and the harness line
LINES_NO_DAFNY=$((LINES - 1))  # section 3 prints SKIP where Dafny is absent
LINES_FULL=$((LINES + 2))      # plus integrity and signature, which --suites omits
printf '  gate result lines   %s   (measured; %s suites, %s without Dafny, %s full)\n' \
  "$LINES" "$SUITES" "$LINES_NO_DAFNY" "$LINES_FULL"

printf '\n\033[1m== syncing ==\033[0m\n'

sync "covered files (covers N)" "$COVERED" \
  'covers [0-9]+ files' "covers $COVERED files" \
  README.md

sync "covered files (Coverage is)" "$COVERED" \
  'Coverage is [0-9]+ files' "Coverage is $COVERED files" \
  CLAUDE.md

sync "covered files (sample run)" "$COVERED" \
  '[0-9]+ files match MANIFEST\.sha256' "$COVERED files match MANIFEST.sha256" \
  README.md

sync "signed roots (in ROOTS)" "$ROOTS_N" \
  'the [0-9]+ directories in `ROOTS`' "the $ROOTS_N directories in \`ROOTS\`" \
  CLAUDE.md

sync "signed roots (across N)" "$ROOTS_N" \
  'across [0-9]+ roots' "across $ROOTS_N roots" \
  CLAUDE.md

sync "signed roots (signed)" "$ROOTS_N" \
  'across [0-9]+ signed roots' "across $ROOTS_N signed roots" \
  README.md

sync "signed roots (deploy spec)" "$ROOTS_N" \
  'the [0-9]+ signed roots' "the $ROOTS_N signed roots" \
  spec/ACP-DEPLOY-001.md

sync "rust tests" "$RUST" \
  '# Rust: [0-9]+ tests' "# Rust: $RUST tests" \
  README.md CLAUDE.md

# ACP-68: every file below published a count that no derivation reached. The
# suite count alone was written four different ways and had drifted to 13 and 14
# in different files simultaneously. RELEASE.md's v1.3.13 changelog section is
# deliberately NOT a target -- "all 13 suites" is correct history, and syncing it
# would rewrite the past to match the present.
sync "gate suites (proofs +)" "$SUITES" \
  'proofs \+ [0-9]+ suites' "proofs + $SUITES suites" \
  README.md CLAUDE.md RELEASE.md .github/CONTRIBUTING.md .github/SECURITY.md \
  .github/workflows/verify.yml deploy/docker-compose.yml dossier/07-REPRODUCTION.md

sync "gate suites (all N)" "$SUITES" \
  'all [0-9]+ suites' "all $SUITES suites" \
  dossier/00-INDEX.md

# ACP-72: deploy/docker-compose.yml is a target here because it now QUOTES the
# entrypoint's banner verbatim, and selftest.sh asserts the two match. Sync them
# together or the next suite-count change updates the entrypoint, leaves the
# quote behind, and turns that assertion red with no derivation able to fix it.
sync "gate suites (+ harness)" "$SUITES" \
  '[0-9]+ suites \+ harness' "$SUITES suites + harness" \
  tools/demonstrator-entrypoint.sh deploy/docker-compose.yml

sync "gate suites (1 proofs +)" "$SUITES" \
  '1 proofs \+ [0-9]+ suites' "1 proofs + $SUITES suites" \
  .github/CONTRIBUTING.md

sync "gate suites (comma form)" "$SUITES" \
  '1 proofs, [0-9]+ suites' "1 proofs, $SUITES suites" \
  dossier/07-REPRODUCTION.md

sync "gate result lines (bold)" "$LINES" \
  '\*\*[0-9]+\*\* result lines' "**$LINES** result lines" \
  README.md CLAUDE.md .github/CONTRIBUTING.md .github/PULL_REQUEST_TEMPLATE.md \
  dossier/07-REPRODUCTION.md

sync "gate result lines (plain)" "$LINES" \
  'Expect [0-9]+ result lines' "Expect $LINES result lines" \
  .github/workflows/verify.yml

sync "gate result lines (exactly)" "$LINES" \
  'exactly [0-9]+ lines' "exactly $LINES lines" \
  .github/workflows/verify.yml

sync "gate lines, no Dafny" "$LINES_NO_DAFNY" \
  'prints [0-9]+ result lines instead of' "prints $LINES_NO_DAFNY result lines instead of" \
  .github/workflows/verify.yml

sync "gate lines, full run" "$LINES_FULL" \
  'complete run prints [0-9]+ result lines' "complete run prints $LINES_FULL result lines" \
  README.md

sync "selftest assertions (PR)" "$ASSERTIONS" \
  'passes \([0-9]+ assertions\)' "passes ($ASSERTIONS assertions)" \
  .github/PULL_REQUEST_TEMPLATE.md

if [ -n "$ASSERTIONS" ]; then
  sync "selftest assertions" "$ASSERTIONS" \
    'tests the tooling itself \([0-9]+ assertions\)' \
    "tests the tooling itself ($ASSERTIONS assertions)" \
    README.md CLAUDE.md .github/CONTRIBUTING.md
else
  printf '  \033[31mMISS\033[0m  %-28s selftest.sh printed no assertion count\n' "selftest assertions"
  DRIFT=1
fi

if [ -n "$BUNDLE" ]; then
  sync "suite 11 (CLAUDE.md)" "$BUNDLE" \
    '# [0-9]+/[0-9]+  the policy bundle' "# $BUNDLE  the policy bundle" \
    CLAUDE.md
  sync "suite 11 (verify.sh)" "$BUNDLE" \
    'run bundle_suite\.py( +)"[0-9]+/[0-9]+"' "run bundle_suite.py\\1\"$BUNDLE\"" \
    tools/verify.sh
fi

if [ -n "$AUDIT" ]; then
  sync "suite 7 (CLAUDE.md)" "$AUDIT" \
    'audit_suite\.py( +)# [0-9]+/[0-9]+' "audit_suite.py\\1# $AUDIT" \
    CLAUDE.md
  # The label is part of the pattern on purpose: verify.sh runs audit_suite.py
  # TWICE, and a pattern matching only the script name would rewrite the
  # --mutate line's 4/4 to the test count and green a gate that checks nothing.
  sync "suite 7 (verify.sh)" "$AUDIT" \
    'run audit_suite\.py( +)"[0-9]+/[0-9]+"( +)"Suite 7  audit/anchor' \
    "run audit_suite.py\\1\"$AUDIT\"\\2\"Suite 7  audit/anchor" \
    tools/verify.sh
  # Anchored on the mutant count rather than on the table's cell boundary:
  # the row is a markdown table and every '|' in it is this sed's delimiter.
  sync "suite 7 (dossier tables)" "$AUDIT" \
    '\*\*[0-9]+/[0-9]+\*\*, mutants \*\*4/4\*\*' \
    "**$AUDIT**, mutants **4/4**" \
    dossier/01-EXECUTIVE-SUMMARY.md
  sync "suite 7 (dossier prose)" "$AUDIT" \
    'accumulators \([0-9]+/[0-9]+, 4/4 mutants\)' \
    "accumulators ($AUDIT, 4/4 mutants)" \
    dossier/05-TEST-EVIDENCE.md
  sync "suite 7 (finding-not-count)" "$AUDIT" \
    'not the [0-9]+/[0-9]+:' "not the $AUDIT:" \
    dossier/05-TEST-EVIDENCE.md
  sync "suite 7 (residual risk)" "$AUDIT" \
    'Suite 7: [0-9]+/[0-9]+, 4/4 mutants' "Suite 7: $AUDIT, 4/4 mutants" \
    dossier/06-RESIDUAL-RISK.md
  sync "suite 7 (reproduction)" "$AUDIT" \
    'audit_suite\.py( +)# expected: [0-9]+/[0-9]+' \
    "audit_suite.py\\1# expected: $AUDIT" \
    dossier/07-REPRODUCTION.md
fi

if [ -n "$CONFORM" ]; then
  sync "suite 1 (CLAUDE.md)" "$CONFORM" \
    'conformance\.py( +)# [0-9]+/[0-9]+' "conformance.py\1# $CONFORM" \
    CLAUDE.md
  sync "suite 1 (verify.sh)" "$CONFORM" \
    'run conformance\.py( +)"[0-9]+/[0-9]+"' "run conformance.py\1\"$CONFORM\"" \
    tools/verify.sh
  sync "suite 1 (README sample)" "$CONFORM" \
    'Suite 1  conformance([^0-9]+)RESULT: [0-9]+/[0-9]+' \
    "Suite 1  conformance\1RESULT: $CONFORM" \
    README.md
  sync "suite 1 (dossier header)" "$CONFORM" \
    '## Suite 1([^0-9]+)Conformance \([0-9]+/[0-9]+\)' \
    "## Suite 1\1Conformance ($CONFORM)" \
    dossier/05-TEST-EVIDENCE.md
  sync "suite 1 (reproduction)" "$CONFORM" \
    'conformance\.py( +)# expected: [0-9]+/[0-9]+ CONFORMANT' \
    "conformance.py\1# expected: $CONFORM CONFORMANT" \
    dossier/07-REPRODUCTION.md
  sync "suite 1 (Dockerfile)" "$CONFORM" \
    'the [0-9]+/[0-9]+ conformance result' "the $CONFORM conformance result" \
    Dockerfile
fi

# The attacks/positive split. Published apart from the total, and it is the half
# that rots quietly: the total stays right while "43 attacks" becomes 44.
if [ -n "$CONF_ATK" ]; then
  sync "suite 1 split (summary)" "$CONF_ATK/$CONF_POS" \
    '\*\*[0-9]+/[0-9]+\*\*([^0-9]+)[0-9]+ attacks fail closed, [0-9]+ honest paths execute' \
    "**$CONFORM**\1$CONF_ATK attacks fail closed, $CONF_POS honest paths execute" \
    dossier/01-EXECUTIVE-SUMMARY.md
  sync "suite 1 split (why not N)" "$CONF_TOTAL/$CONF_ATK" \
    'the suite total is [0-9]+ and not [0-9]+' \
    "the suite total is $CONF_TOTAL and not $CONF_ATK" \
    dossier/05-TEST-EVIDENCE.md
  sync "suite 1 split (obligation)" "$CONF_ATK/$CONF_POS" \
    '\*\*[0-9]+ attacks must fail closed; [0-9]+ honest paths must execute\.\*\*' \
    "**$CONF_ATK attacks must fail closed; $CONF_POS honest paths must execute.**" \
    dossier/05-TEST-EVIDENCE.md
  sync "suite 1 split (vectors)" "$CONF_ATK/$CONF_POS" \
    '## Suite 1([^0-9]+)conformance \([0-9]+ cases: [0-9]+ positive, [0-9]+ attacks\)' \
    "## Suite 1\1conformance ($CONF_TOTAL cases: $CONF_POS positive, $CONF_ATK attacks)" \
    spec/vectors/CLASSIFICATION.md
fi

if [ -n "$MUTEXEC" ]; then
  sync "suite 2 (CLAUDE.md)" "$MUTEXEC" \
    'mutate_executor\.py( +)# [0-9]+/[0-9]+' "mutate_executor.py\1# $MUTEXEC" \
    CLAUDE.md
  sync "suite 2 (verify.sh)" "$MUTEXEC" \
    'run mutate_executor\.py( +)"[0-9]+/[0-9]+"' "run mutate_executor.py\1\"$MUTEXEC\"" \
    tools/verify.sh
  sync "suite 2 (README sample)" "$MUTEXEC" \
    'Suite 2  executor mutation([^0-9]+)RESULT: [0-9]+/[0-9]+ killed' \
    "Suite 2  executor mutation\1RESULT: $MUTEXEC killed" \
    README.md
  sync "suite 2 (dossier header)" "$MUTEXEC" \
    '## Suite 2([^0-9]+)Implementation mutation \([0-9]+/[0-9]+ kill\)' \
    "## Suite 2\1Implementation mutation ($MUTEXEC kill)" \
    dossier/05-TEST-EVIDENCE.md
  sync "suite 2 (reproduction)" "$MUTEXEC" \
    'mutate_executor\.py( +)# expected: [0-9]+/[0-9]+ killed' \
    "mutate_executor.py\1# expected: $MUTEXEC killed" \
    dossier/07-REPRODUCTION.md
  # ANCHORED ON THE ROW'S OWN WORDS, and this one bit on its first run. The
  # bare '\*\*[0-9]+/[0-9]+ kill\*\*' pattern matched TWO rows of that table
  # and rewrote "Mutation controls on the proofs | **9/9 kill**" to the executor
  # figure -- a sync that corrupts an unrelated published claim while printing
  # SYNC. Caught by reading the diff, which is not a control; the anchor is.
  #
  # The anchor is the trailing prose rather than the row LABEL because the label
  # is followed by a table '|', and '|' is this function's sed delimiter.
  sync "suite 2 (summary)" "$MUTEXEC" \
    '\*\*[0-9]+/[0-9]+ kill\*\*([^0-9]+)every check is load-bearing' \
    "**$MUTEXEC kill**\1every check is load-bearing" \
    dossier/01-EXECUTIVE-SUMMARY.md
fi

# The aggregate. Ten files, four phrasings, one sum of three lists -- so a
# mutant added to any one suite moves a number in the Dockerfile, the compose
# file and both .github templates at once. That is precisely the coupling
# nobody re-greps for.
#
# The compose and entrypoint lines are synced TOGETHER and deliberately:
# ACP-72 made the compose comment quote the entrypoint's banner verbatim and
# selftest.sh compares them, so they must move in the same run or the gate
# reports a mismatch this script created.
if [ -n "$MUT_TOTAL" ]; then
  sync "mutants (CLAUDE.md sum)" "$MUT_TOTAL" \
    '[0-9]+ \+ [0-9]+ \+ [0-9]+ = \*\*[0-9]+ mutants\*\*' \
    "$MUT_E + $MUT_A + $MUT_U = **$MUT_TOTAL mutants**" \
    CLAUDE.md
  sync "mutants (not the N)" "$MUT_TOTAL" \
    'not the [0-9]+ mutants' "not the $MUT_TOTAL mutants" \
    CLAUDE.md
  sync "mutants (do not express)" "$MUT_TOTAL" \
    'express the [0-9]+ mutants' "express the $MUT_TOTAL mutants" \
    dossier/06-RESIDUAL-RISK.md crates/acp-conformance/src/lib.rs
  sync "mutants (Dockerfile)" "$MUT_TOTAL" \
    'and the [0-9]+ mutants' "and the $MUT_TOTAL mutants" \
    Dockerfile
  sync "mutants (image banner)" "$MUT_TOTAL" \
    'suites \+ harness \+ [0-9]+ mutants' "suites + harness + $MUT_TOTAL mutants" \
    tools/demonstrator-entrypoint.sh deploy/docker-compose.yml
  sync "mutants (compose split)" "$MUT_TOTAL" \
    '\([0-9]+ executor \+ [0-9]+ ack \+ [0-9]+ audit = [0-9]+ mutants\)' \
    "($MUT_E executor + $MUT_A ack + $MUT_U audit = $MUT_TOTAL mutants)" \
    deploy/docker-compose.yml
  sync "mutants (obligations)" "$MUT_TOTAL" \
    '\*\*[0-9]+ mutants: [0-9]+ executor, [0-9]+ acknowledgement, [0-9]+ audit\.\*\*' \
    "**$MUT_TOTAL mutants: $MUT_E executor, $MUT_A acknowledgement, $MUT_U audit.**" \
    spec/vectors/OBLIGATIONS.md
  sync "mutants (obligations row)" "$MUT_TOTAL" \
    '\*\([0-9]+ mutants, no case rows\)\*' "*($MUT_TOTAL mutants, no case rows)*" \
    spec/vectors/OBLIGATIONS.md
  # README publishes the same fact TWICE, in two phrasings that drifted apart
  # once already ("30 mutation controls" beside "34 of them: 24 executor..."
  # while the suites held 35). selftest.sh asserts both, so both are synced --
  # syncing one of a pair is how a pair comes to disagree.
  sync "mutants (README total)" "$MUT_TOTAL" \
    '[0-9]+ mutation controls' "$MUT_TOTAL mutation controls" \
    README.md
  sync "mutants (README split)" "$MUT_TOTAL" \
    '[0-9]+ of them: [0-9]+ executor, [0-9]+ acknowledgement, [0-9]+ audit' \
    "$MUT_TOTAL of them: $MUT_E executor, $MUT_A acknowledgement, $MUT_U audit" \
    README.md
  # And the classification file's own phrasing, which is a third one again.
  sync "mutants (vector cases)" "$MUT_TOTAL" \
    '\*\*[0-9]+ mutation cases\*\*([^0-9]+)[0-9]+ executor, [0-9]+ ack, [0-9]+ audit' \
    "**$MUT_TOTAL mutation cases**\1$MUT_E executor, $MUT_A ack, $MUT_U audit" \
    spec/vectors/CLASSIFICATION.md
  sync "mutants (PR template)" "$MUT_TOTAL" \
    'that [0-9]+ mutants locate' "that $MUT_TOTAL mutants locate" \
    .github/PULL_REQUEST_TEMPLATE.md
  sync "mutants (contributing)" "$MUT_TOTAL" \
    '\*\*[0-9]+ mutants\*\* must keep being killed: [0-9]+ executor, [0-9]+ ack, [0-9]+ audit' \
    "**$MUT_TOTAL mutants** must keep being killed: $MUT_E executor, $MUT_A ack, $MUT_U audit" \
    .github/CONTRIBUTING.md
fi

if [ -n "$REGISTRY" ]; then
  sync "registry (CLAUDE.md)" "$REGISTRY" \
    'attack_registry\.py( +)# [0-9]+/[0-9]+' "attack_registry.py\\1# $REGISTRY" \
    CLAUDE.md
  # Label-anchored for the same reason the suite 7 line above is: verify.sh
  # runs attack_registry.py TWICE, and the bare-script pattern rewrote the
  # --compose line's 4/4 to the registry total. It was caught by reading the
  # file after the sync, which is not a control -- hence this comment.
  sync "registry (verify.sh)" "$REGISTRY" \
    'run attack_registry\.py( +)"[0-9]+/[0-9]+"( +)"ALL attacks' \
    "run attack_registry.py\\1\"$REGISTRY\"\\2\"ALL attacks" \
    tools/verify.sh
  sync "registry (README sample)" "$REGISTRY" \
    '\(consolidated registry\)([^0-9]+)RESULT: [0-9]+/[0-9]+' \
    "(consolidated registry)\1RESULT: $REGISTRY" \
    README.md
  sync "registry (dossier)" "$REGISTRY" \
    'consolidated registry and composition \([0-9]+/[0-9]+, 4/4\)' \
    "consolidated registry and composition ($REGISTRY, 4/4)" \
    dossier/05-TEST-EVIDENCE.md
fi

printf '\n\033[1m== Result ==\033[0m\n'
# ACP-83, checked before anything else: a vacuous sync is a worse outcome than
# drift. Drift means a number is stale and this script can fix it. A MISS means
# the script CANNOT SEE the number any more, so every future run reports
# success about a claim nobody is checking. Exit 3, distinct from 1 (drift) and
# 2 (halt), so a caller can tell the three apart.
if [ $VACUOUS -ne 0 ]; then
  printf '  \033[31m%d check(s) matched nothing — this run is VACUOUS for them.\033[0m\n' "$VACUOUS"
  echo "  Every MISS above is a published count that is no longer being kept in"
  echo "  step. Repair the pattern; do NOT repair the prose to suit the pattern."
  exit 3
fi
if [ $CHECK -eq 1 ]; then
  if [ $DRIFT -eq 0 ]; then
    echo "  every published count matches the tooling."
    exit 0
  fi
  echo "  published counts have drifted — run ./tools/sync-counts.sh"
  exit 1
fi
echo "  done. Now run ./tools/selftest.sh: it is the authority on whether"
echo "  anything was missed, and a count this script does not know about is"
echo "  still a count that has to agree."
exit 0
