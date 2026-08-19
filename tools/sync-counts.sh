#!/usr/bin/env bash
# sync-counts.sh — re-derive every published count from the tooling and write it
# back into the prose that publishes it.
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
# - Anything under spec/ or dossier/. Those are the argument, not the readme.
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

# Rewrite one sed pattern across the named files, reporting whether it moved.
#
# Takes the DERIVED value and a sed expression carrying a \1-style capture, so a
# pattern that matches nothing is visible as "0 occurrences" rather than
# silently succeeding. A substitution that matches nothing is the shape of a
# check that cannot fail.
sync() {
  local label="$1" want="$2" pattern="$3" replacement="$4"; shift 4
  local files=("$@")
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
  elif [ "$moved" -eq 0 ]; then
    printf '  \033[32mOK\033[0m    %-28s %s (%d occurrence(s))\n' "$label" "$want" "$hits"
  fi
}

printf '\n\033[1m== deriving ==\033[0m\n'

COVERED=$(./tools/sign-release.sh list | wc -l | tr -d ' ')
printf '  covered files      %s   (sign-release.sh list)\n' "$COVERED"

RUST=$(cargo test --workspace 2>&1 \
  | grep -E '^test result:' \
  | awk -F'[ ;]' '{p+=$4} END {print p+0}')
printf '  rust tests         %s   (cargo test --workspace)\n' "$RUST"

BUNDLE=$(cd reference/suites && PYTHONPATH=../src python3 bundle_suite.py 2>/dev/null \
  | grep -oE 'RESULT: [0-9]+/[0-9]+' | grep -oE '[0-9]+/[0-9]+')
printf '  suite 11           %s (bundle_suite.py)\n' "$BUNDLE"

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
ASSERTIONS=$(./tools/selftest.sh 2>/dev/null \
  | grep -oE 'tooling self-test (passed|FAILED) \([0-9]+ assertions\)' \
  | grep -oE '[0-9]+')
printf '  selftest assertions %s  (selftest.sh)\n' "${ASSERTIONS:-?}"

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

sync "rust tests" "$RUST" \
  '# Rust: [0-9]+ tests' "# Rust: $RUST tests" \
  README.md CLAUDE.md

if [ -n "$ASSERTIONS" ]; then
  sync "selftest assertions" "$ASSERTIONS" \
    'tests the tooling itself \([0-9]+ assertions\)' \
    "tests the tooling itself ($ASSERTIONS assertions)" \
    README.md CLAUDE.md
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
    '\(consolidated registry\) — RESULT: [0-9]+/[0-9]+' \
    "(consolidated registry) — RESULT: $REGISTRY" \
    README.md
  sync "registry (dossier)" "$REGISTRY" \
    'consolidated registry and composition \([0-9]+/[0-9]+, 4/4\)' \
    "consolidated registry and composition ($REGISTRY, 4/4)" \
    dossier/05-TEST-EVIDENCE.md
fi

printf '\n\033[1m== Result ==\033[0m\n'
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
