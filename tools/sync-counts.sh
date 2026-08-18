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
    after=$(sed -E "s|$pattern|$replacement|g" "$f")
    if [ "$after" != "$(cat "$f")" ]; then
      moved=$((moved + 1))
      DRIFT=1
      if [ $CHECK -eq 1 ]; then
        printf '  \033[33mDRIFT\033[0m %-28s %s would change\n' "$label" "$f"
      else
        # printf '%s\n' restores the trailing newline that $( ) strips.
        printf '%s\n' "$after" > "$f"
        printf '  \033[32mSYNC\033[0m  %-28s %s -> %s\n' "$label" "$f" "$want"
      fi
    fi
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
