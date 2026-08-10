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

hasnot '^docs/'           "does NOT cover docs/ (working documents, not release artifacts)"
hasnot 'MANIFEST\.sha256' "does NOT cover the manifest or its signature"
hasnot '__pycache__'      "does NOT cover build outputs"

printf '\n\033[1m== Result ==\033[0m\n'
if [ $FAIL -eq 0 ]; then echo "  tooling self-test passed."
else echo "  tooling self-test FAILED."; fi
exit $FAIL
