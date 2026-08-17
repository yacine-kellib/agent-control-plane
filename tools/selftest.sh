#!/usr/bin/env bash
# selftest.sh — tests the repository's own tooling.
#
# verify.sh proves claims about ACP. This proves claims about verify.sh and
# sign-release.sh. They are separate files so that a bug in the tooling cannot
# print a green ACP result.
set -uo pipefail
cd "$(dirname "$0")/.."   # tools/ -> repo root
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
# verify.sh colours its result lines, so a bare '^  OK' never matches. Strip
# the escapes before counting. Getting this wrong reported 0 of 14 lines while
# every suite was in fact passing.
strip_ansi() { sed $'s/\033\\[[0-9;]*m//g'; }

printf '\n\033[1m== sign-release.sh list ==\033[0m\n'

OUT=$(./tools/sign-release.sh list 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "list exits 0 (got $rc)"

has '^README\.md$'                     "covers README.md"
has '^LICENSE$'                        "covers LICENSE (no extension)"
has '^\.gitignore$'                    "covers .gitignore (signer input set derives from it)"
has '^reference/src/acp_executor\.py$' "covers reference/src"
has '^reference/suites/conformance\.py$' "covers reference/suites"
has '^tools/verify\.sh$'               "covers verify.sh (the tool that checks the claims)"
has '^dossier/06-RESIDUAL-RISK\.md$'   "covers the numbered dossier documents"
has '^spec/ACP-SPEC-001\.md$'          "covers the normative spec"

hasnot '^docs/'           "does NOT cover docs/ (working documents, not release artifacts)"
hasnot 'MANIFEST\.sha256' "does NOT cover the manifest or its signature"
hasnot '__pycache__'      "does NOT cover build outputs"

printf '\n\033[1m== signer halt-assertion ==\033[0m\n'

# A new file type must stop the release rather than be silently signed or
# silently skipped. Uses a git-tracked file because tracked-ness is axis 2 --
# `git add -N` is enough: an intent-to-add path does appear in `git ls-files`
# (verified), so the signer sees it without anything being committed.
# Trap covers INT/TERM as well as EXIT: an interrupted self-test must not
# leave the user's index dirty.
SCRATCH=reference/src/scratch.bin
cleanup_scratch() {
  git rm -q --cached "$SCRATCH" 2>/dev/null || true
  rm -f "$SCRATCH"
}
trap cleanup_scratch INT TERM EXIT
printf 'x' > "$SCRATCH"
git add -N "$SCRATCH"

OUT=$(./tools/sign-release.sh list 2>&1); rc=$?
[ $rc -eq 4 ]; chk $? "unrecognised extension halts the signer (exit 4, got $rc)"
has 'scratch\.bin' "names the offending file"

cleanup_scratch
trap - INT TERM EXIT

OUT=$(./tools/sign-release.sh list 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "clean tree lists successfully again (got $rc)"

printf '\n\033[1m== sign never destroys a signed manifest ==\033[0m\n'

# sign builds into temporaries and moves into place only after the signature
# exists. These assertions run the REAL sign path with keys that cannot work,
# and prove the existing release survives. Without this, a mistyped key path
# leaves a regenerated manifest that only the offline key holder can re-sign.
before=$(sha256sum MANIFEST.sha256 | awk '{print $1}')

OUT=$(./tools/sign-release.sh sign /nonexistent/key.pem 2>&1); rc=$?
[ $rc -eq 5 ]; chk $? "missing key file exits 5 before touching anything (got $rc)"

printf 'not a key' > /tmp/acp_bogus_key.pem
OUT=$(./tools/sign-release.sh sign /tmp/acp_bogus_key.pem 2>&1); rc=$?
[ $rc -ne 0 ]; chk $? "unparseable key fails (got $rc)"
rm -f /tmp/acp_bogus_key.pem

after=$(sha256sum MANIFEST.sha256 | awk '{print $1}')
[ "$before" = "$after" ]; chk $? "MANIFEST.sha256 is byte-identical after both failures"
[ ! -f MANIFEST.sha256.tmp ]; chk $? "no .tmp manifest left behind"
[ ! -f MANIFEST.sha256.sig.tmp ]; chk $? "no .tmp signature left behind"

printf '\n\033[1m== verify.sh --suites ==\033[0m\n'

OUT=$(./tools/verify.sh --suites 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "--suites exits 0 (got $rc)"

hasnot '1\. Integrity'      "--suites skips integrity (no release key needed)"
hasnot 'Manifest signature' "--suites skips signature"
has    'Formal proofs'      "--suites still runs the proof step"

# 15 = 1 prerequisites + 1 proofs + 14 suite lines. The prerequisites line at
# verify.sh:21 is easy to forget; an assertion of 14 fails against a healthy run.
n=$(echo "$OUT" | strip_ansi | grep -cE '^  (OK|FAIL)')
[ "$n" -eq 16 ]; chk $? "--suites reports 16 result lines: prereqs + proofs + 14 suites (got $n)"

nf=$(echo "$OUT" | strip_ansi | grep -cE '^  FAIL')
[ "$nf" -eq 0 ]; chk $? "--suites has no failing line (got $nf)"

OUT=$(./tools/verify.sh --bogus 2>&1); rc=$?
[ $rc -eq 2 ]; chk $? "unknown flag exits 2 with usage (got $rc)"

printf '\n\033[1m== a mutant that cannot import is ERROR, never KILL ==\033[0m\n'

# Since v1.3.14 acp_executor hard-imports acp_crypto, so every mutation suite
# must copy BOTH into its temp dir. The failure mode this guards against is the
# one that reads as green: if the copy were forgotten, every mutant would die at
# import, and a harness that scored an import failure as a kill would print
# "22/22 killed" while testing nothing at all. Same shape as the tmpfs trap in
# deploy/docker-compose.yml — infrastructure breakage wearing a passing badge.
#
# Asserted by breaking it on purpose: run mutate_executor.py against a stubbed
# acp_crypto that raises on import, and require the run to FAIL, to say ERROR,
# and never to say KILL.
#
# The fixture mirrors the real reference/{src,suites} layout, because
# mutate_executor.py resolves SRC_DIR relative to its OWN file. A flat temp dir
# would make the suite fail for the wrong reason — no acp_executor.py to read —
# and a test that passes for the wrong reason is the thing this file exists to
# prevent.
tmp=$(mktemp -d)
mkdir -p "$tmp/reference/src" "$tmp/reference/suites"
cp reference/src/acp_executor.py "$tmp/reference/src/"
cp reference/suites/mutate_executor.py reference/suites/conformance.py \
   "$tmp/reference/suites/"
printf 'raise ImportError("selftest: deliberately broken acp_crypto")\n' \
    > "$tmp/reference/src/acp_crypto.py"
OUT=$(cd "$tmp" && PYTHONPATH= python3 reference/suites/mutate_executor.py 2>&1); rc=$?
[ $rc -ne 0 ]; chk $? "a broken acp_crypto makes the mutation suite FAIL (rc=$rc)"
echo "$OUT" | strip_ansi | grep -q 'ERROR'
chk $? "it reports ERROR on the unrunnable mutants"
if echo "$OUT" | strip_ansi | grep -q 'KILL'; then false; else true; fi
chk $? "and never reports KILL for a mutant that never ran"
rm -rf "$tmp"

printf '\n\033[1m== published file count matches what the signer covers ==\033[0m\n'

# Found stale in v1.3.14: README said 111 files while the signer covered 115.
# Harmless on its own, and exactly the shape of the v1.3.13 fingerprint defect —
# a number in the prose that stopped matching a number the tooling prints, left
# for a human to notice. Humans do not notice three-digit numbers. So it is
# asserted, and asserted non-vacuously: deleting the sentence fails the check
# rather than quietly satisfying it.
covered=$(./tools/sign-release.sh list | wc -l | tr -d ' ')
claimed=$(grep -ohE 'covers [0-9]+ files' README.md RELEASE.md | grep -ohE '[0-9]+' | sort -u)
[ -n "$claimed" ]; chk $? "at least one tracked .md publishes a covered-file count"
[ "$claimed" = "$covered" ]
chk $? "every published file count equals the signer's ($claimed vs $covered)"

printf '\n\033[1m== published fingerprint matches the shipped key ==\033[0m\n'

# v1.3.13 shipped a README whose release-key fingerprint came from a superseded
# key, while RELEASE.md and release-key.pub were correct. A reader performing
# the out-of-band check the README itself asks for got a mismatch on an
# AUTHENTIC package -- the one failure mode an out-of-band anchor exists to
# prevent. The value is derivable from release-key.pub, so by this repository's
# own rule it must be checked by a command rather than by proofreading.
# The checker also fails when it finds NO fingerprint, so deleting the line
# cannot turn the assertion green.
OUT=$(python3 - <<'PY' 2>&1
from cryptography.hazmat.primitives import serialization as ser
import hashlib, re, subprocess, sys

raw = ser.load_pem_public_key(open("release-key.pub", "rb").read()).public_bytes(
    ser.Encoding.Raw, ser.PublicFormat.Raw)
expect = "SHA256:" + hashlib.sha256(raw).hexdigest()[:32]

files = subprocess.run(["git", "ls-files", "*.md"],
                       capture_output=True, text=True).stdout.split()
seen, bad = 0, []
for f in files:
    for found in re.findall(r"SHA256:[0-9a-f]{32}",
                            open(f, encoding="utf-8").read()):
        seen += 1
        if found != expect:
            bad.append(f"{f} publishes {found}")

print(f"expected {expect}, checked {seen} fingerprint(s)")
for b in bad:
    print(f"  {b}")
sys.exit(1 if bad or seen == 0 else 0)
PY
); rc=$?
[ $rc -eq 0 ]; chk $? "every SHA256: fingerprint in tracked .md matches release-key.pub (got $rc)"
has 'checked [1-9][0-9]* fingerprint' "the fingerprint check is non-vacuous (found at least one)"

printf '\n\033[1m== Result ==\033[0m\n'
if [ $FAIL -eq 0 ]; then echo "  tooling self-test passed."
else echo "  tooling self-test FAILED."; fi
exit $FAIL
