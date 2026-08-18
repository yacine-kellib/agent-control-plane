#!/usr/bin/env bash
# selftest.sh — tests the repository's own tooling.
#
# verify.sh proves claims about ACP. This proves claims about verify.sh and
# sign-release.sh. They are separate files so that a bug in the tooling cannot
# print a green ACP result.
set -uo pipefail
cd "$(dirname "$0")/.."   # tools/ -> repo root
FAIL=0
TOTAL=0
OUT=""
ok()  { printf '  \033[32mOK\033[0m   %s\n' "$1"; TOTAL=$((TOTAL + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=1; TOTAL=$((TOTAL + 1)); }
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

# 17 = 1 prerequisites + 1 proofs + 14 suite lines + 1 harness. The prereq line at
# verify.sh:21 is easy to forget; an assertion of 14 fails against a healthy run.
n=$(echo "$OUT" | strip_ansi | grep -cE '^  (OK|FAIL)')
[ "$n" -eq 17 ]; chk $? "--suites reports 17 result lines: prereqs + proofs + 14 suites + harness (got $n)"

nf=$(echo "$OUT" | strip_ansi | grep -cE '^  FAIL')
[ "$nf" -eq 0 ]; chk $? "--suites has no failing line (got $nf)"

OUT=$(./tools/verify.sh --bogus 2>&1); rc=$?
[ $rc -eq 2 ]; chk $? "unknown flag exits 2 with usage (got $rc)"

printf '\n\033[1m== a mutant that cannot import is ERROR, never KILL ==\033[0m\n'

# Since v1.3.14 acp_executor hard-imports acp_crypto, so every mutation suite
# must copy BOTH into its temp dir. The failure mode this guards against is the
# one that reads as green: if the copy were forgotten, every mutant would die at
# import, and a harness that scored an import failure as a kill would print
# "25/25 killed" while testing nothing at all. Same shape as the tmpfs trap in
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

printf '\n\033[1m== published mutant counts match the suites ==\033[0m\n'

# The same defect as the file count above, found the same way and one release
# later: README's front page said "30 mutation controls" in one paragraph and
# "34 of them: 24 executor, 6 acknowledgement, 4 audit" four lines below, while
# the suites held 25 + 6 + 4 = 35. Two published numbers that disagreed with the
# code AND with each other, on the front page, under a heading claiming the
# mutation results are the ones worth reading.
#
# Counted by parsing the MUTANTS lists rather than by running them: the suites
# fork a subprocess per mutant and take minutes, and this assertion is about
# what is published, not about whether the mutants still die. The gate already
# asserts the latter.
read -r m_ex m_ack m_aud <<EOF
$(python3 - <<'PY'
import ast
out = []
for f in ("reference/suites/mutate_executor.py",
          "reference/suites/ack_suite.py",
          "reference/suites/audit_suite.py"):
    n = 0
    for node in ast.walk(ast.parse(open(f).read())):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
            if any(isinstance(t, ast.Name) and t.id == "MUTANTS" for t in node.targets):
                n = len(node.value.elts)
    out.append(str(n))
print(" ".join(out))
PY
)
EOF
m_total=$(( m_ex + m_ack + m_aud ))
[ "$m_total" -gt 0 ]; chk $? "the MUTANTS lists parse (${m_ex}+${m_ack}+${m_aud}=${m_total})"

# The split, published as one sentence, so a partial edit cannot satisfy it.
split=$(grep -ohE '[0-9]+ of them: [0-9]+ executor, [0-9]+ acknowledgement, [0-9]+ audit' README.md)
[ -n "$split" ]; chk $? "README publishes the mutant split"
set -- $(printf '%s' "$split" | grep -oE '[0-9]+')
[ "$1" = "$m_total" ] && [ "$2" = "$m_ex" ] && [ "$3" = "$m_ack" ] && [ "$4" = "$m_aud" ]
chk $? "the published split equals the suites ($1/$2/$3/$4 vs $m_total/$m_ex/$m_ack/$m_aud)"

# The other paragraph, which drifted independently of the one above. Asserting
# only one of them is how they came to disagree.
controls=$(grep -ohE '[0-9]+ mutation controls' README.md | grep -oE '[0-9]+')
[ -n "$controls" ]; chk $? "README publishes a mutation-control total"
[ "$controls" = "$m_total" ]
chk $? "every published mutant total agrees ($controls vs $m_total)"

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

printf '\n\033[1m== published key fingerprints match what the code derives ==\033[0m\n'

# spec/vectors/CLASSIFICATION.md publishes a WORKED EXAMPLE -- HybridKey(b"k1")
# derives fingerprint sha256:38a223bd... -- as the anchor for the claim that a
# vector may name a seed instead of a key. The Rust test
# `the_fingerprint_is_the_same_on_both_sides` recomputes that value, but it
# compares against the committed FIXTURE, not against the prose, and its comment
# claimed the two "cannot drift apart silently". They could: corrupting the
# published hex left cargo test and this script green, which is how this block
# came to exist. The number is derivable from the code, so by this repository's
# own rule it is checked by a command rather than by proofreading.
#
# The block above checks SHA256: (the release key, uppercase, 32 hex). This one
# checks sha256: (a HybridKey identity, lowercase, 64 hex). Neither pattern
# matches the other's literals, so the older assertion reporting "got 0" was not
# covering this file at all.
OUT=$(python3 - <<'PY' 2>&1
import pathlib, re, subprocess, sys
sys.path.insert(0, "reference/src")
from acp_crypto import HybridKey

# Targets the published construct exactly, so an unrelated sha256: literal (a
# tree hash, a digest in an example) is not swept in and does not have to be
# excluded by a deny-list that would rot.
CLAIM = re.compile(
    r'HybridKey\(b"([^"]+)"\)\s*\.public\(\)\s*\.fingerprint\s*=*\s*"?(sha256:[0-9a-f]{64})')

files = subprocess.run(["git", "ls-files", "*.md"],
                       capture_output=True, text=True).stdout.split()
seen, bad = 0, []
for f in files:
    for seed, published in CLAIM.findall(pathlib.Path(f).read_text(encoding="utf-8")):
        seen += 1
        actual = HybridKey(seed.encode()).public().fingerprint()
        if published != actual:
            bad.append(f"{f} publishes {published} for seed {seed!r}, code derives {actual}")

print(f"checked {seen} published derivation(s)")
for b in bad:
    print(f"  {b}")
sys.exit(1 if bad or seen == 0 else 0)
PY
); rc=$?
[ $rc -eq 0 ]; chk $? "every published HybridKey fingerprint matches the derivation (got $rc)"
has 'checked [1-9][0-9]* published derivation' "the derivation check is non-vacuous (found at least one)"

printf '\n\033[1m== Python verifies what the Rust signer produced ==\033[0m\n'

# The reverse of tests/python_interop.rs, and the half that was missing until
# custody.rs existed: that test proves the Rust VERIFIER accepts a correct
# signature, which says nothing about whether the Rust SIGNER makes one.
#
# It runs here rather than in cargo because it needs both toolchains. It runs
# SOMEWHERE because sim/bundle.py was load-bearing with no gate line for
# several releases and silently dropped three fields from a hash (ACP-35); an
# assertion nothing executes is that shape exactly.
if ! command -v cargo >/dev/null 2>&1; then
  printf '  \033[33mSKIP\033[0m cargo is not installed; Rust-signs/Python-verifies not checked\n'
else
  OUT=$(python3 tools/check-rust-signatures.py 2>&1); rc=$?
  [ $rc -eq 0 ]; chk $? "Python verifies every Rust signature (got $rc)"
  has 'verified [1-9][0-9]* Rust-signed identities' "the cross-language check is non-vacuous"
fi

printf '\n\033[1m== published Rust test count matches the workspace ==\033[0m\n'

# README and CLAUDE.md both published "Rust: 7 tests" while the workspace ran
# 47. Nobody had touched the number since the crates were scaffolded, and no
# command checked it -- the same shape as the mutation-count drift (ACP-42) and
# the release-key fingerprint before it. Every count this repository publishes
# is load-bearing evidence, so it is asserted rather than proofread.
#
# Skipped, with a notice, when cargo is absent -- the same treatment Dafny gets
# in verify.sh. A skipped check announces itself; a silently-passing one does
# not, and this file exists to catch exactly that difference.
if ! command -v cargo >/dev/null 2>&1; then
  printf '  \033[33mSKIP\033[0m cargo is not installed; Rust test count not checked\n'
else
  OUT=$(python3 - <<'PY' 2>&1
import re, subprocess, sys

run = subprocess.run(["cargo", "test", "--workspace"],
                     capture_output=True, text=True)
actual = sum(int(n) for n in re.findall(r"^test result: ok\. (\d+) passed",
                                        run.stdout, re.M))

files = subprocess.run(["git", "ls-files", "*.md"],
                       capture_output=True, text=True).stdout.split()
seen, bad = 0, []
for f in files:
    for published in re.findall(r"cargo test --workspace\s*#\s*Rust: (\d+) tests",
                                open(f, encoding="utf-8").read()):
        seen += 1
        if int(published) != actual:
            bad.append(f"{f} publishes {published}, workspace runs {actual}")

print(f"workspace runs {actual}, checked {seen} published count(s)")
for b in bad:
    print(f"  {b}")
sys.exit(1 if bad or seen == 0 or actual == 0 else 0)
PY
  ); rc=$?
  [ $rc -eq 0 ]; chk $? "every published Rust test count equals the workspace (got $rc)"
  has 'checked [1-9][0-9]* published count' "the Rust count check is non-vacuous (found at least one)"
fi

printf '\n\033[1m== published assertion count matches this run ==\033[0m\n'

# README.md and CLAUDE.md both publish how many assertions this script makes.
# The number had already drifted once -- it said 34 while the run made 45 --
# which is the same defect as the mutation counts and the Rust test count, in
# the file whose entire job is catching that defect.
#
# THIS ASSERTION COUNTS ITSELF. It is the (TOTAL+1)-th, so the published number
# is TOTAL+1 as measured here, and a reader counting OK lines gets the same
# figure. An off-by-one would be a wrong published number arriving by exactly
# the mechanism this block exists to prevent, so it is spelled out rather than
# left to be noticed.
#
# Skipped branches lower the total honestly: a run without cargo makes fewer
# assertions and must publish fewer, which is why this compares against the
# count of what actually ran rather than a constant in the script.
EXPECT=$((TOTAL + 1))
PUBLISHED=$(git ls-files '*.md' \
  | xargs grep -ho 'tests the tooling itself ([0-9]\{1,\} assertions)' 2>/dev/null \
  | grep -o '[0-9]\{1,\}' | sort -u)
if [ -z "$PUBLISHED" ]; then
  bad "no tracked .md publishes an assertion count (the check would be vacuous)"
elif [ "$PUBLISHED" = "$EXPECT" ]; then
  ok "every published assertion count equals this run ($PUBLISHED vs $EXPECT)"
else
  bad "published assertion count is $(echo "$PUBLISHED" | tr '\n' ' ')but this run made $EXPECT"
fi

printf '\n\033[1m== Result ==\033[0m\n'
if [ $FAIL -eq 0 ]; then echo "  tooling self-test passed ($TOTAL assertions)."
else echo "  tooling self-test FAILED ($TOTAL assertions)."; fi
exit $FAIL
