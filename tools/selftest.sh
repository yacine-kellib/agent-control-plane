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

# ACP-16. A passphrase-encrypted key must FAIL, not block, when there is no
# terminal to read the passphrase from. This is the assertion that keeps the
# gate runnable: `sign` prompts on a TTY, and a prompt reached from selftest,
# CI or cron would hang forever. A gate that hangs is worse than one that
# fails, because it reports nothing at all. Stdin is a pipe here, so isatty()
# is false exactly as it would be under automation.
ENCKEY=$(mktemp)
python3 - "$ENCKEY" <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
import sys
k = Ed25519PrivateKey.generate()
open(sys.argv[1], "wb").write(k.private_bytes(
    ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
    ser.BestAvailableEncryption(b"selftest-throwaway-passphrase")))
PY
OUT=$(printf '' | ./tools/sign-release.sh sign "$ENCKEY" 2>&1); rc=$?
[ $rc -ne 0 ]; chk $? "an encrypted key with no terminal fails instead of hanging (got $rc)"
printf '%s' "$OUT" | grep -q 'no terminal'
chk $? "and says why, rather than failing as an unparseable key"
rm -f "$ENCKEY"

after=$(sha256sum MANIFEST.sha256 | awk '{print $1}')
[ "$before" = "$after" ]; chk $? "MANIFEST.sha256 is byte-identical after both failures"
[ ! -f MANIFEST.sha256.tmp ]; chk $? "no .tmp manifest left behind"
[ ! -f MANIFEST.sha256.sig.tmp ]; chk $? "no .tmp signature left behind"

printf '\n\033[1m== keygen never writes to $HOME, and never clobbers a key ==\033[0m\n'

# ACP-16. `keygen` hardcoded ~/acp-release.key and then printed "move to offline
# media" -- the tool created the exposure the dossier's two-gate argument denies,
# and nothing here tested it, so the footgun shipped untested for the life of the
# script. Two properties, both destructive-by-omission:
#
#   (1) the path is REQUIRED. A default of $HOME puts the release key where every
#       npm install, editor extension and agent session can read it.
#   (2) it REFUSES to overwrite. `sign` already builds into .tmp so a mistyped
#       path cannot destroy the last valid manifest; the key had no such guard,
#       and the asymmetry matters -- a clobbered manifest can be re-signed, a
#       destroyed key makes every signature it ever produced unverifiable.
#
# The decoy is never a real key and the real key is never an argument here: a
# test that can reach the signing key is the defect it is testing for.
OUT=$(./tools/sign-release.sh keygen 2>&1); rc=$?
[ $rc -ne 0 ]; chk $? "keygen with no path fails instead of defaulting to \$HOME (rc=$rc)"

DECOY=$(mktemp); printf 'DECOY-not-a-key\n' > "$DECOY"
BEFORE=$(shasum -a 256 "$DECOY" | awk '{print $1}')
OUT=$(./tools/sign-release.sh keygen "$DECOY" 2>&1); rc=$?
# Exit 3 specifically, not merely non-zero: 1 is "usage" and a check accepting
# any failure would pass for a keygen that refused for the wrong reason.
[ $rc -eq 3 ]; chk $? "keygen refuses to overwrite an existing key, exit 3 (got $rc)"
[ "$BEFORE" = "$(shasum -a 256 "$DECOY" | awk '{print $1}')" ]
chk $? "and the refused target is byte-identical — nothing was written"
rm -f "$DECOY"

printf '\n\033[1m== verify.sh --suites ==\033[0m\n'

OUT=$(./tools/verify.sh --suites 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "--suites exits 0 (got $rc)"

hasnot '1\. Integrity'      "--suites skips integrity (no release key needed)"
hasnot 'Manifest signature' "--suites skips signature"
has    'Formal proofs'      "--suites still runs the proof step"

# 18 = 1 prerequisites + 1 proofs + 15 suite lines + 1 harness. The prereq line at
# verify.sh:21 is easy to forget; an assertion of 15 fails against a healthy run.
n=$(echo "$OUT" | strip_ansi | grep -cE '^  (OK|FAIL)')
[ "$n" -eq 18 ]; chk $? "--suites reports 18 result lines: prereqs + proofs + 15 suites + harness (got $n)"

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

printf '\n\033[1m== Python and Rust agree on a bundle ==\033[0m\n'

# ACP-38 and ACP-39's acceptance criteria. `verify.sh --suites` runs each
# implementation against itself; this runs them against EACH OTHER, on the same
# directory, comparing the tree hash, the verdict, and WHICH refusal fired.
# Two implementations that both refuse for different reasons agree on nothing
# useful -- and checks running in the wrong order is precisely how that happens.
#
# Needs both toolchains, which is why it is here rather than in the gate.
if ! command -v cargo >/dev/null 2>&1; then
  printf '  \033[33mSKIP\033[0m cargo is not installed; bundle differential not checked\n'
else
  cargo build -q -p acp-bundle-cli 2>/dev/null
  OUT=$(python3 tools/check-bundle-differential.py 2>&1); rc=$?
  [ $rc -eq 0 ]; chk $? "python and rust agree on every bundle case (got $rc)"
  has 'agree on [1-9][0-9]* bundles' "the bundle differential is non-vacuous"
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

printf '\n\033[1m== custody T2: the tier tests run in some build (ACP-61) ==\033[0m\n'

# `cargo test --workspace` above builds with default features, and T2 lives
# behind `kms`. So the tier that ACP-61 added is compiled out of the only Rust
# command any gate runs, and its tests would pass forever by not existing --
# which is the same defect as an unrun mutant reporting SURVIVE, and the reason
# the mutation suites strip PYTHONPATH from their subprocess.
#
# Two assertions, and the second is the load-bearing one. Passing is cheap; a
# feature build with the tests deleted also passes. So the count under `kms`
# must EXCEED the count without it, which is false the moment the T2 tests stop
# existing or stop being gated on the feature that names them.
if ! command -v cargo >/dev/null 2>&1; then
  printf '  \033[33mSKIP\033[0m cargo is not installed; custody T2 not checked\n'
else
  OUT=$(python3 - <<'PY' 2>&1
import re, subprocess, sys

def count(args):
    r = subprocess.run(["cargo", "test", "-p", "acp-crypto", *args],
                       capture_output=True, text=True)
    n = sum(int(x) for x in re.findall(r"^test result: ok\. (\d+) passed",
                                       r.stdout, re.M))
    return r.returncode, n, r.stdout

rc, with_kms, out = count(["--features", "kms"])
_,  without,  _   = count([])

print(f"kms build runs {with_kms}, default runs {without}")
if rc != 0:
    print("  the --features kms build did not pass")
if with_kms <= without:
    print("  the kms feature added no tests -- T2 is unchecked in every build")
if "kms::" not in out:
    print("  no test in the kms module ran")
sys.exit(1 if rc != 0 or with_kms <= without or "kms::" not in out else 0)
PY
  ); rc=$?
  [ $rc -eq 0 ]; chk $? "custody T2 tests pass under --features kms (got $rc)"
  has 'kms build runs [1-9][0-9]*' "the T2 check is non-vacuous (tests actually ran)"
fi

printf '\n\033[1m== acp-bundle CLI: the release signer discipline, applied to bundles ==\033[0m\n'

# Mirrors the sign-release.sh assertions above, on the bundle signer. The rules
# are the same rules and were paid for once already: list and sign must agree,
# an unrecognised file type must HALT, and a failed signing must leave the
# previous SIGNATURE byte-identical rather than truncated or missing.
if ! command -v cargo >/dev/null 2>&1; then
  printf '  \033[33mSKIP\033[0m cargo is not installed; bundle signer not checked\n'
else
  cargo build -q -p acp-bundle-cli 2>/dev/null
  BIN=./target/debug/acp-bundle
  BDIR=$(mktemp -d)
  KEYS=$(mktemp -d)
  mkdir -p "$BDIR/attesters"
  cat > "$BDIR/manifest.json" <<'JSON'
{"schema_version":"1","bundle_epoch":7,"created_at":"2026-01-01T00:00:00Z",
 "author":{"id":"ana","display_name":"Ana"},
 "reviewer":{"id":"bo","display_name":"Bo"},
 "expires_at":"2027-01-01T00:00:00Z","min_suite":"hybrid-ed25519-mldsa65",
 "custody":{"tier":"T1","classical":"x","pq":"y"}}
JSON
  echo '{"payments":"T3"}' > "$BDIR/floors.json"
  echo '{"schema_version":"1","quorum_k":2,"attesters":{"ana":{"classical":"ka","pq":"pa"},"bo":{"classical":"kb","pq":"pb"}}}' \
    > "$BDIR/attesters/registry.json"

  # Keys come from the Python reference's derivation, so the signer is exercised
  # against the same key material every other cross-language check uses.
  python3 - "$KEYS" <<'PY' >/dev/null 2>&1
import sys, json
sys.path.insert(0, "reference/src")
from acp_crypto import HybridKey
from cryptography.hazmat.primitives import serialization as ser
out = sys.argv[1]
k = HybridKey(b"bundle-signing-key")
ed_sk = k.ed_sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
ed_pk = k.ed_sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
json.dump({"ed25519_sk_hex": ed_sk.hex(), "mldsa65_sk_hex": k.ml_sk.hex()}, open(f"{out}/key.json", "w"))
json.dump({"ed25519_pk_hex": ed_pk.hex(), "mldsa65_pk_hex": k.ml_pk.hex()}, open(f"{out}/pub.json", "w"))
PY

  OUT=$("$BIN" list "$BDIR" 2>&1); rc=$?
  [ $rc -eq 0 ]; chk $? "list exits 0 with no key (got $rc)"
  has 'attesters/registry\.json' "list covers the attester registry (PB-KEY)"
  LIST_HASH=$(echo "$OUT" | grep -o 'sha256:[0-9a-f]*')

  OUT=$("$BIN" sign "$BDIR" --key "$KEYS/key.json" 2>&1); rc=$?
  [ $rc -eq 0 ]; chk $? "sign exits 0 (got $rc)"
  SIGN_HASH=$(echo "$OUT" | grep -o 'sha256:[0-9a-f]*')
  [ -n "$LIST_HASH" ] && [ "$LIST_HASH" = "$SIGN_HASH" ]
  chk $? "list and sign agree on the tree hash"

  OUT=$("$BIN" verify "$BDIR" --pubkey "$KEYS/pub.json" --now 2026-08-18T00:00:00Z 2>&1); rc=$?
  [ $rc -eq 0 ]; chk $? "a freshly signed bundle verifies (got $rc)"
  has '^OK Normal$' "and serves at full strength inside its validity window"

  # A FAILED SIGNING MUST NOT DESTROY THE LAST VALID SIGNATURE -- the defect the
  # release signer hit once. Build into .tmp, move only after the bytes exist.
  BEFORE=$(shasum "$BDIR/SIGNATURE" | cut -d' ' -f1)
  echo '{"ed25519_sk_hex":"00","mldsa65_sk_hex":"00"}' > "$KEYS/bad.json"
  OUT=$("$BIN" sign "$BDIR" --key "$KEYS/bad.json" 2>&1); rc=$?
  [ $rc -ne 0 ]; chk $? "an unusable key makes sign fail (got $rc)"

  # THE PREVIOUS ASSERTION ALONE IS VACUOUS, and was, until a mutant proved it:
  # a bad key is rejected BEFORE anything is written, so a signer writing
  # straight to SIGNATURE passes it too. Removing the .tmp-and-move left the
  # whole block green, which is the "green run that means nothing" this file
  # exists to prevent.
  #
  # The failure has to land AFTER the signature is produced, at the write. A
  # read-only directory does that: creating SIGNATURE.tmp is refused, while an
  # existing SIGNATURE stays writable through its own mode -- so a direct writer
  # truncates the last valid signature and a .tmp writer cannot touch it. That
  # asymmetry is the whole control, and it is what this now measures.
  chmod 500 "$BDIR"
  OUT=$("$BIN" sign "$BDIR" --key "$KEYS/key.json" 2>&1); rc=$?
  chmod 700 "$BDIR"
  [ $rc -ne 0 ]; chk $? "sign fails when it cannot write into the bundle (got $rc)"
  AFTER=$(shasum "$BDIR/SIGNATURE" | cut -d' ' -f1)
  [ "$BEFORE" = "$AFTER" ]
  chk $? "SIGNATURE is byte-identical after a write that failed mid-signing"
  [ ! -e "$BDIR/SIGNATURE.tmp" ]; chk $? "no .tmp file is left behind"

  # HALT, not skip. A silently skipped file is unsigned content inside a signed
  # bundle, which is the thing the signature exists to deny.
  echo '#!/bin/sh' > "$BDIR/helper.sh"
  OUT=$("$BIN" list "$BDIR" 2>&1); rc=$?
  [ $rc -ne 0 ]; chk $? "an unrecognised file type makes list halt (got $rc)"
  has 'unrecognised file type' "and says which file, rather than skipping it"
  OUT=$("$BIN" sign "$BDIR" --key "$KEYS/key.json" 2>&1); rc=$?
  [ $rc -ne 0 ]; chk $? "sign halts on it too, so list and sign cannot disagree"
  rm -f "$BDIR/helper.sh"

  # PB-2 at signing time, where the author can still fix it.
  python3 - "$BDIR" <<'PY' >/dev/null 2>&1
import json, sys
p = f"{sys.argv[1]}/manifest.json"
m = json.load(open(p))
m["reviewer"] = m["author"]
json.dump(m, open(p, "w"))
PY
  OUT=$("$BIN" sign "$BDIR" --key "$KEYS/key.json" 2>&1); rc=$?
  [ $rc -ne 0 ]; chk $? "sign refuses when author == reviewer (PB-2) (got $rc)"
  has 'PB-2' "and names the clause"

  rm -rf "$BDIR" "$KEYS"
fi

printf '\n\033[1m== codegen: the committed types still match the schemas ==\033[0m\n'

# `spec/` is the only normative source, and CLAUDE.md has said since the
# polyglot restructure that the Rust and TypeScript wire types are GENERATED
# from `spec/schemas/bundle/`, never hand-written -- a hand-written type is a
# second definition of an object the spec already defines, and two definitions
# of one object is the encoding-split defect at the source level. That sentence
# is only true while the COMMITTED output still matches the schemas, so it is
# asserted rather than believed.
#
# It lives in selftest.sh and not in verify.sh because "the generator's output
# is current" is a claim about the tooling, not about ACP, and because the gate
# is asserted at exactly 18 result lines four blocks above.
OUT=$(./tools/codegen.sh --check 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "codegen --check exits 0 on the committed output (got $rc)"
has 'generated types are current' "and reports the generated types as current"

# THE ASSERTION ABOVE IS VACUOUS ON ITS OWN: a --check that compared nothing, or
# compared the regenerated text against itself, prints the same green line. The
# precedent is one block up in this very file -- "an unusable key makes sign
# fail" passed for a signer that wrote straight to SIGNATURE, because a bad key
# was rejected BEFORE any write happened, so the .tmp-and-move discipline it
# claimed to cover was never exercised. So drift is MANUFACTURED here, on every
# run, and the red is measured rather than assumed.
#
# The edit is a single trailing space, which is the smallest edit that proves
# the comparison is byte-for-byte rather than structural -- a generator diffed
# on parsed shape would not see it. Confirmed by running it before relying on
# it: exit 1, naming crates/acp-core/src/generated.rs.
#
# Trap covers INT/TERM as well as EXIT, like the SCRATCH block above. A
# generated file left edited on disk by an interrupted self-test would put a
# hand-modified generated.rs into the release path, which is a far worse outcome
# than having no test here at all.
GENFILE=crates/acp-core/src/generated.rs
GENBAK=$(mktemp)
cp "$GENFILE" "$GENBAK"
# Idempotent, like cleanup_scratch above: a trapped INT restores and drops the
# backup, and the EXIT trap then fires on the way out with nothing left to do.
restore_generated() { [ -s "$GENBAK" ] && cp "$GENBAK" "$GENFILE"; }
trap 'restore_generated; rm -f "$GENBAK"' INT TERM EXIT
printf ' ' >> "$GENFILE"

OUT=$(./tools/codegen.sh --check 2>&1); rc=$?
[ $rc -eq 1 ]; chk $? "one trailing space in a generated file is DRIFT, exit 1 (got $rc)"
has 'crates/acp-core/src/generated\.rs has drifted' "and names the file that drifted"

restore_generated
trap - INT TERM EXIT
cmp -s "$GENBAK" "$GENFILE"
chk $? "the generated file is byte-identical again after the restore"
rm -f "$GENBAK"

printf '\n\033[1m== codegen halts rather than guessing a fail-safe default ==\033[0m\n'

# `x-acp-absent` carries the fail-safe rule AS DATA rather than as prose:
# floors absent => T3 (RK-1), reversibility absent => IRREVERSIBLE (RV-1),
# notice_targets absent => refuse (DR-13), risk_functions absent => refuse at
# 8.4-3. A generator meeting a lookup table with no such rule has to return
# SOMETHING, and every off-the-shelf generator returns `Option<T>`, and an
# `Option` gets an `unwrap_or` -- which is precisely how "absent" becomes
# "permissive", the defect class this specification exists to prevent. So the
# generator HALTS, the same posture sign-release.sh takes on an unrecognised
# file type. The halt IS the control, and this is what proves it exists.
#
# EXIT 2 EXACTLY, not merely non-zero. Drift (1) and halt (2) are deliberately
# distinct because they want opposite responses: drift means "regenerate", halt
# means "a schema is under-specified and you must state the intent". A test that
# accepted any non-zero code would report the control as present when the
# schemas had merely drifted.
#
# On a COPY, in a mktemp -d. spec/schemas/bundle/ is signed normative content,
# and a self-test that edits a normative source to make its point is the same
# move as regenerating MANIFEST.sha256 to turn an integrity line green.
sdir=$(mktemp -d)
cp spec/schemas/bundle/*.json "$sdir/"

# The control first. Copying the schemas elsewhere could itself halt the
# generator -- a $ref that only resolves in its own directory would do it -- and
# then the exit 2 below would fire for a reason that has nothing to do with the
# missing rule. A test that passes for the wrong reason is what this file exists
# to prevent, so the untouched copy is required to generate cleanly first.
OUT=$(./tools/codegen.sh --schemas "$sdir" --check 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "an untouched copy of the schemas generates cleanly (got $rc)"

python3 - "$sdir" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]) / "floors.schema.json"
s = json.loads(p.read_text())
del s["properties"]["floors"]["x-acp-absent"]   # RK-1's "absent => T3", removed
p.write_text(json.dumps(s, indent=2))
PY

OUT=$(./tools/codegen.sh --schemas "$sdir" --check 2>&1); rc=$?
[ $rc -eq 2 ]; chk $? "a lookup table with no x-acp-absent rule HALTS, exit 2 (got $rc)"
has 'x-acp-absent' "and names the missing rule instead of guessing a default"

[ -n "$sdir" ] && rm -rf "$sdir"

printf '\n\033[1m== Rust decision-path mutants (ACP-45) ==\033[0m\n'

# The parser is OUTSIDE the proof TCB. Annex B quantifies over parsed `Expr`
# values and the Z1 differential generated ASTs, so the whole assurance
# apparatus sat downstream of the ambiguity and could not see it (RES-10: every
# proof has a boundary, and the defect will be found immediately outside it).
# The §8.4 fold below it is where a grade can come out lower than the policy
# author wrote, which is the only direction that matters.
#
# `cargo test --workspace` above already runs both suites. That is not the
# claim: a suite that cannot fail passes forever. This breaks each named check
# in turn and requires the suite to go RED. It has already earned it twice --
# the first Z1 witness test survived the precedence mutant, and the
# out-of-range integer literal silently became a field reference.
if ! command -v cargo >/dev/null 2>&1; then
  printf '  \033[33mSKIP\033[0m cargo is not installed; Rust mutants not checked\n'
else
  OUT=$(./tools/mutate-rust.sh 2>&1); rc=$?
  [ $rc -eq 0 ]; chk $? "every Rust decision-path mutant is killed (rc=$rc)"
  # An unrun mutant is not a caught one. The script reports ERROR rather than
  # KILL when a mutant fails to build, and this asserts the run actually
  # reached all of them -- a script that silently ran zero would otherwise
  # print a green nothing.
  # NOTE: this number is HAND-MAINTAINED. `sync-counts.sh` derives every other
  # published count in this repository but knows nothing about mutate-rust.sh,
  # so adding a mutant means editing this line. That is tolerable only because
  # the assertion is what forces the edit -- it went red on slice 6 the moment
  # the count moved 20 -> 26, which is the behaviour ACP-42/ACP-43 wanted and
  # a hand-maintained number usually fails to give.
  N=$(printf '%s' "$OUT" | grep -c 'KILL')
  [ "$N" -eq 26 ]; chk $? "and all twenty-six mutants actually ran (counted $N)"
fi

printf '\n\033[1m== EL-1 differential: Python vs Rust on generated source ==\033[0m\n'

# diff_prose.py found Z1 with two evaluators written from the PROSE. That found
# the ambiguity; it says nothing about whether the two implementations this
# repository ships agree today. §1246 requires parser conformance to be run
# against the deployment's own parser -- and there are two deployments here, so
# the same method pointed at both is the check that the fix actually holds.
#
# The --selfcheck run comes FIRST and is not decoration: a differential
# reporting "0 divergences" while unable to detect one looks exactly like a
# healthy run. It proves the comparator calls a real difference a divergence
# before any clean result is believed.
if ! command -v cargo >/dev/null 2>&1; then
  printf '  \033[33mSKIP\033[0m cargo is not installed; EL-1 differential not checked\n'
else
  python3 tools/check-el1-differential.py --selfcheck >/dev/null 2>&1
  chk $? "the EL-1 differential can detect a divergence (--selfcheck)"

  OUT=$(python3 tools/check-el1-differential.py -n 2000 2>&1); rc=$?
  [ $rc -eq 0 ]; chk $? "Python and Rust agree on 2000 generated EL-1 cases (rc=$rc)"

  # Mixed connectives are the ONLY shapes where the Z1 class can appear. A run
  # whose generator quietly stopped mixing would still report agreement, so the
  # count is asserted rather than trusted.
  M=$(printf '%s' "$OUT" | sed -n 's/.*, \([0-9]\{1,\}\) mixed-connective.*/\1/p' | head -1)
  [ -n "$M" ] && [ "$M" -gt 500 ]; chk $? "and at least 500 of them mix && with || (got ${M:-none})"

  printf '%s' "$OUT" | grep -q 'pinned divergence'
  chk $? "and the disclosed i64-width divergences are still exactly as pinned"
fi

printf '\n\033[1m== the WHOLE-DECISION differential: §9.3 in both languages (ACP-45 slice 6) ==\033[0m\n'

# The EL-1 differential above compares one expression language. This one drives
# the whole §9.3 checklist on BOTH implementations from one set of inputs -- the
# exact receipt, proposal and bundle the reference Executor itself was handed --
# and compares the verdict, the recomputed risk, the operator, and WHICH CLAUSE
# refused.
#
# The clause is the point. Two implementations that both refuse a forged,
# expired receipt -- one saying 9.3-1, the other 9.3-5 -- have not been shown to
# agree on anything an operator could act on.
if ! command -v cargo >/dev/null 2>&1; then
  printf '  \033[33mSKIP\033[0m cargo is not installed; the decision differential not checked\n'
else
  # --selfcheck FIRST, and it asserts BOTH failure modes: a verdict divergence
  # and a same-verdict-DIFFERENT-CLAUSE divergence. The second is the one this
  # comparison exists for and the one a naive comparator misses, so a harness
  # proving only the first would leave its interesting half untested.
  python3 tools/check-decision-differential.py --selfcheck >/dev/null 2>&1
  chk $? "the decision differential can detect a divergence, INCLUDING a wrong clause"

  OUT=$(python3 tools/check-decision-differential.py --quiet 2>&1); rc=$?
  [ $rc -eq 0 ]; chk $? "Python and Rust agree on §9.3 across the conformance corpus (rc=$rc)"

  # NON-VACUITY, asserted as a NUMBER. A stale BLOCKED entry, a case that stops
  # reaching Executor.execute, or a harness that quietly compared nothing all
  # produce a green run with a smaller denominator. `git add -A` before
  # sync-counts.sh exists for the same reason: green is not the assertion.
  N=$(printf '%s' "$OUT" | sed -n 's/.*agree on \([0-9]\{1,\}\) case(s).*/\1/p' | head -1)
  [ -n "$N" ] && [ "$N" -ge 33 ]; chk $? "and it actually compared at least 33 cases (got ${N:-none})"

  # The classification must cover every conformance case. Adding one to
  # conformance.py turns this red until somebody classifies it -- the harness
  # imports that list rather than keeping a second copy of it.
  printf '%s' "$OUT" | grep -q 'PARTIAL'
  chk $? "and it reports the blocked cases as PARTIAL rather than a smaller total"

  printf '%s' "$OUT" | grep -q 'pinned divergence'
  chk $? "and the disclosed CR-1/CR-4 divergence (ACP-82) is still exactly as pinned"

  # ACP-80 has no conformance case, so the corpus above cannot reach it -- a
  # corpus derived from a case list exercises only what that list holds (T-33).
  # The probe flips ONE byte of unsigned wire data and requires both languages
  # to agree that the outcome changes. If `kind` ever becomes signature-covered
  # the probe must be rewritten, and it says so rather than passing quietly.
  printf '%s' "$OUT" | grep -q 'ACP-80 pinned in BOTH languages'
  chk $? "and ACP-80 (unsigned kind decides quorum membership) reproduces in both"

  # A stale exemption is the failure mode that still prints GREEN: it shrinks
  # the denominator and nothing else changes. So the detector is made to fire on
  # purpose rather than trusted -- the experiment is the claim, the passing run
  # is not.
  python3 tools/check-decision-differential.py --inject-stale --selfcheck >/dev/null 2>&1
  [ $? -ne 0 ]; chk $? "and a stale BLOCKED entry is caught rather than shrinking the denominator"
fi

printf '\n\033[1m== a vacuous sync FAILS the run (ACP-83) ==\033[0m\n'

# The defect this closes: `sync-counts.sh` printed "pattern matched nothing --
# the published claim moved or was deleted, so this sync is vacuous" and then
# EXITED 0. Three checks were dead for a day, and a handoff recorded that exit
# 0 as a green absorbed result.
#
# The trigger was cosmetic. Commit 825f1b3 replaced em dashes with hyphens in
# README.md -- "style, and NOT because anything was found" -- and three sync
# patterns anchored on the em dash. NINE of 62 did; the other six survived only
# because dossier/ and spec/vectors/ had not been cleaned yet.
#
# The repair is not "be careful with dashes", and it is emphatically not
# restoring the punctuation -- that would make README's typography load-bearing
# for a check nobody would guess depends on it. No pattern anchors on a dash any
# more, and THIS is what keeps that honest: a detector whose failure does not
# fail the build is documentation.
#
# The probe drives the REAL sync() function, lifted out of the real file, rather
# than re-running the whole script: sync-counts.sh derives its counts from
# `cargo test --workspace` and every Python suite, so a full second run would
# add minutes to this gate to test three lines of exit logic. Extracting the
# function keeps the subject genuine -- it is the shipped code, not a copy of it
# -- while costing milliseconds.
T=$(mktemp -d)
{
  echo 'CHECK=1; DRIFT=0; VACUOUS=0'
  sed -n '/^sync() {/,/^}$/p' tools/sync-counts.sh
  # A pattern no file can contain. Not a broken regex -- a VALID pattern that
  # matches nothing, which is exactly the shape a renamed claim produces.
  echo "sync \"probe\" \"9/9\" 'ZZQQ-CANNOT-MATCH-[0-9]+/[0-9]+' 'ZZQQ' README.md"
  awk '/== Result ==/,0' tools/sync-counts.sh
} > "$T/probe.sh"

grep -q 'ZZQQ-CANNOT-MATCH' "$T/probe.sh" && grep -q 'VACUOUS' "$T/probe.sh"
chk $? "the vacuity probe carries both the unmatchable pattern and the real exit logic"

OUT=$(cd "$T" 2>/dev/null; bash "$T/probe.sh" 2>&1); rc=$?

# Both halves are asserted. A run that failed for an unrelated reason would
# satisfy the exit-code half on its own and prove nothing about the MISS path.
printf '%s' "$OUT" | grep -q 'matched nothing'
chk $? "a pattern that matches nothing is reported as MISS, not passed over"

[ "$rc" -ne 0 ]; chk $? "and a vacuous sync FAILS the run (rc=$rc, must not be 0)"

printf '%s' "$OUT" | grep -q 'VACUOUS'
chk $? "and the result says VACUOUS rather than reporting ordinary drift"
rm -rf "$T"

printf '\n\033[1m== published assertion count matches this run ==\033[0m\n'

# README.md and CLAUDE.md both publish how many assertions this script makes.
# The number had already drifted once -- it said 34 while the run made 45 --
# which is the same defect as the mutation counts and the Rust test count, in
# the file whose entire job is catching that defect.
#
printf '\n\033[1m== spec: the vector classification totals equal its own rows ==\033[0m\n'

# ACP-74/ACP-76. `spec/vectors/CLASSIFICATION.md` carries a per-case table and a
# Totals table stating the same three numbers, and nothing compared them. Adding
# one conformance case moves the row count and leaves the Totals row saying what
# it said yesterday -- a published claim contradicting the table three screens
# above it, in the file that tells a second implementer how much of this
# repository's evidence is shareable.
#
# It is NOT a sync-counts target on purpose: the vector/obligation split is a
# JUDGEMENT made per case, not something a run can derive. What a machine can
# do is insist the summary agrees with the rows it summarises.
CLS=spec/vectors/CLASSIFICATION.md
if [ ! -f "$CLS" ]; then
  bad "$CLS is missing — the classification check cannot run"
else
  ROWS=$(grep -cE '^\| `[a-zA-Z_0-9]+` \|' "$CLS")
  VEC=$(grep -E '^\| `[a-zA-Z_0-9]+` \|' "$CLS" | grep -c '\*\*vector\*\*')
  OBL=$((ROWS - VEC))
  STATED=$(grep -oE '^\| \*\*Total\*\* \| \*\*[0-9]+\*\* \| \*\*[0-9]+\*\* \| \*\*[0-9]+\*\* \|' "$CLS" \
           | grep -oE '[0-9]+' | tr '\n' ' ')

  # The detector must be able to see rows at all. A changed table style would
  # otherwise make ROWS=0, OBL=0, and a stated 0/0/0 would "agree" -- the
  # vacuous-green shape this file exists to refuse.
  [ "$ROWS" -gt 50 ]; chk $? "the per-case detector finds rows at all (counted $ROWS)"

  [ "$STATED" = "$ROWS $VEC $OBL " ]
  chk $? "the Totals row equals the rows it summarises (rows say $ROWS/$VEC/$OBL, table says ${STATED:-none})"
fi

printf '\n\033[1m== spec: clause ids are defined exactly once ==\033[0m\n'

# v1.3.15 defined CL-7 TWICE -- "ledger writes are check-then-mutate" (v1.3.9)
# and "every claim operation MUST be audited" (older) -- because the v1.3.9
# insertion landed above CL-6 and took an id already in use two lines below it.
# Both meanings were cited in the document simultaneously, which made a
# conformance claim of "CL-7 satisfied" unfalsifiable: an implementation could
# satisfy either and cite the clause honestly.
#
# It was found by READING. Nothing in this repository could have found it by
# running, and `spec/vectors/OBLIGATIONS.md` keys per-implementation
# obligations to these ids -- a corpus cannot express "passes CL-7" while CL-7
# names two rules. So the check is on the CLASS: every clause family in the
# document, not the CL-* instance that happened to collide.
dupe_ids() {
  grep -oE '^[[:space:]]*-[[:space:]]+\*\*[A-Z]{2,4}-[0-9]+[a-z]?' "$1" \
    | grep -oE '[A-Z]{2,4}-[0-9]+[a-z]?' | sort | uniq -d
}

# ACP-65: this scanned spec/ACP-SPEC-001.md BY LITERAL PATH, so ACP-DEPLOY-001's
# 85 clause ids were never checked at all and a duplicate DP- id would have
# shipped green. Every normative document in spec/ is scanned now, and the
# manufactured collision below is derived from EACH document's own first id
# rather than hardcoding CL-6 -- a hardcoded id from one document proves
# nothing about another.
for SPECFILE in spec/ACP-*.md; do
  SPECNAME=$(basename "$SPECFILE" .md)

  D=$(dupe_ids "$SPECFILE")
  if [ -z "$D" ]; then
    ok "every clause id in $SPECNAME is defined exactly once"
  else
    bad "$SPECNAME: clause ids defined more than once: $(echo "$D" | tr '\n' ' ')"
  fi

  # THE ASSERTION ABOVE IS VACUOUS ON ITS OWN. A detector whose regex matched
  # nothing -- a changed bullet style, a renamed file, a document that uses a
  # different convention -- reports the same green line as a document with no
  # duplicates, and that is the exact failure this block was written to answer.
  # So a collision is MANUFACTURED per document and the detector must name it.
  # The sabotage is a copy: the real spec is never written to, because a restore
  # step that fails leaves the normative source corrupted.
  FIRSTID=$(grep -oE '^[[:space:]]*-[[:space:]]+\*\*[A-Z]{2,4}-[0-9]+[a-z]?' "$SPECFILE" \
            | grep -oE '[A-Z]{2,4}-[0-9]+[a-z]?' | head -1)
  if [ -z "$FIRSTID" ]; then
    bad "$SPECNAME: the clause-id detector matched NOTHING — the check is vacuous here"
  else
    SPECCOPY=$(mktemp); cp "$SPECFILE" "$SPECCOPY"
    printf -- '- **%s.** manufactured collision — selftest\n' "$FIRSTID" >> "$SPECCOPY"
    D=$(dupe_ids "$SPECCOPY")
    if [ "$D" = "$FIRSTID" ]; then
      ok "and the detector names a manufactured duplicate ($FIRSTID) in $SPECNAME"
    else
      bad "$SPECNAME: manufactured $FIRSTID collision NOT detected (got '$(echo "$D" | tr '\n' ' ')')"
    fi
    rm -f "$SPECCOPY"
  fi
done

# ACP-63's six scaffold assertions moved to the product repository together
# with the services they check (ACP-66). They cannot stay here: services/ is
# no longer in this repository, so the checks would read files that do not
# exist and pass vacuously -- which is precisely the defect ACP-64 was filed
# for. Do not re-add a version of them that skips when services/ is absent.

# --- DP-83/DP-87: the leg register, and a negative control on the check -------
if python3 tools/check-flow-legs.py >/dev/null 2>&1; then
  ok "ACP-DEPLOY-001 Annex A: obligations enforced or exempted, every leg names an artifact"
else
  bad "ACP-DEPLOY-001 Annex A: the leg register has a defect"
fi

# A checker asserted only by `exit 0` is satisfied by a checker that always
# exits 0, and this one grew four new checks in ACP-78. So the register is
# mutated back to its pre-ACP-78 state -- the F9.1 time-source leg and its
# vocabulary row removed -- and the check must FAIL and must name DP-7's
# crossing (v). That mutation is not hypothetical: it is exactly what the
# register said until ACP-78, while DP-7 enumerated the crossing three hundred
# lines above it and nothing compared the two.
LEGDOC=spec/ACP-DEPLOY-001.md
LEGBAK=$(mktemp)
cp "$LEGDOC" "$LEGBAK"
restore_legdoc() { [ -s "$LEGBAK" ] && cp "$LEGBAK" "$LEGDOC"; }
trap 'restore_legdoc; rm -f "$LEGBAK"' INT TERM EXIT

grep -v '^| F9\.1 ' "$LEGBAK" | grep -v '^| network time source | DP-7 |$' > "$LEGDOC"

OUT=$(python3 tools/check-flow-legs.py 2>&1); rc=$?
[ $rc -ne 0 ]; chk $? "removing the time-source leg makes check-flow-legs FAIL (got $rc)"
has 'DP-7 crossing \(v\) names no artifact any leg carries' \
    "and it names DP-7 crossing (v), the enumerated crossing with no row"

restore_legdoc
trap - INT TERM EXIT
cmp -s "$LEGBAK" "$LEGDOC"
chk $? "the leg register is byte-identical again after the restore"
rm -f "$LEGBAK"

# Control: the unmutated register passes the same check. Without this line the
# two assertions above are satisfied by a checker that fails on everything.
OUT=$(python3 tools/check-flow-legs.py 2>&1); rc=$?
[ $rc -eq 0 ]; chk $? "and the restored register passes again (got $rc)"

# --- ACP-71: DP-27's custody claims must match custody.rs -----------------------
# DP-27 is a Normative Disclosure. It said "there is no `KmsSigner`" for weeks
# after ACP-61 created one. Nothing compared the prose to the code, so the
# divergence was invisible -- and it survived because it erred in the SAFE
# direction: a disclosure claiming less capability than exists trips no test and
# reads as humility. This compares both directions.
custody_says () {   # honours a substituted file, which is what makes the falsification possible
  grep -qE "pub struct ${1}Signer" "${2:-crates/acp-crypto/src/custody.rs}" && echo yes || echo no
}
spec_claims () {    # what ACP-DEPLOY-001 asserts about a tier
  grep -qF "$1" spec/ACP-DEPLOY-001.md && echo yes || echo no
}

CODE_T2=$(custody_says Kms); DOC_T2=$(spec_claims 'Custody tier **T2 is implemented**')
CODE_T3=$(custody_says Hsm); DOC_T3=$(spec_claims 'Custody tier **T3 is declared and not implemented**')
if [ "$CODE_T2" = "$DOC_T2" ] && [ "$CODE_T3" != "$DOC_T3" ]; then
  ok "ACP-DEPLOY-001 DP-27 agrees with custody.rs on which tiers are implemented"
else
  bad "DP-27 disagrees with custody.rs — KmsSigner=$CODE_T2 doc-says-T2-implemented=$DOC_T2, HsmSigner=$CODE_T3 doc-says-T3-unimplemented=$DOC_T3"
fi

# MANUFACTURED: delete KmsSigner from a COPY of custody.rs and the comparison must
# go red. Without this the check passes whenever the grep pattern rots, which is
# the same defect one level up. The real source is never written to.
CUSTODYCOPY=$(mktemp)
sed 's/pub struct KmsSigner/pub struct REMOVED_BY_SELFTEST/' \
  crates/acp-crypto/src/custody.rs > "$CUSTODYCOPY"
if [ "$(custody_says Kms "$CUSTODYCOPY")" = "no" ] && [ "$DOC_T2" = "yes" ]; then
  ok "and removing KmsSigner from a copy makes the comparison disagree, as it must"
else
  bad "removing KmsSigner from a copy did NOT change the comparison — the check is vacuous"
fi
rm -f "$CUSTODYCOPY"

# --- ACP-72: the in-image gate is described once, by the thing that runs it ---
# deploy/docker-compose.yml said the in-image gate ran "proofs + 15 suites".
# Eight lines away tools/demonstrator-entrypoint.sh prints "proofs SKIPPED: no
# Dafny in this image", and the Dockerfile installs no Dafny -- so the compose
# comment advertised a proof run that cannot happen, and a reader trusting it
# would count a skipped proof as a passed one.
#
# What makes it worth a check rather than an edit: the ACP-68 count pass TOUCHED
# THAT LINE. It corrected "13 suites" to "15 suites" and left the false "proofs +"
# prefix standing, because a pass that re-derives numbers does not read claims.
# Nothing compared the two descriptions of one run, so the prose fix closed the
# instance and not the class -- the ACP-43/ACP-68 shape, one level up.
#
# The rule asserted: the runner is the authority. Whatever the entrypoint ECHOES
# is what compose must carry, VERBATIM. A paraphrase that agrees today is the
# defect in its dormant form.
gate_banner () {    # the banner from the verify) case, not whichever echo comes first
  awk '/^  verify\)/,/^    ;;/' "${1:-tools/demonstrator-entrypoint.sh}" \
    | sed -n 's/.*echo "== \(.*\) ==".*/\1/p' | head -1
}

BANNER=$(gate_banner)
if [ -z "$BANNER" ]; then
  bad "the entrypoint's verify) banner was not found — every check below it is vacuous"
else
  ok "the entrypoint's verify) case publishes a gate banner"
  if grep -qF "$BANNER" deploy/docker-compose.yml; then
    ok "and deploy/docker-compose.yml describes that run in the runner's own words"
  else
    bad "deploy/docker-compose.yml does not carry the entrypoint's banner: $BANNER"
  fi
fi

# MANUFACTURED, TWICE, because this check has two independent ways to rot.
#
# One: the extractor stops matching -- a renamed case label, a changed banner
# style -- and $BANNER goes empty, at which point `grep -qF ""` matches every
# file on earth and the comparison passes forever. Feeding it an entrypoint with
# no verify) case must produce an empty banner.
ENTRYCOPY=$(mktemp)
sed 's/^  verify)/  RENAMED_BY_SELFTEST)/' tools/demonstrator-entrypoint.sh > "$ENTRYCOPY"
if [ -z "$(gate_banner "$ENTRYCOPY")" ]; then
  ok "and an entrypoint with no verify) case yields no banner rather than a blank match"
else
  bad "a renamed verify) case still yielded a banner — the extractor matches the wrong echo"
fi
rm -f "$ENTRYCOPY"

# Two: the comparison itself. Restore the false claim on a COPY of compose and
# the check must name the file. The real compose is never written to.
COMPOSECOPY=$(mktemp)
grep -vF "$BANNER" deploy/docker-compose.yml > "$COMPOSECOPY"
if [ -n "$BANNER" ] && ! grep -qF "$BANNER" "$COMPOSECOPY"; then
  ok "and a compose file stripped of the banner fails the comparison, as it must"
else
  bad "stripping the banner from a copy did NOT fail the comparison — the check is vacuous"
fi
rm -f "$COMPOSECOPY"

# --- ACP-66 guard 1: the product half must not come back ----------------------
# The split is only worth something if it stays split. A file reappearing under
# services/, orchestrator/ or packages/acp-client is not a merge accident for a
# reviewer to notice -- it is two definitions of one object at repository level,
# and nothing else in this gate would say a word about it. The signer would not
# either: those directories are out of ROOTS now, so a returning file is not
# unsigned-and-loud, it is simply invisible.
#
# Written as a function on purpose: it honours GIT_INDEX_FILE, which is what
# makes the manufactured failure below possible without touching the worktree.
product_paths_tracked () {
  for p in services orchestrator packages/acp-client; do
    git ls-files "$p" | grep -q . && printf '%s ' "$p"
  done
  return 0
}

D=$(product_paths_tracked)
if [ -z "$D" ]; then
  ok "no product path is tracked here (services/ orchestrator/ packages/acp-client)"
else
  bad "product paths are back in this repository: $D"
fi

# THE ASSERTION ABOVE IS VACUOUS ON ITS OWN. "Nothing found" is also what a
# detector reports when it cannot see -- a renamed path, a typo in the loop, a
# git invocation that silently errors. So a violation is MANUFACTURED on every
# run and the detector must name it.
#
# It is staged into a THROWAWAY INDEX, never the working tree and never the real
# index: services/ must not exist on disk even for an instant, because a failure
# between creating it and removing it would leave the split undone and the next
# signature would cover it.
TMPIDX=$(mktemp); rm -f "$TMPIDX"
BLOB=$(printf 'manufactured -- selftest' | git hash-object -w --stdin)
GIT_INDEX_FILE="$TMPIDX" git read-tree HEAD
GIT_INDEX_FILE="$TMPIDX" git update-index --add \
  --cacheinfo "100644,$BLOB,services/manufactured.rs"
D=$(GIT_INDEX_FILE="$TMPIDX" product_paths_tracked)
case "$D" in
  *services*) ok "and the detector names a manufactured services/ file rather than passing" ;;
  *)          bad "a manufactured services/ file was NOT detected (got '$D')" ;;
esac
rm -f "$TMPIDX"

# THIS ASSERTION COUNTS ITSELF. It is the (TOTAL+1)-th, so the published number
# is TOTAL+1 as measured here, and a reader counting OK lines gets the same
# figure. An off-by-one would be a wrong published number arriving by exactly
# the mechanism this block exists to prevent, so it is spelled out rather than
# left to be noticed.
#
# Skipped branches lower the total honestly: a run without cargo makes fewer
# assertions and must publish fewer, which is why this compares against the
# count of what actually ran rather than a constant in the script.
#
# ACP-72: this scanned ONE phrasing -- 'tests the tooling itself (N assertions)'
# -- and .github/PULL_REQUEST_TEMPLATE.md publishes the same number as
# '`./tools/selftest.sh` passes (N assertions)'. That file was therefore free to
# go stale while this assertion reported green, which is the ACP-65 shape: a
# check scoped to where the defect was last seen rather than to the claim.
#
# The pattern is now the PARENTHESISED count, because that is what separates a
# live claim from history. RELEASE.md and docs/plans/roadmap.md both cite old
# figures -- "went from 27 assertions to 29", "published 34 assertions while
# making 45" -- and both are correct as written about released versions. Neither
# is parenthesised, so neither is scanned. A parenthesised count is a claim about
# THIS run and must equal it; if a future note needs to quote an old figure in
# parentheses, this will fail loudly, which is the right way round.
EXPECT=$((TOTAL + 1))
PUBLISHED=$(git ls-files '*.md' \
  | xargs grep -ho '([0-9]\{1,\} assertions)' 2>/dev/null \
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
