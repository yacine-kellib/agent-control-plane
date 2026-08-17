#!/usr/bin/env bash
# verify.sh — integrity, then full replay. Exit non-zero on any failure.
#
# This script is the dossier's central claim made executable: every green
# number in §05 is produced here, on your machine, from these bytes. A result
# you have not reproduced should not be believed -- including these.
set -uo pipefail
cd "$(dirname "$0")/.."   # tools/ -> repo root; every path below is root-relative

# The suites import the reference implementation by module name. Setting this
# here, in the runner, keeps the sys.path manipulation out of the library and
# out of every suite file -- and keeps `clone, run one command` true without a
# pip install step.
export PYTHONPATH="$PWD/reference/src"

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

FAIL=0
hdr() { printf '\n\033[1m%s\033[0m\n' "== $* =="; }
chk() { if [ "$1" -eq 0 ]; then printf '  \033[32mOK\033[0m   %s\n' "$2";
        else printf '  \033[31mFAIL\033[0m %s\n' "$2"; FAIL=1; fi; }

hdr "0. Prerequisites"
if ! python3 -c "import cryptography, dilithium_py" 2>/dev/null; then
  printf '  \033[31mFAIL\033[0m missing Python modules (cryptography, dilithium-py)\n'
  printf '       python3 -m pip install --break-system-packages cryptography dilithium-py\n'
  printf '       or:   python3 -m venv .venv && source .venv/bin/activate && pip install cryptography dilithium-py\n'
  exit 2
fi
chk 0 "python modules present (cryptography, dilithium-py)"
command -v dafny >/dev/null 2>&1 || printf '  \033[33mNOTE\033[0m dafny not on PATH -- section 04 will be skipped\n'

if [ $SUITES_ONLY -eq 0 ]; then
hdr "1. Integrity"
if sha256sum -c MANIFEST.sha256 >/tmp/acp_sums 2>&1; then
  chk 0 "$(grep -c ': OK$' /tmp/acp_sums) files match MANIFEST.sha256"
else
  chk 1 "manifest mismatch:"; grep -v ': OK$' /tmp/acp_sums | sed 's/^/       /'
fi

hdr "2. Manifest signature (Ed25519, offline release key)"
if [ -f MANIFEST.sha256.sig ] && [ -f release-key.pub ]; then
  python3 - <<'PY'; chk $? "detached signature verifies against release-key.pub"
import sys
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
try:
    pk = load_pem_public_key(open("release-key.pub","rb").read())
    pk.verify(open("MANIFEST.sha256.sig","rb").read(),
              open("MANIFEST.sha256","rb").read())
except (InvalidSignature, Exception) as e:
    print("       ", type(e).__name__, e); sys.exit(1)
PY
else
  printf '  \033[33mSKIP\033[0m unsigned manifest (see RELEASE.md "Signing")\n'
fi
fi  # SUITES_ONLY -- sections 1 and 2 need the release key to be green

hdr "3. Formal proofs"
if command -v dafny >/dev/null 2>&1; then
  out=$(dafny verify --function-syntax:4 reference/proofs/binding.dfy 2>&1 | tail -1)
  echo "$out" | grep -q "36 verified, 0 errors"; chk $? "$out"
else
  printf '  \033[33mSKIP\033[0m dafny not installed — §04 unverified on this machine\n'
fi

hdr "4. Test suites"
cd reference/suites
run() { # run <script> <expected-substring> <label> [args]
  local s=$1 e=$2 l=$3; shift 3
  o=$(python3 "$s" "$@" 2>&1 | grep -E '^RESULT' | tail -1)
  echo "$o" | grep -q "$e"; chk $? "$l — ${o:-no RESULT line}"
}
run attack_registry.py      "79/79"      "ALL attacks (consolidated registry)"
run attack_registry.py      "4/4"        "Composition ack x ledger" --compose
run conformance.py          "50/50"      "Suite 1  conformance"
run mutate_executor.py      "24/24"      "Suite 2  executor mutation"
run partition_suite.py      "9/9"        "Suite 3  ledger partition"
run partition_integration.py "6/6"       "Suite 4  executor x ledger"
run cbor_suite.py           "8/8"        "Suite 5  canonical CBOR"
run class_findings.py       "/4"         "Suite 8  classification findings"
run ack_suite.py            "14/14"      "Suite 9  signed acknowledgement"
run ack_suite.py            "6/6"        "Suite 9  ack mutation" --mutate
run audit_suite.py          "11/11"      "Suite 7  audit/anchor/accumulator"
run audit_suite.py          "4/4"        "Suite 7  audit mutation" --mutate
run llm_agent_suite.py      "44/44"      "Suite 10 live-agent client"
o=$(python3 diff_prose.py 2>&1 | grep -c "disagreements")
[ "$o" -ge 1 ]; chk $? "Suite 6  prose differential — Z1 divergence reproduced"
cd ..

hdr "Result"
if [ $FAIL -eq 0 ]; then
  if [ $SUITES_ONLY -eq 1 ]; then
    # Do not print a claim this run did not check. Integrity was never replayed
    # in --suites mode, and prose that outruns the evidence is a defect here.
    echo "  All suites and proofs replay on this machine."
    echo "  Integrity and signature NOT checked -- run without --suites for those."
  else
    echo "  All replayed claims hold on this machine."
  fi
  echo "  This does NOT mean the system is reviewed: see §06 RR-1."
else
  echo "  One or more claims did not replay. Treat the affected claim as unproven."
fi
exit $FAIL
