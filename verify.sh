#!/usr/bin/env bash
# verify.sh — integrity, then full replay. Exit non-zero on any failure.
#
# This script is the dossier's central claim made executable: every green
# number in §05 is produced here, on your machine, from these bytes. A result
# you have not reproduced should not be believed -- including these.
set -uo pipefail
cd "$(dirname "$0")"
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

hdr "3. Formal proofs"
if command -v dafny >/dev/null 2>&1; then
  out=$(dafny verify --function-syntax:4 artifacts/binding_v1_3_8.dfy 2>&1 | tail -1)
  echo "$out" | grep -q "36 verified, 0 errors"; chk $? "$out"
else
  printf '  \033[33mSKIP\033[0m dafny not installed — §04 unverified on this machine\n'
fi

hdr "4. Test suites"
cd artifacts
run() { # run <script> <expected-substring> <label> [args]
  local s=$1 e=$2 l=$3; shift 3
  o=$(python3 "$s" "$@" 2>&1 | grep -E '^RESULT' | tail -1)
  echo "$o" | grep -q "$e"; chk $? "$l — ${o:-no RESULT line}"
}
run attack_registry.py      "73/73"      "ALL attacks (consolidated registry)"
run attack_registry.py      "4/4"        "Composition ack x ledger" --compose
run conformance.py          "44/44"      "Suite 1  conformance"
run mutate_executor.py      "19/19"      "Suite 2  executor mutation"
run partition_suite.py      "9/9"        "Suite 3  ledger partition"
run partition_integration.py "6/6"       "Suite 4  executor x ledger"
run cbor_suite.py           "8/8"        "Suite 5  canonical CBOR"
run class_findings.py       "/4"         "Suite 8  classification findings"
run ack_suite.py            "14/14"      "Suite 9  signed acknowledgement"
run ack_suite.py            "6/6"        "Suite 9  ack mutation" --mutate
run audit_suite.py          "11/11"      "Suite 7  audit/anchor/accumulator"
run audit_suite.py          "4/4"        "Suite 7  audit mutation" --mutate
o=$(python3 diff_prose.py 2>&1 | grep -c "disagreements")
[ "$o" -ge 1 ]; chk $? "Suite 6  prose differential — Z1 divergence reproduced"
cd ..

hdr "Result"
if [ $FAIL -eq 0 ]; then
  echo "  All replayed claims hold on this machine."
  echo "  This does NOT mean the system is reviewed: see §06 RR-1."
else
  echo "  One or more claims did not replay. Treat the affected claim as unproven."
fi
exit $FAIL
