#!/usr/bin/env bash
# Entrypoint for the ACP demonstrator container.
#
# Two jobs: refuse to run unless the operator has said, in the run command, that
# they know this is not a control plane; and state the three reasons why before
# anything else is printed. Every scaffold main() under services/ exits non-zero
# for the same reason -- a thing that runs is assumed to work, and this one does
# not deliver its own headline invariant.
set -uo pipefail

banner() {
  cat <<'EOF'
================================================================================
  ACP DEMONSTRATOR — NOT A DEPLOYABLE CONTROL PLANE
================================================================================
  This runs the real control FLOW across seven real OS processes. Three things
  are modelled rather than implemented, and all three are load-bearing:

  1. PRIMITIVES ARE HMAC-SHA256, NOT Ed25519/ML-DSA  (acp_executor.py:80)
     HMAC is symmetric, so every verifier holds a key that can also sign.
     INV-1-HIGH — "no single compromised component can cause a high-impact
     action to execute" — DOES NOT HOLD HERE. A compromised executor mints
     its own quorum. The hybrid COMPOSITION (CR-1..CR-5) is faithful; the
     primitives are not.

  2. THE LEDGER IS IN-MEMORY  (acp_executor.py:221)
     CL-2 nonce single-use, CL-3 attestation single-use and the RAD-3 epoch
     high-water mark are Python sets. They do not survive a restart, and
     replay protection that forgets on restart is not replay protection.

  3. THE ANCHOR IS AN IN-PROCESS LIST  (acp_audit.py:70)
     AU-4 requires the anchor to sit outside the trust domain of what it
     anchors. Here it shares a process tree with it.

  What this DOES demonstrate: that a fully-injected model's output is only a
  proposal, that risk is recomputed from a signed bundle the model never sees,
  and that irreversible actions do not execute on silence.

  Fixing (1) is days — cryptography and dilithium-py are already dependencies
  and the swap sites are marked CRYPTO-SWAP. See dossier/06-RESIDUAL-RISK.md.
================================================================================
EOF
}

if [ "${ACP_DEMONSTRATOR:-}" != "1" ]; then
  banner
  cat <<'EOF'

  REFUSING TO START.

  Set ACP_DEMONSTRATOR=1 to confirm you have read the three limitations above
  and are not treating this as a control plane:

      docker run --rm -e ACP_DEMONSTRATOR=1 acp-demonstrator

  This check exists so the container cannot silently become production. It is
  the same reason every scaffold main() in services/ exits non-zero.

EOF
  exit 3
fi

banner
echo

cd /acp

case "${1:-day}" in
  day)
    echo "== the day, across seven real OS processes =="
    exec python3 -m sim.supervise
    ;;
  checks)
    echo "== process-isolation properties only =="
    exec python3 -m sim.supervise --checks
    ;;
  scoreboard)
    echo "== the deliverable =="
    exec python3 -m sim.scoreboard
    ;;
  acceptance)
    echo "== twelve criteria =="
    exec python3 -m sim.acceptance
    ;;
  verify)
    # The gate, inside the image. Two things are deliberately absent.
    #
    # Integrity and signature are NOT checked: regenerating the manifest needs
    # the offline release key, which must never be in a container image. Red
    # sections 1-2 between releases are a property of offline signing.
    #
    # Dafny is NOT installed, so section 3 prints SKIP and the run reports 14
    # result lines rather than 15. A skipped proof is not a passed one -- to
    # replay the 36 proofs, run ./tools/verify.sh --suites on a host with Dafny.
    # CI does exactly that on every push.
    echo "== 13 suites + 29 mutants (proofs SKIPPED: no Dafny in this image) =="
    exec ./tools/verify.sh --suites
    ;;
  shell)
    exec /bin/bash
    ;;
  *)
    exec "$@"
    ;;
esac
