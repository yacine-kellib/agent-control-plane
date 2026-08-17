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
  This runs the real control FLOW across seven real OS processes. Two things
  are modelled rather than implemented, and both are load-bearing:

  1. THE LEDGER IS IN-MEMORY  (acp_executor.py:221)
     CL-2 nonce single-use, CL-3 attestation single-use and the RAD-3 epoch
     high-water mark are Python sets. They do not survive a restart, and
     replay protection that forgets on restart is not replay protection.

  2. THE ANCHOR IS AN IN-PROCESS LIST  (acp_audit.py:70)
     AU-4 requires the anchor to sit outside the trust domain of what it
     anchors. Here it shares a process tree with it.

  SIGNATURES ARE REAL as of v1.3.14: Ed25519 + ML-DSA-65, asymmetric, and the
  bundle carries public keys only. This banner listed a third blocker until
  then — HMAC primitives, under which a compromised executor could mint its own
  quorum and INV-1-HIGH did not hold. What is still NOT real: COSE_Sign1 is not
  the carrier (canonical JSON is), and SLH-DSA is declared in SUITES without an
  implementation and fails closed.

  What this DOES demonstrate: that a fully-injected model's output is only a
  proposal, that risk is recomputed from a signed bundle the model never sees,
  and that irreversible actions do not execute on silence.

  See dossier/06-RESIDUAL-RISK.md.
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
    # result lines rather than 16. A skipped proof is not a passed one -- to
    # replay the 36 proofs, run ./tools/verify.sh --suites on a host with Dafny.
    # CI does exactly that on every push.
    echo "== 14 suites + 33 mutants (proofs SKIPPED: no Dafny in this image) =="
    exec ./tools/verify.sh --suites
    ;;
  ingress)
    # The only mode that opens a socket. Binds 0.0.0.0 INSIDE the container so
    # compose can publish it to the host's loopback; the compose port mapping is
    # 127.0.0.1:8848 and widening that is the operator's decision, not ours.
    echo "== external agents may propose here =="
    exec python3 -m sim.ingress --host 0.0.0.0 --port 8848
    ;;
  agent)
    # The untrusted caller. Needs ANTHROPIC_API_KEY in the environment and a
    # reachable ingress; refuses rather than falling back to a recording,
    # because a recorded agent proves nothing this image does not already prove.
    #
    # `shift` drops the mode word. Without it $@ still starts with `agent`,
    # argparse rejects it as an unrecognised argument, and the container exits
    # 2 -- the SAME code the missing-key path uses, so the service looked like
    # it was reporting "no API key" while in fact it had never parsed its
    # arguments at all. This branch is the only one that forwards flags; `*)`
    # below must keep the unshifted $@, since it is the raw-command escape
    # hatch (`run --rm agent ls /acp`).
    shift
    exec python3 -m sim.llm_agent "$@"
    ;;

  ingress-suite)
    echo "== the door, attacked over the wire =="
    exec python3 -m sim.ingress_suite
    ;;
  shell)
    exec /bin/bash
    ;;
  *)
    exec "$@"
    ;;
esac
