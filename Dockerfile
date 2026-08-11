# ACP demonstrator — the control plane as seven real processes, in one container.
#
# WHAT THIS IS. `sim.supervise` runs the Python reference implementation across
# seven OS processes with real boundaries: the agent holds no key material,
# policy and executor derive the signed bundle independently (RAD-4), the anchor
# sits outside what it anchors, and the notifier and approval render paths are
# distinct (DR-2). `--checks` asserts all four.
#
# WHAT THIS IS NOT. A deployable control plane. Three things are modelled rather
# than real, and each is named on startup by tools/demonstrator-banner.sh:
#
#   1. Signature PRIMITIVES are HMAC-SHA256 (acp_executor.py:80). HMAC is
#      symmetric, so a verifier must hold the signing key. INV-1-HIGH -- "no
#      single compromised component" -- does NOT hold here: a compromised
#      executor can mint its own quorum. The hybrid COMPOSITION (CR-1..CR-5) is
#      faithful, because that is protocol logic; the primitives are not.
#   2. The ledger is in-memory (acp_executor.py:221). CL-2/CL-3 single-use and
#      the RAD-3 epoch high-water mark do not survive a restart, and replay
#      protection that forgets on restart is not replay protection.
#   3. The anchor is an in-process list (acp_audit.py:70), while AU-4 requires
#      it to live outside the trust domain of what it anchors.
#
# The container refuses to start without ACP_DEMONSTRATOR=1 so that it cannot
# quietly become somebody's production control plane -- the same reason every
# scaffold main() in services/ exits non-zero.

FROM python:3.12-slim

# cryptography and dilithium-py are needed by tools/verify.sh, not by sim/ --
# the simulation is standard library only. They are installed so the image can
# reproduce the repository's own claims, not merely run the day.
RUN pip install --no-cache-dir cryptography dilithium-py

WORKDIR /acp

# Copy only what the demonstrator and the gate need. docs/, assets/, crates/,
# services/, orchestrator/ and deploy/ are not required to run or to verify the
# Python claims, and leaving them out keeps the image honest about what it runs.
COPY reference/ ./reference/
COPY sim/ ./sim/
COPY spec/ ./spec/
COPY tools/ ./tools/
COPY MANIFEST.sha256 release-key.pub ./

# sim/ imports the reference modules rather than forking them, which is what
# lets the demonstrator inherit the 44/44 conformance result and the 29 mutants
# instead of being a second implementation with no evidence behind it.
ENV PYTHONPATH=/acp/reference/src
ENV PYTHONUNBUFFERED=1

# Not root. The demonstrator binds nothing and needs no privilege.
RUN useradd --create-home --uid 10001 acp && chown -R acp:acp /acp
USER acp

ENTRYPOINT ["/acp/tools/demonstrator-entrypoint.sh"]
CMD ["day"]
