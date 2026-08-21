# ACP demonstrator — the control plane as seven real processes, in one container.
#
# WHAT THIS IS. `sim.supervise` runs the Python reference implementation across
# seven OS processes with real boundaries: the agent holds no key material,
# policy and executor derive the signed bundle independently (RAD-4), the anchor
# sits outside what it anchors, and the notifier and approval render paths are
# distinct (DR-2). `--checks` asserts all four.
#
# WHAT THIS IS NOT. A deployable control plane. Two things are modelled rather
# than real, and each is named on startup by tools/demonstrator-banner.sh:
#
#   1. The ledger is in-memory (acp_executor.py:221). CL-2/CL-3 single-use and
#      the RAD-3 epoch high-water mark do not survive a restart, and replay
#      protection that forgets on restart is not replay protection.
#   2. The anchor is an in-process list (acp_audit.py:70), while AU-4 requires
#      it to live outside the trust domain of what it anchors.
#
# Signatures were a third entry here until v1.3.14 and are now real: Ed25519 +
# ML-DSA-65, asymmetric, bundle carries public keys only. COSE_Sign1 is still
# not the carrier and SLH-DSA is declared without an implementation.
#
# The container refuses to start without ACP_DEMONSTRATOR=1 so that it cannot
# quietly become somebody's production control plane. That is the repository's
# fail-safe-default rule applied to itself: absent input never means permission.

FROM python:3.12-slim

# cryptography and dilithium-py are needed by tools/verify.sh AND, since
# v1.3.14, by sim/ itself, which signs with real hybrid keys. They are installed
# so the image can
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
# lets the demonstrator inherit the 57/57 conformance result and the 38 mutants
# instead of being a second implementation with no evidence behind it.
ENV PYTHONPATH=/acp/reference/src
ENV PYTHONUNBUFFERED=1

# Not root. The demonstrator binds nothing and needs no privilege.
RUN useradd --create-home --uid 10001 acp && chown -R acp:acp /acp
USER acp

ENTRYPOINT ["/acp/tools/demonstrator-entrypoint.sh"]
CMD ["day"]
