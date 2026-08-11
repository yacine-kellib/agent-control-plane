"""
sim — end-to-end business simulation of an agentic research pipeline under ACP.

ILLUSTRATIVE. This models a company *shaped like* an AI-driven drug design firm,
built from public information. It describes no organisation's internal systems
and claims no knowledge of any. Every number, tier and threshold below is a
placeholder a real deployment must re-derive with its own scientists and its own
risk owners.

The control plane itself is NOT re-implemented here. Every enforcement rule
comes from the reference implementation in ../reference/src, imported unchanged:

    acp_executor.py   Executor (§9.3), Bundle, DeferredReleaseGate (DR-1..12)
    acp_ack.py        AuthenticatedReleaseGate (ACK-1..6)
    acp_audit.py      AuditChain, AnchorService, Accumulators (AU-6/7, AC-5)
    acp_ledger.py     QuorumLedger (CL-1..7)

That is deliberate. Those modules carry mutation-tested checks whose markers the
repo's own evidence chain depends on; a forked-and-edited copy would silently
void it. What this package adds is a *domain* and a *day*, never a control.
"""
import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "reference", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
