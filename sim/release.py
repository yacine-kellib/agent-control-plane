#!/usr/bin/env python3
"""
release.py — hold, notify, acknowledge, release (brief §6.1: `notifier`,
`approval`, and the gate between them).

Assembles three reference gates into the one this business needs:

    DeferredReleaseGate       DR-1..DR-12   hold, veto, silence, sampling
    AuthenticatedReleaseGate  ACK-1..ACK-6  acknowledgement is a SIGNED OBJECT
    AuditedReleaseGate        AU-6/7, AC-5  anchor before release, count at release

They are combined by inheritance rather than rewritten, so every mutation-tested
marker in them stays where the repo's evidence chain expects it.

THE STARTUP CHECK is here too, and it is the reason this module imports both
render paths: a deployment whose notifier and approval screen share a rendering
code path is refused before it serves a single action.
"""
from __future__ import annotations

import sys

import sim  # noqa: F401
from acp_ack import AuthenticatedReleaseGate, make_ack
from acp_audit import Accumulators, AnchorService, AuditChain, AuditedReleaseGate
from acp_executor import CriticalAlert, FailClosed

from sim.approve import render as approve_render
from sim.notify import render as notify_render
from sim.world import PEOPLE, SITES, site_of

#: Deny-effect accumulator threshold, defined ONCE and imported by every
#: component that needs it. It was previously repeated in four places and drifted
#: the moment the timeline grew: sci-01's legitimate floor-HIGH volume rose to
#: exactly the threshold, and the lockout demonstration silently stopped
#: demonstrating anything. A security constant with four copies has no value.
#:
#: Chosen with headroom on both sides, so the test can fail in either direction:
#:   sci-01 legitimate releases      10   (under it — they keep working)
#:   + the 16:05 repudiated burst    23   (over it — they would be locked out)
#: Count at release (AC-5) and sci-01 works. Count at decision (the W1 defect)
#: and an attacker who executed nothing has taken them offline.
ACCUMULATOR_THRESHOLD = 15


# ------------------------------------------------------- criterion 11
def assert_render_paths_distinct() -> str:
    """
    Refuse to start if the notifier and the approval screen share a render path.

    DR-2 is an architectural property, not a runtime one — the specification is
    explicit that the runtime check is a lint rather than a control (T-32, open).
    This is that lint, and its honest description is: it catches the refactor
    that collapses the two paths, not an adversary who wants them collapsed.
    Someone who controls both services controls this check too.

    It compares CODE OBJECT filenames, so a module that merely re-exports the
    other one is caught even though its own `__file__` differs.
    """
    a, b = notify_render.path_id(), approve_render.path_id()
    a_file = a.split(":", 1)[1]
    b_file = b.split(":", 1)[1]
    if a_file == b_file:
        raise CriticalAlert(
            "DR-2", f"notifier and approval share a rendering code path "
                    f"({a_file}) — refused at startup. Two channels sourced "
                    f"from one renderer are one channel wearing two hats.")
    return f"{a}  ||  {b}"


# ------------------------------------------------------------------ notifier
class Notifier:
    """
    The out-of-band notification service (brief §6.1: `notifier`).

    MUST NOT share rendering code or repository with `approval`. It obtains no
    display text from any component of the approval chain — it re-derives
    everything from the canonical Proposal. A summary obtained *from* the party
    under verification would be that party's claim about what it displayed,
    which is not evidence.
    """

    def __init__(self, unreachable: set | None = None):
        #: Injectable, because DR-8 is a claim about what happens when the
        #: detection channel is absent, and a claim like that needs the absence
        #: to be producible.
        self.unreachable = set(unreachable or ())
        self.sent: list = []

    def render(self, proposal: dict):
        return notify_render.render(proposal)

    def recipients(self, pr) -> list:
        attesters = [e.get("attester") for e in (pr.receipt.get("attestations") or [])]
        return notify_render.recipients_for(pr.operator, attesters)

    def deliver(self, recipients: list, note) -> list:
        delivered = [r for r in recipients if r not in self.unreachable]
        for r in delivered:
            self.sent.append({"to": r, "text": note.text})
        # DR-8 is enforced by the gate comparing this against `recipients`:
        # incomplete delivery means the veto channel is absent, and executing
        # while the detection channel is absent is executing unwatched.
        return delivered


# ---------------------------------------------------------------- approvers
def ack_latency_seconds(site: str, hhmm: str) -> float:
    """
    How long an approver at `site` takes to answer a notification sent at `hhmm`
    (timeline times are UTC).

    This is where the timezone story stops being decorative. An approver outside
    working hours is slower, and slower means a longer hold — which is exactly
    how a control that looks fine on an architecture diagram becomes an
    availability problem for Boston at 08:15 UTC.

    NOTE THE CEILING. Every value here is below L-14's 120 s receipt validity,
    and deliberately so: an acknowledgement arriving after the receipt expires
    fails closed at DR-6, and the honest path never releases. A deployment whose
    real approver latencies exceed its receipt window has an unsatisfiable
    configuration, not a slow approver.

    Values are illustrative placeholders. A real deployment measures them, and
    measuring them is most of the point of running this at all.
    """
    cfg = SITES.get(site)
    if cfg is None:
        return 60.0
    hour_utc = int(hhmm.split(":")[0])
    local = (hour_utc + cfg["utc_offset"]) % 24
    if cfg["work_start"] <= local < cfg["work_end"]:
        return 25.0                      # at a desk
    if local < cfg["work_start"]:
        return 85.0                      # before hours — reachable, slowly
    return 95.0                          # after hours


class ResearchGate(AuditedReleaseGate, AuthenticatedReleaseGate):
    """
    One gate carrying every release property this business needs.

    MRO: AuditedReleaseGate → AuthenticatedReleaseGate → DeferredReleaseGate.
    So `hold_action`/`release` come from the audited layer (anchor before
    release, count at release), while `confirm`/`repudiate` come from the
    authenticated layer (a signed object, never a bare name), and the DR-*
    decision logic underneath both is the reference implementation's, untouched.

    Plus one domain control the reference Executor does not carry: REQUIRED
    ROLES.
    """

    def hold_action(self, pr, approval_summary):
        """
        Enforce the bundle's required-role rule, then hold as normal.

        WHY THIS LIVES HERE. §9.3 step 7b(vi) verifies quorum *count* and
        attester distinctness; it does not verify that the quorum contains a
        particular role, because the reference bundle has no such requirement.
        This deployment does: a disclosure leaving the trust boundary needs
        `legal-01` in the room, and two scientists agreeing with each other is
        not the control the contract requires.

        Implemented as an additive check in the enforcement path rather than by
        editing `acp_executor.py`, because that module's checks carry
        mutation-test markers the repository's evidence chain depends on. In a
        production implementation this belongs inside step 7b(vi).

        The role set is read from the SIGNED BUNDLE and the attester identities
        from the VERIFIED Attestation Objects — never from the receipt body.
        """
        required = self.bundle.roles_required(pr.proposal["task_type"])
        if required:
            present = {e["attester"] for e in (pr.receipt.get("attestations") or [])
                       if e.get("kind") == "approval"}
            missing = set(required) - present
            if missing:
                raise CriticalAlert(
                    "AT-3/roles",
                    f"quorum for {pr.proposal['task_type']} is missing required "
                    f"role(s) {sorted(missing)} — present: {sorted(present)}")
        return super().hold_action(pr, approval_summary)


def build_release_stack(bundle, ledger, *, hold_seconds: int = 60,
                        sample_rate: float = 0.10, sampler=None,
                        unreachable: set | None = None,
                        accumulator_threshold: int = ACCUMULATOR_THRESHOLD,
                        now: float = 0.0):
    """
    Wire the release path and return everything the runner needs to drive it.

    The startup check runs FIRST. A stack that cannot demonstrate path
    distinctness is never constructed.

See ACCUMULATOR_THRESHOLD above for why the default is what it is.
    """
    paths = assert_render_paths_distinct()

    anchor = AnchorService()
    chain = AuditChain("t1", bundle.epoch, "1.0.0", anchor, now=now)
    acc = Accumulators(threshold=accumulator_threshold)
    notifier = Notifier(unreachable=unreachable)

    gate = ResearchGate(chain=chain, accumulators=acc, bundle=bundle,
                        ledger=ledger, hold_seconds=hold_seconds,
                        notifier=notifier, sample_rate=sample_rate,
                        sampler=sampler)
    return {"gate": gate, "chain": chain, "anchor": anchor, "accumulators": acc,
            "notifier": notifier, "render_paths": paths}


def sign_ack(bundle, proposal_hash: str, who: str, decision: str,
             now: float, ttl: int = 110):
    """
    Produce a signed Acknowledgement Object on behalf of a human.

    `who` must hold a registered key. `agent-01` does not, so the agent cannot
    acknowledge its own action — the containment restated at the release step.
    """
    person = PEOPLE.get(who)
    if person is None or person.key is None:
        raise FailClosed("ACK-2", f"{who!r} holds no registered key")
    return make_ack(bundle, proposal_hash, who, decision, person.key,
                    now=now, ttl=ttl)


if __name__ == "__main__":
    try:
        print("render paths:", assert_render_paths_distinct())
        print("PASS — notifier and approval are structurally distinct")
    except CriticalAlert as e:
        print(f"FAIL — {e}")
        sys.exit(1)
