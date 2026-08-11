#!/usr/bin/env python3
"""
world.py — the organisation the simulation runs inside (brief §2).

One engine serving four program contexts. The partners are commercial
competitors and the internal pipeline competes with all of them, so PROGRAM
SEPARATION IS THE BUSINESS, not a compliance nicety. That single fact is what
makes the cross-program rule in bundle.py the most important entry in the
policy table.

Nothing in this module is a control. It is the org chart the controls act on.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ------------------------------------------------------------------ programs
# Four contexts sharing one engine. alpha, beta and gamma are commercial
# competitors of each other; internal competes with all three.
PROGRAMS = {
    "prog-internal": "own pipeline — undisclosed targets, highest sensitivity",
    "prog-alpha":    "partner A — contractual data boundary",
    "prog-beta":     "partner B — competitor of A",
    "prog-gamma":    "partner C — competitor of A and B",
}

# --------------------------------------------------------------------- sites
# Sites matter for exactly two reasons: an approver must be reachable in a
# working timezone (which is where notification latency and habituation come
# from), and some actions are jurisdiction-bound.
SITES = {
    "london":   {"utc_offset": 1,  "work_start": 9, "work_end": 18},
    "lausanne": {"utc_offset": 2,  "work_start": 8, "work_end": 17},
    "boston":   {"utc_offset": -4, "work_start": 9, "work_end": 18},
}


@dataclass(frozen=True)
class Person:
    id: str
    role: str
    programs: frozenset          # which program contexts they may see
    site: str
    can_attest: bool
    # A key is what makes an identity able to sign. `None` is not an omission.
    key: bytes | None = None

    def sees(self, program: str) -> bool:
        return "*" in self.programs or program in self.programs


# -------------------------------------------------------------------- people
#
# NOTE THE LAST ROW. `agent-01` holds no attester key, and that is not an
# implementation detail — it is the design. The agent proposes; it is never a
# principal, so there is no key for a compromised agent to misuse and no quorum
# it can contribute to. Every other identity here can sign because a human
# stands behind it.
PEOPLE = {
    "sci-01":   Person("sci-01",   "computational scientist",
                       frozenset({"prog-internal", "prog-alpha"}), "london",
                       True,  b"k-sci-01"),
    "sci-02":   Person("sci-02",   "computational scientist",
                       frozenset({"prog-alpha"}), "london",
                       True,  b"k-sci-02"),
    "sci-03":   Person("sci-03",   "medicinal chemist",
                       frozenset({"prog-internal", "prog-beta"}), "lausanne",
                       True,  b"k-sci-03"),
    "ops-01":   Person("ops-01",   "lab operations",
                       frozenset({"*"}), "boston",
                       True,  b"k-ops-01"),
    "legal-01": Person("legal-01", "contracts",
                       frozenset({"*"}), "london",
                       True,  b"k-legal-01"),
    "agent-01": Person("agent-01", "the AI agent",
                       frozenset(), "—",
                       False, None),
}

#: Keys the signed bundle registers for attestation and acknowledgement.
#: An identity absent from this map cannot sign anything the Executor accepts —
#: which is the whole of `agent-01`'s containment, stated as data.
ATTESTER_KEYS = {p.id: p.key for p in PEOPLE.values() if p.key is not None}

#: `legal-01` is required in the quorum for any disclosure leaving the trust
#: boundary. Contract exposure is not a judgement a scientist is positioned to
#: make, and the control plane should not pretend otherwise.
DISCLOSURE_ROLE = "legal-01"


def attesters_for(program: str, exclude: set[str] | None = None) -> list[str]:
    """
    Identities eligible to attest for an action in `program`.

    Eligibility is program visibility plus a registered key. The operator is
    excluded by the caller (AT-2 distinctness) rather than here, because who
    the operator is depends on the action, not on the org chart.
    """
    exclude = exclude or set()
    return [p.id for p in PEOPLE.values()
            if p.can_attest and p.sees(program) and p.id not in exclude]


def site_of(person_id: str) -> str:
    p = PEOPLE.get(person_id)
    return p.site if p else "—"


# -------------------------------------------------------------- capabilities
#: What each role may *operate*, independent of what it may *attest*. The two
#: are deliberately different lists: `legal-01` must be in the quorum for a
#: partner release but is not the person who proposes one, and `ops-01` runs
#: instruments without being able to commit spend.
ROLE_ACTIONS = {
    "computational scientist": {
        "read_literature", "run_simulation", "predict_structure",
        "register_candidate", "schedule_assay", "order_synthesis",
        "release_to_partner", "submit_regulatory"},
    "medicinal chemist": {
        "read_literature", "run_simulation", "predict_structure",
        "register_candidate", "schedule_assay", "consume_reagent",
        "order_synthesis"},
    "lab operations": {"schedule_assay", "consume_reagent"},
    "contracts": {"release_to_partner", "submit_regulatory"},
}


def capabilities(permitted_targets: dict) -> dict:
    """
    Build the Context Store: operator → {"action:target"}.

    Shape matches the reference Executor's step-9 recheck, which re-queries
    capability at EXECUTION time rather than trusting the receipt (T-10). The
    16:05 attack turns on that distinction: an operator who was capable when a
    proposal was made must still be capable when it releases, and — the half
    people forget — an operator flooded with repudiated proposals must NOT lose
    the capability they still legitimately hold.

    `agent-01` appears nowhere in the result. It proposes; it never operates.
    """
    ctx: dict[str, set[str]] = {}
    for p in PEOPLE.values():
        if p.key is None:                       # the agent holds no capability
            continue
        allowed = ROLE_ACTIONS.get(p.role, set())
        caps = set()
        for action in allowed:
            for target in permitted_targets.get(action, set()):
                # A partner channel is only reachable by someone who sees that
                # program. Everything else is shared infrastructure.
                if target.startswith("partner-channel:"):
                    if not p.sees(target.split(":", 1)[1]):
                        continue
                caps.add(f"{action}:{target}")
        ctx[p.id] = caps
    return ctx


@dataclass
class Clock:
    """
    Simulated wall clock, compressed. Held as a mutable object so the whole
    simulation reads one time source: a hold window that "elapses" must elapse
    for the ledger, the audit chain and the release gate identically, or the
    run proves nothing about ordering.
    """
    now: float = 0.0

    def set_hhmm(self, hhmm: str) -> float:
        h, m = hhmm.split(":")
        self.now = float(int(h) * 3600 + int(m) * 60)
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now

    def hhmm(self) -> str:
        t = int(self.now)
        return f"{(t // 3600) % 24:02d}:{(t % 3600) // 60:02d}"
