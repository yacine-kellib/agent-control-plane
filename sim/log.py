#!/usr/bin/env python3
"""
log.py — the one event log every downstream claim is computed from.

The scoreboard's counterfactual column MUST be derived from this log rather
than written by hand (brief §8, criterion 12). That constraint is why the record
below carries the *business facts* of an action — its cost, its dataset, its
destination program — and not a precomputed verdict. A record that stored
"would have cost €40,000" would be a hard-coded answer with extra steps.

`controls_touched` is the other load-bearing field. The headline ratio is a
claim about how much of the day passed through no control at all, and a claim
like that is only worth making if something counts it.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

# Disposition from the policy engine
ALLOW, ATTEST, DENY = "ALLOW", "ATTEST", "DENY"

# Terminal outcomes an action can reach
EXECUTED = "executed"          # ran, no human involvement needed
RELEASED = "released"          # was held, then released
REFUSED = "refused"            # policy said no
BLOCKED = "blocked"            # held, then failed closed (no ack, repudiated, ...)


#: Controls that make an action WAIT or make a human ACT. Membership in this
#: set is what disqualifies an action from the headline ratio.
BLOCKING_CONTROLS = {"hold", "notifier", "approver", "anchor", "quorum"}

#: The nonce claim every receipt makes against the Consumption Ledger (§9.3
#: step 6, CL-3). Deliberately NOT a blocking control, and deliberately tracked
#: rather than hidden — see ActionRecord.uncontrolled.
LEDGER_NONCE = "ledger:nonce"


@dataclass
class ActionRecord:
    seq: int
    at: str                      # simulated wall clock, "HH:MM"
    event: int                   # index into the timeline
    task: str
    target: str
    operator: str
    program: str | None
    params: dict

    disposition: str = ""
    risk: str = "—"
    reversibility: str = "—"
    rule: str = ""
    reason: str = ""

    outcome: str = ""
    attack: str | None = None     # which attack produced this, if any

    controls_touched: set = field(default_factory=set)

    @property
    def uncontrolled(self) -> bool:
        """
        Executed without waiting for anything or anyone.

        NOT "touched no ledger". Every executed action claims its receipt nonce
        against the Consumption Ledger, LOW ones included — §9.3 step 6 makes no
        exemption by risk class, and it shouldn't: an unconsumed nonce is a
        replayable receipt (T-09). So the brief's criterion 1, read literally,
        is not satisfiable by a conformant implementation, and this property
        does not pretend otherwise.

        What IS true, and is what the ratio claims: a fast-path action touches
        no notifier, no approver, no anchor and no hold. It claims a nonce in
        microseconds and proceeds. That is the honest version of the number.
        """
        return (self.outcome == EXECUTED
                and not (self.controls_touched & BLOCKING_CONTROLS))

    # -- hold / release detail (floor-HIGH only) -------------------------
    held_at: float | None = None
    released_at: float | None = None
    hold_seconds: float | None = None
    release_mode: str = ""        # "silent" | "acknowledged" | ""
    human_verified: bool = False
    sampled: bool = False
    notified: list = field(default_factory=list)
    acknowledgers: list = field(default_factory=list)
    repudiated_by: str | None = None
    site: str = ""                # operator's site
    ack_site: str = ""            # site of whoever answered — reachability lives here
    ack_latency: float | None = None  # seconds until a human answered; None = nobody was asked
    anchored: bool = False

    def to_json(self) -> dict:
        d = asdict(self)
        d["controls_touched"] = sorted(self.controls_touched)
        return d


class EventLog:
    """Append-only within a run. The single source for every reported number."""

    def __init__(self):
        self.records: list[ActionRecord] = []

    def add(self, rec: ActionRecord) -> ActionRecord:
        rec.seq = len(self.records)
        self.records.append(rec)
        return rec

    def __iter__(self):
        return iter(self.records)

    def __len__(self):
        return len(self.records)

    def where(self, **kw) -> list[ActionRecord]:
        return [r for r in self.records
                if all(getattr(r, k, None) == v for k, v in kw.items())]

    def dump(self, path: str) -> None:
        with open(path, "w") as fh:
            json.dump([r.to_json() for r in self.records], fh, indent=2)
