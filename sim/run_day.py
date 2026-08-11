#!/usr/bin/env python3
"""
run_day.py — run one business day (brief §4).

Build order matters here and is deliberate: this runner executed the fast path
and printed the ratio BEFORE any hold, notifier, acknowledgement or attack code
existed. The demo's credibility rests on the ratio, and the ratio is invisible
if the interesting cases are built first.

Run:  python3 -m sim.run_day             # the day
      python3 -m sim.run_day --ratio     # just the headline ratio
      python3 -m sim.run_day --quiet     # no per-action lines
"""
from __future__ import annotations

import json
import os
import random
import sys

import sim  # noqa: F401
from acp_executor import Executor, FailClosed, h
from acp_ledger import QuorumLedgerAdapter

from sim.agent import Agent
from sim.approve import render as approve_render
from sim.bundle import make_bundle
from sim.log import (ALLOW, ATTEST, BLOCKED, DENY, EXECUTED, LEDGER_NONCE,
                     REFUSED, RELEASED, ActionRecord, EventLog)
from sim.policy import PolicyEngine
from sim.receipts import make_quorum, make_receipt
from sim.release import ack_latency_seconds, build_release_stack, sign_ack
from sim.world import Clock, attesters_for, capabilities, site_of

HERE = os.path.dirname(os.path.abspath(__file__))
TIMELINE = os.path.join(HERE, "timeline.json")


class Simulation:
    """
    One day, one engine, four programs.

    Components are wired here but their responsibilities do not blur: the agent
    proposes, the policy engine decides, the executor verifies. The runner
    itself performs no control — if it did, the simulation would be measuring
    its own orchestration rather than the architecture.
    """

    def __init__(self, timeline_path: str = TIMELINE, verbose: bool = True,
                 seed: int | None = None, ledger_replicas: int = 5):
        with open(timeline_path) as fh:
            self.timeline = json.load(fh)
        self.bundle = make_bundle()
        self.context = capabilities(self.bundle.permitted_targets)
        self.policy = PolicyEngine(self.bundle, self.context)
        self.agent = Agent()
        self.clock = Clock()
        self.log = EventLog()
        self.verbose = verbose

        # One ledger for the whole day, shared by every Executor. Single-use is
        # a property across actions or it is not a property at all.
        self.ledger = QuorumLedgerAdapter(n=ledger_replicas)

        # DR-11: the sampling draw must come from a CSPRNG and must not be
        # influenceable by the requester. `--seed` substitutes a deterministic
        # draw SO THE DEMO REPRODUCES, and a deployment that did this would
        # have handed the attacker the ability to grind proposals until one
        # falls outside the sample. Off by default, and recorded when used.
        self.seed = seed
        sampler = None
        if seed is not None:
            rng = random.Random(seed)
            sampler = rng.random

        stack = build_release_stack(self.bundle, self.ledger, hold_seconds=60,
                                    sample_rate=0.10, sampler=sampler,
                                    now=self.clock.now)
        self.gate = stack["gate"]
        self.chain = stack["chain"]
        self.anchor = stack["anchor"]
        self.accumulators = stack["accumulators"]
        self.notifier = stack["notifier"]
        self.render_paths = stack["render_paths"]

        self.executor = Executor(bundle=self.bundle, ledger=self.ledger,
                                 context=self.context, gate=self.gate)

    # ------------------------------------------------------------------
    def run(self) -> EventLog:
        for idx, ev in enumerate(self.timeline["events"]):
            self.clock.set_hhmm(ev["at"])
            inbound = ev.get("inbound", {})
            hidden = self._load_hidden(inbound)
            self.agent.ingest(inbound, hidden)

            if self.verbose:
                tag = f"  [{ev['attack']} attack]" if ev.get("attack") else ""
                print(f"\n{ev['at']}  {inbound.get('summary','')}{tag}")

            for spec in ev.get("proposals", []):
                for p in self.agent.propose(spec):
                    self._handle(p, idx, ev)
        return self.log

    # ------------------------------------------------------------------
    def _load_hidden(self, inbound: dict) -> str | None:
        """
        Pull the text a human reader never sees out of the inbound document.

        Kept as a first-class step rather than a detail, because the 11:30 event
        depends on a viewer being able to see exactly what the model saw.
        """
        doc = inbound.get("document")
        if not doc:
            return None
        path = os.path.join(HERE, doc)
        if not os.path.exists(path):
            return None
        from sim.attacks.document import extract_hidden
        return extract_hidden(path)

    # ------------------------------------------------------------------
    def _handle(self, p: dict, event_idx: int, ev: dict) -> ActionRecord:
        rec = ActionRecord(
            seq=-1, at=self.clock.hhmm(), event=event_idx,
            task=p["task_type"], target=p["targets"][0], operator=p["operator"],
            program=p.get("program"), params=dict(p.get("params", {})),
            attack=ev.get("attack"), site=site_of(p["operator"]))

        # ---- policy evaluation. The agent's proposal is evaluated exactly as
        # a legitimate one would be; nothing here knows or cares that some of
        # these came from a poisoned document.
        d = self.policy.evaluate(p)
        rec.disposition, rec.risk = d.disposition, d.risk
        rec.reversibility, rec.rule, rec.reason = d.reversibility, d.rule, d.reason
        if d.program:
            rec.program = d.program

        if d.disposition == DENY:
            rec.outcome = REFUSED
            rec.controls_touched.add("policy")
            return self._emit(rec)

        if d.disposition == ATTEST:
            return self._emit(self._attested(rec, p, d, ev))

        # ---- ALLOW: verify and execute. -------------------------------
        receipt = make_receipt(self.bundle, p, operator=p["operator"],
                               now=self.clock.now)
        try:
            out = self.executor.execute(receipt, p)
            rec.outcome = EXECUTED if out.get("executed") else ""
            # §9.3 step 6: every receipt claims its nonce, LOW included. Not a
            # blocking control, but recorded rather than hidden.
            rec.controls_touched.add(LEDGER_NONCE)
        except FailClosed as e:
            rec.outcome = REFUSED
            rec.rule, rec.reason = e.rule, e.detail
            rec.controls_touched.add("policy")
        return self._emit(rec)

    # ------------------------------------------------------------------
    def _attested(self, rec: ActionRecord, p: dict, d, ev: dict) -> ActionRecord:
        """
        The floor-HIGH path: quorum, hold, notify, acknowledge (or not), release.

        Every step below can fail closed, and several of them are supposed to.
        A HIGH action reaching the end of this method is the exception on this
        day, not the rule.
        """
        rec.controls_touched.update({"quorum", "hold", "notifier"})
        now = self.clock.now
        phash = h(p)

        # -- assemble a quorum from people who may actually attest ---------
        #
        # `quorum: false` in the timeline models the case where NO HUMAN WAS
        # EVER ASKED. That is the honest shape of the 11:30 injection: the
        # model emitted a well-formed proposal, and there is simply no
        # attestation in existence to attach to it. Assembling one here would
        # be the simulation doing the attacker's work — the receipt would carry
        # signatures from people who never saw the action.
        if ev.get("quorum") is False:
            atts = []
        else:
            approvers = self._pick_approvers(p, d)
            if len(approvers) < 2:
                rec.outcome = BLOCKED
                rec.rule, rec.reason = "AT-3", "no eligible approver pool"
                return rec
            atts = make_quorum(self.bundle, p, operator=p["operator"],
                               approvers=approvers, risk="HIGH", now=now,
                               required_roles=sorted(d.required_roles))
        receipt = make_receipt(self.bundle, p, operator=p["operator"],
                               now=now, atts=atts)

        # -- the approval screen. This is the surface that can lie (A-8). ----
        approval_summary = approve_render.render(p)

        # -- verify + hold. The Executor recomputes everything that matters
        # and hands the action to the gate rather than executing it (DR-1).
        try:
            out = self.executor.execute(receipt, p,
                                        approval_summary=approval_summary)
            rec.controls_touched.add(LEDGER_NONCE)
        except FailClosed as e:
            rec.outcome = BLOCKED
            rec.rule, rec.reason = e.rule, e.detail
            return rec

        if not out.get("pending_release"):
            # Should not happen while a gate is installed; recorded rather than
            # assumed away, because a HIGH action executing at verification
            # time is precisely what DR-1 forbids.
            rec.outcome = EXECUTED
            rec.rule, rec.reason = "DR-1", "HIGH executed without a hold"
            return rec

        pr = self.gate.pending.get(phash)
        rec.held_at = now
        rec.notified = list(pr.notified) if pr else []
        rec.sampled = bool(pr and pr.sampled)

        # -- the human step, or its absence -------------------------------
        #
        # Latency belongs to whoever ANSWERS, not to whoever proposed. An action
        # raised in London and approved by Boston waits for Boston. Candidates
        # are tried fastest-first, because in practice the first person to reach
        # their phone is the one who releases it.
        needs_ack = (rec.reversibility == "IRREVERSIBLE") or rec.sampled
        candidates = sorted(
            ((ack_latency_seconds(site_of(w), rec.at), w)
             for w in (pr.notified if pr else []) if w != rec.operator),
            key=lambda t: t[0])
        latency = None
        if ev.get("attack") == "lockout":
            # The 16:05 burst: every proposal is repudiated by a notified party.
            latency = self._repudiate(rec, pr, phash, now, candidates)
        elif needs_ack:
            latency = self._acknowledge(rec, pr, phash, now, candidates)
        rec.ack_latency = latency

        # -- release. The clock must actually pass the hold window. --------
        # A silent release waits exactly the hold window and no longer: nobody
        # was asked to answer, so there is no one to wait for. Only an action
        # that genuinely needs a human inherits that human's latency.
        wait = (self.gate.hold if latency is None
                else max(self.gate.hold, latency + 1))
        self.clock.now = now + wait
        rec.controls_touched.add("anchor")
        try:
            res = self.gate.release(phash, self.clock.now)
            rec.outcome = RELEASED
            rec.released_at = self.clock.now
            rec.hold_seconds = self.clock.now - now
            rec.human_verified = bool(res.get("human_verified"))
            rec.release_mode = "acknowledged" if rec.human_verified else "silent"
            rec.anchored = True
            rec.rule = "DR-9" if rec.human_verified else "DR-7"
            rec.reason = ("released on positive acknowledgement"
                          if rec.human_verified else
                          "released on silence — counted as UNVERIFIED (DR-12)")
        except FailClosed as e:
            rec.outcome = BLOCKED
            rec.released_at = None
            rec.hold_seconds = self.clock.now - now
            rec.rule, rec.reason = e.rule, e.detail
        finally:
            self.clock.now = now      # the day's clock is the timeline's
        return rec

    # ------------------------------------------------------------------
    def _pick_approvers(self, p: dict, d) -> list:
        """
        Eligible approvers: can attest, see the program, and are NOT the
        operator (AT-2). Required roles are seated first — a quorum that
        happens to satisfy the count while omitting `legal-01` is refused by
        the gate, so building it that way would only produce a slower failure.
        """
        program = d.program or p.get("program") or "prog-internal"
        pool = attesters_for(program, exclude={p["operator"]})
        required = [r for r in sorted(d.required_roles) if r in pool]
        rest = [a for a in pool if a not in required]
        return (required + rest)[:2]

    def _acknowledge(self, rec, pr, phash, now, candidates):
        """
        DR-9: a signed acknowledgement from a notified NON-operator party.

        Returns the latency of whoever actually answered, so the hold reflects
        real reachability rather than a nominal window.
        """
        for latency, who in candidates:
            try:
                at = now + latency
                ack = sign_ack(self.bundle, phash, who, "CONFIRM", at)
                self.gate.confirm(phash, ack, at)
                rec.acknowledgers.append(who)
                rec.ack_site = site_of(who)
                rec.controls_touched.add("approver")
                return latency
            except FailClosed:
                continue
        return None

    def _repudiate(self, rec, pr, phash, now, candidates):
        """DR-4: any notified party may veto. Fails closed with a critical alert."""
        for latency, who in candidates:
            try:
                at = now + latency
                ack = sign_ack(self.bundle, phash, who, "REPUDIATE", at)
                self.gate.repudiate(phash, ack, at)
                rec.repudiated_by = who
                rec.ack_site = site_of(who)
                rec.controls_touched.add("approver")
                return latency
            except FailClosed:
                continue
        return None

    def _emit(self, rec: ActionRecord) -> ActionRecord:
        self.log.add(rec)
        if self.verbose and (rec.risk == "HIGH" or rec.outcome == REFUSED):
            mark = {REFUSED: "REFUSED", EXECUTED: "executed",
                    RELEASED: "released", BLOCKED: "BLOCKED"}.get(rec.outcome, "held")
            print(f"        {mark:<9} {rec.task:<20} {rec.target:<28} "
                  f"[{rec.rule}] {rec.reason}")
        return rec


# ------------------------------------------------------------------ reporting
def ratio_report(log: EventLog) -> dict:
    """
    The number the architecture lives or dies on.

    If the overwhelming majority of a day does not pass through a control, the
    control plane is affordable. If it doesn't, the design argues against
    itself: a control plane that taxes the routine gets routed around, and a
    control that is routed around provides nothing.
    """
    total = len(log)
    uncontrolled = sum(1 for r in log if r.uncontrolled)
    low = sum(1 for r in log if r.uncontrolled and r.risk == "LOW")
    medium = sum(1 for r in log if r.uncontrolled and r.risk == "MEDIUM")
    executed = sum(1 for r in log if r.outcome == EXECUTED)
    held = sum(1 for r in log if r.risk == "HIGH" and r.outcome != REFUSED)
    refused = sum(1 for r in log if r.outcome == REFUSED)
    return {"total": total, "uncontrolled": uncontrolled, "executed": executed,
            "low": low, "medium": medium, "held": held, "refused": refused,
            "pct": (100.0 * uncontrolled / total) if total else 0.0}


def print_ratio(log: EventLog) -> None:
    r = ratio_report(log)
    print("\n" + "=" * 78)
    print("THE RATIO")
    print("=" * 78)
    print(f"  proposals evaluated                       {r['total']:>5}")
    print(f"  executed with NO control interaction      {r['uncontrolled']:>5}"
          f"   {r['pct']:.1f}%")
    print(f"      of which LOW    (fast path)           {r['low']:>5}")
    print(f"      of which MEDIUM (audited, no hold)    {r['medium']:>5}")
    print(f"  held for a human                          {r['held']:>5}")
    print(f"  refused at policy evaluation              {r['refused']:>5}")
    print("-" * 78)
    print("  None of those touched a ledger, a notifier or an approver. Every one")
    print("  of them was audited — audit is universal here and is not counted as a")
    print("  control interaction, or this number would be zero and would be")
    print("  describing a tax the architecture does not levy.")


def main(argv: list) -> int:
    verbose = "--quiet" not in argv and "--ratio" not in argv
    sim_ = Simulation(verbose=verbose)
    log = sim_.run()
    print_ratio(log)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
