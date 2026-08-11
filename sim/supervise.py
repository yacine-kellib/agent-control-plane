#!/usr/bin/env python3
"""
supervise.py — run the day across seven real OS processes (brief §6.1).

    supervisor
      ├── agent      no key, no tool, no egress — one pipe, typed proposals only
      ├── policy     evaluates; holds the receipt signing key
      ├── approval   the screen humans sign on; holds the attester keys
      └── executor   verifies, holds, releases; holds NO signing key
            ├── ledger     single-use, 5 replicas, injectable partitions
            ├── anchor     external audit anchoring, injectable outage
            └── notifier   out-of-band summaries, own render path

`sim/run_day.py` runs the identical logic in one interpreter and is the faster
way to iterate. This module exists because "separate services" is a claim about
process boundaries, and a claim like that is worth exactly as much as the
strongest test of it. Seven boxes that are really seven imports have drawn the
architecture, not built it.

Run:  python3 -m sim.supervise            # the day, across processes
      python3 -m sim.supervise --checks   # the isolation properties only
"""
from __future__ import annotations

import json
import os
import sys

from sim.log import (BLOCKED, EXECUTED, LEDGER_NONCE, REFUSED, RELEASED,
                     ActionRecord, EventLog)
from sim.release import ack_latency_seconds
from sim.services._rpc import RemoteFailure, Service
from sim.world import Clock, site_of

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
TIMELINE = os.path.join(HERE, "timeline.json")


class Deployment:
    """The four processes the supervisor owns directly."""

    def __init__(self):
        self.agent = Service("agent", "sim.services.agent_svc", REPO)
        self.policy = Service("policy", "sim.services.policy_svc", REPO)
        self.approval = Service("approval", "sim.services.approval_svc", REPO)
        self.executor = Service("executor", "sim.services.executor_svc", REPO)

    def close(self):
        for s in (self.agent, self.policy, self.approval, self.executor):
            s.close()

    # ------------------------------------------------------------------
    def isolation_checks(self) -> list:
        """
        The structural properties, asked of the running processes.

        Every one of these is a question about what a process IS, not about how
        it promises to behave.
        """
        out = []

        holds = self.agent.call("holds_key")
        out.append(("agent holds no key material", holds is False,
                    "the agent proposes; it is never a principal, so there is "
                    "no key a compromised agent could misuse"))

        st = self.executor.call("stats")
        paths = st["render_paths"]
        notif, appr = [p.strip() for p in paths.split("||")]
        out.append(("notifier and approval render paths are distinct",
                    notif != appr,
                    f"{notif}  vs  {appr}"))

        pids = st["pids"]
        all_pids = {self.agent.pid, self.policy.pid, self.approval.pid,
                    self.executor.pid, *pids.values()}
        out.append(("seven distinct OS processes", len(all_pids) == 7,
                    f"pids {sorted(all_pids)} — no shared interpreter, no "
                    f"shared memory, no cross-imports at run time"))

        # The bundle is not shipped between services; each derives it and they
        # agree. A service handed a bundle by a peer would be trusting the peer.
        pol_hash = self.policy.call("bundle_hash")
        exe_hash = st.get("bundle_hash")
        out.append(("policy and executor independently derive the same bundle",
                    bool(exe_hash) and pol_hash == exe_hash,
                    f"{pol_hash[:23]}… computed separately in each process — "
                    f"no bundle is shipped over a pipe, because a service handed "
                    f"a bundle by a peer is trusting the peer (RAD-4)"))
        return out


class ProcessRun:
    """Drives the timeline over the pipes."""

    def __init__(self, dep: Deployment, verbose: bool = True):
        self.d = dep
        self.clock = Clock()
        self.log = EventLog()
        self.verbose = verbose
        with open(TIMELINE) as fh:
            self.timeline = json.load(fh)

    def run(self) -> EventLog:
        for idx, ev in enumerate(self.timeline["events"]):
            self.clock.set_hhmm(ev["at"])
            inbound = ev.get("inbound", {})
            hidden = self._hidden(inbound)
            self.d.agent.call("ingest", inbound=inbound, hidden=hidden)
            if self.verbose:
                tag = f"  [{ev['attack']} attack]" if ev.get("attack") else ""
                print(f"\n{ev['at']}  {inbound.get('summary','')}{tag}")
            for spec in ev.get("proposals", []):
                for p in self.d.agent.call("propose", spec=spec):
                    self._handle(p, idx, ev)
        return self.log

    def _hidden(self, inbound):
        doc = inbound.get("document")
        if not doc:
            return None
        path = os.path.join(HERE, doc)
        if not os.path.exists(path):
            return None
        from sim.attacks.document import extract_hidden
        return extract_hidden(path)

    # ------------------------------------------------------------------
    def _handle(self, p: dict, idx: int, ev: dict):
        rec = ActionRecord(seq=-1, at=self.clock.hhmm(), event=idx,
                           task=p["task_type"], target=p["targets"][0],
                           operator=p["operator"], program=p.get("program"),
                           params=dict(p.get("params", {})),
                           attack=ev.get("attack"), site=site_of(p["operator"]))

        d = self.d.policy.call("evaluate", proposal=p)
        rec.disposition, rec.risk = d["disposition"], d["risk"]
        rec.reversibility = d["reversibility"]
        rec.rule, rec.reason = d["rule"], d["reason"]
        if d.get("program"):
            rec.program = d["program"]

        if d["disposition"] == "DENY":
            rec.outcome = REFUSED
            rec.controls_touched.add("policy")
            return self._emit(rec)

        now = self.clock.now
        if d["disposition"] == "ATTEST":
            return self._emit(self._high(rec, p, d, ev, now))

        receipt = self.d.policy.call("issue_receipt", proposal=p,
                                     operator=p["operator"], now=now)
        summary = self.d.approval.call("render", proposal=p)
        try:
            out = self.d.executor.call("execute", receipt=receipt, proposal=p,
                                       approval_summary=summary)
            rec.outcome = EXECUTED if out.get("executed") else ""
            rec.controls_touched.add(LEDGER_NONCE)
        except RemoteFailure as e:
            rec.outcome = REFUSED
            rec.rule, rec.reason = e.rule, e.detail
            rec.controls_touched.add("policy")
        return self._emit(rec)

    # ------------------------------------------------------------------
    def _high(self, rec, p, d, ev, now):
        rec.controls_touched.update({"quorum", "hold", "notifier"})
        approvers = self._approvers(p, d)
        atts = []
        if ev.get("quorum") is not False:
            if len(approvers) < 2:
                rec.outcome = BLOCKED
                rec.rule, rec.reason = "AT-3", "no eligible approver pool"
                return rec
            atts = self.d.approval.call("attest", proposal=p,
                                        operator=p["operator"],
                                        approvers=approvers, now=now,
                                        roles=d.get("required_roles") or [])

        receipt = self.d.policy.call("issue_receipt", proposal=p,
                                     operator=p["operator"], now=now, atts=atts)
        summary = self.d.approval.call("render", proposal=p)
        try:
            out = self.d.executor.call("execute", receipt=receipt, proposal=p,
                                       approval_summary=summary)
            rec.controls_touched.add(LEDGER_NONCE)
        except RemoteFailure as e:
            rec.outcome = BLOCKED
            rec.rule, rec.reason = e.rule, e.detail
            return rec

        ph = receipt["proposal_hash"]
        rec.held_at = now
        rec.notified = out.get("notified") or []
        rec.sampled = bool(out.get("sampled"))

        candidates = sorted(((ack_latency_seconds(site_of(w), rec.at), w)
                             for w in rec.notified if w != rec.operator),
                            key=lambda t: t[0])
        latency = None
        if ev.get("attack") == "lockout":
            latency = self._answer(rec, ph, now, candidates, "REPUDIATE")
        elif rec.reversibility == "IRREVERSIBLE" or rec.sampled:
            latency = self._answer(rec, ph, now, candidates, "CONFIRM")
        rec.ack_latency = latency

        at = now + (60 if latency is None else max(60, latency + 1))
        rec.controls_touched.add("anchor")
        try:
            res = self.d.executor.call("release", proposal_hash=ph, now=at)
            rec.outcome = RELEASED
            rec.released_at, rec.hold_seconds = at, at - now
            rec.human_verified = bool(res.get("human_verified"))
            rec.release_mode = "acknowledged" if rec.human_verified else "silent"
            rec.anchored = True
            rec.rule = "DR-9" if rec.human_verified else "DR-7"
            rec.reason = ("released on positive acknowledgement" if rec.human_verified
                          else "released on silence — counted UNVERIFIED (DR-12)")
        except RemoteFailure as e:
            rec.outcome = BLOCKED
            rec.hold_seconds = at - now
            rec.rule, rec.reason = e.rule, e.detail
        return rec

    def _answer(self, rec, ph, now, candidates, decision):
        for latency, who in candidates:
            at = now + latency
            try:
                ack = self.d.approval.call("acknowledge", proposal_hash=ph,
                                           who=who, decision=decision, now=at)
                method = "repudiate" if decision == "REPUDIATE" else "confirm"
                self.d.executor.call(method, proposal_hash=ph, ack=ack, now=at)
                if decision == "REPUDIATE":
                    rec.repudiated_by = who
                else:
                    rec.acknowledgers.append(who)
                rec.ack_site = site_of(who)
                rec.controls_touched.add("approver")
                return latency
            except RemoteFailure:
                continue
        return None

    @staticmethod
    def _approvers(p, d):
        from sim.world import attesters_for
        program = d.get("program") or p.get("program") or "prog-internal"
        pool = attesters_for(program, exclude={p["operator"]})
        required = [r for r in (d.get("required_roles") or []) if r in pool]
        return (required + [a for a in pool if a not in required])[:2]

    def _emit(self, rec):
        self.log.add(rec)
        if self.verbose and (rec.risk == "HIGH" or rec.outcome == REFUSED):
            mark = {REFUSED: "REFUSED", EXECUTED: "executed",
                    RELEASED: "released", BLOCKED: "BLOCKED"}.get(rec.outcome, "held")
            print(f"        {mark:<9} {rec.task:<20} {rec.target:<28} "
                  f"[{rec.rule}] {rec.reason}")
        return rec


def main(argv: list) -> int:
    dep = Deployment()
    try:
        print("=" * 92)
        print("DEPLOYMENT — seven processes")
        print("=" * 92)
        failures = 0
        for name, ok, detail in dep.isolation_checks():
            failures += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
            print(f"        {detail}")
        if failures:
            return 1
        if "--checks" in argv:
            return 0

        run = ProcessRun(dep, verbose="--quiet" not in argv)
        log = run.run()

        from sim.scoreboard import compute, render
        st0 = dep.executor.call("stats")
        print("\n" + render(compute(log, st0["accumulator_threshold"])))

        st = dep.executor.call("stats")
        print("\n  audit chain: "
              f"{st['chain_len']} records, reconciliation findings: "
              f"{st['reconcile'] or 'none'}; accumulator reconciliation: "
              f"{st['reconcile_accumulators'] or 'none'}")
        return 0
    finally:
        dep.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
