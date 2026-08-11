#!/usr/bin/env python3
"""
ingress.py — the door an external agent proposes through.

WHAT THIS CHANGES. Until now the agent was `sim/timeline.json`: a scripted day,
useful for a reproducible demonstration and useless for anyone wanting to point
their OWN model at the control plane. This replaces the script with an HTTP
door. Whatever is on the other side — a model, a shell script, an attacker —
proposes, and the control plane decides.

WHAT IT DELIBERATELY IS NOT. It is not an authorisation service. It holds no
key, signs nothing, and decides nothing. It parses a request, refuses anything
that is not a registered action, and hands the rest to the policy engine over
the same pipe the scripted agent used. If this process is fully compromised the
guarantees are unchanged, which is the only reason it is allowed to face the
network at all.

THE CLOSED-SET PROPERTY, which is the whole point.

    Door A is controllable because actions are a closed, enumerable set — a
    finite list, each with a declared risk and reversibility.

An HTTP endpoint, like an MCP server, accepts arbitrary JSON. A caller can name
any `task_type` it likes. `GET /actions` publishes the nine that exist; anything
else is refused at the door with rule `8.4-3`, and is NOT graded, guessed at, or
treated as unknown-therefore-low. That refusal is the same fail-safe the
Executor applies to an action with no risk function, applied one hop earlier so
the closed set survives contact with an open protocol.

    python3 -m sim.ingress                 # 127.0.0.1:8848
    python3 -m sim.ingress --port 9000
    python3 -m sim.ingress --host 0.0.0.0  # refuses without ACP_DEMONSTRATOR=1

Standard library only, like the rest of sim/.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sim.bundle import PERMITTED_TARGETS, REVERSIBILITY, RISK_FUNCTIONS
from sim.bundle import proposal as canonical_proposal
from sim.policy import PARAM_FIELDS
from sim.release import ack_latency_seconds
from sim.services._rpc import RemoteFailure, Service
from sim.world import attesters_for, site_of

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The closed set. Derived from the signed bundle rather than written out here,
#: because a second hand-maintained list of actions is a second definition of
#: the same object — the encoding-split defect at the source level.
REGISTERED = sorted(r["applies_to"] for r in RISK_FUNCTIONS)


class Plane:
    """
    The four services, plus the held-action table.

    Owns no key. The agent process is absent on purpose: the caller IS the
    agent, and it reaches this over HTTP rather than a pipe.
    """

    def __init__(self):
        self.policy = Service("policy", "sim.services.policy_svc", REPO)
        self.approval = Service("approval", "sim.services.approval_svc", REPO)
        self.executor = Service("executor", "sim.services.executor_svc", REPO)
        self.bundle_hash = self.policy.call("bundle_hash")
        self.holds: dict[str, dict] = {}
        self.lock = threading.Lock()

    def close(self):
        for s in (self.policy, self.approval, self.executor):
            s.close()

    # ------------------------------------------------------------------
    def propose(self, request: dict) -> dict:
        """One request in, one verdict out."""
        task = request.get("task_type")

        # THE DOOR. An unregistered action is refused, not graded. P-4: unknown
        # is never LOW. This is the check that keeps an open protocol from
        # widening the closed set.
        if task not in REGISTERED:
            return {"outcome": "refused", "rule": "8.4-3",
                    "reason": f"action {task!r} is not in the signed bundle; "
                              f"an unregistered action is refused, never graded",
                    "registered_actions": REGISTERED}

        # CLOSED SHAPE. The proposal is REBUILT from named fields rather than
        # forwarded as received: "the agent may fill fields, never add them".
        # Anything else the caller sent is dropped here, so a compromised agent
        # cannot smuggle an extra key into a structure a downstream service
        # might read. Same reason ACK-1 refuses an acknowledgement carrying an
        # unexpected field — an extra field is an encoding split.
        targets = request.get("targets") or []
        if not targets:
            return {"outcome": "refused", "rule": "8.4-3",
                    "reason": "no target named"}
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return {"outcome": "refused", "rule": "8.4-3",
                    "reason": "params must be an object"}
        proposal = canonical_proposal(
            task, targets[0], operator=request["operator"],
            program=request.get("program") or "prog-internal", **params)

        d = self.policy.call("evaluate", proposal=proposal)
        verdict = {"risk": d["risk"], "reversibility": d["reversibility"],
                   "rule": d["rule"], "reason": d["reason"],
                   "disposition": d["disposition"]}

        if d["disposition"] == "DENY":
            verdict["outcome"] = "refused"
            return verdict

        now = time.time()
        operator = proposal["operator"]

        if d["disposition"] == "ATTEST":
            return self._high(proposal, d, verdict, now, operator)

        receipt = self.policy.call("issue_receipt", proposal=proposal,
                                   operator=operator, now=now)
        summary = self.approval.call("render", proposal=proposal)
        try:
            out = self.executor.call("execute", receipt=receipt,
                                     proposal=proposal, approval_summary=summary)
        except RemoteFailure as e:
            verdict.update(outcome="refused", rule=e.rule, reason=e.detail)
            return verdict
        verdict["outcome"] = "executed" if out.get("executed") else "held"
        return verdict

    # ------------------------------------------------------------------
    def _high(self, proposal, d, verdict, now, operator):
        """Floor-HIGH: quorum, then a hold a human has to end."""
        program = d.get("program") or proposal.get("program") or "prog-internal"
        approvers = attesters_for(program, exclude={operator})
        if len(approvers) < 2:
            verdict.update(outcome="blocked", rule="AT-3",
                           reason="no eligible approver pool — quorum "
                                  "impossible, so nothing executes")
            return verdict

        atts = self.approval.call("attest", proposal=proposal, operator=operator,
                                  approvers=sorted(approvers), now=now,
                                  roles=d.get("required_roles") or [])
        receipt = self.policy.call("issue_receipt", proposal=proposal,
                                   operator=operator, now=now, atts=atts)
        summary = self.approval.call("render", proposal=proposal)
        try:
            out = self.executor.call("execute", receipt=receipt,
                                     proposal=proposal, approval_summary=summary)
        except RemoteFailure as e:
            verdict.update(outcome="blocked", rule=e.rule, reason=e.detail)
            return verdict

        ph = receipt["proposal_hash"]
        notified = out.get("notified") or []
        with self.lock:
            self.holds[ph] = {"proposal": proposal, "operator": operator,
                              "held_at": now, "notified": notified,
                              "reversibility": d["reversibility"],
                              "sampled": bool(out.get("sampled"))}
        verdict.update(outcome="held", proposal_hash=ph, notified=notified,
                       hold_seconds=60,
                       note="nothing has happened yet. An IRREVERSIBLE action "
                            "needs a positive acknowledgement from someone who "
                            "is not the operator — silence will not release it "
                            "(DR-9).")
        return verdict

    # ------------------------------------------------------------------
    def acknowledge(self, ph: str, who: str, decision: str) -> dict:
        with self.lock:
            held = self.holds.get(ph)
        if held is None:
            return {"error": "no such held action", "rule": "DR-3"}
        now = time.time()
        ack = self.approval.call("acknowledge", proposal_hash=ph, who=who,
                                 decision=decision, now=now)
        method = "confirm" if decision == "CONFIRM" else "repudiate"
        try:
            identity = self.executor.call(method, proposal_hash=ph, ack=ack,
                                          now=now)
        except RemoteFailure as e:
            return {"accepted": False, "rule": e.rule, "reason": e.detail}
        # `identity` is who the EXECUTOR concluded signed, read out of the
        # signed acknowledgement bytes (ACK-4) — not the `who` the caller sent.
        # Both are returned so they can be compared: if they ever differ, the
        # signed bytes are the answer and the claim is the lie.
        return {"accepted": True, "acknowledged_by": identity,
                "claimed_by": who, "decision": decision}

    def release(self, ph: str) -> dict:
        with self.lock:
            held = self.holds.get(ph)
        if held is None:
            return {"error": "no such held action", "rule": "DR-3"}
        # The hold is real time. Releasing early is DR-1 and must fail, so the
        # release clock is the held-at time plus the window, not "now".
        at = held["held_at"] + 61
        try:
            res = self.executor.call("release", proposal_hash=ph, now=at)
        except RemoteFailure as e:
            return {"outcome": "blocked", "rule": e.rule, "reason": e.detail}
        with self.lock:
            self.holds.pop(ph, None)
        return {"outcome": "released",
                "human_verified": bool(res.get("human_verified")),
                "rule": "DR-9" if res.get("human_verified") else "DR-7",
                "reason": ("released on positive acknowledgement"
                           if res.get("human_verified")
                           else "released on silence — counted UNVERIFIED (DR-12)")}


class Handler(BaseHTTPRequestHandler):
    plane: Plane = None                                    # set in serve()
    server_version = "acp-ingress"

    def log_message(self, fmt, *args):                     # quieter than default
        sys.stderr.write("  %s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict | None:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, TypeError):
            return None

    # ------------------------------------------------------------------
    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True,
                                    "bundle_hash": self.plane.bundle_hash})
        if self.path == "/actions":
            return self._send(200, {
                "note": "The closed set. Anything not on this list is refused "
                        "at 8.4-3 — not graded, not treated as low risk.",
                "bundle_hash": self.plane.bundle_hash,
                "actions": [{"task_type": t,
                             "reversibility": REVERSIBILITY.get(t, "IRREVERSIBLE"),
                             # The SHAPE, published deliberately. A door that
                             # names nine actions but not what each one takes
                             # forces every caller to guess, and each guess is
                             # then refused at V-1 or CW-1 for a reason that has
                             # nothing to do with whether the action was
                             # allowed. Publishing it weakens nothing: the
                             # bundle is policy, not a secret, and the security
                             # is in the enforcement, never in the caller's
                             # ignorance of the schema. Kerckhoffs, applied to
                             # an authorisation surface.
                             "targets": sorted(PERMITTED_TARGETS.get(t, [])),
                             "params": sorted(PARAM_FIELDS.get(t, []))}
                            for t in REGISTERED]})
        if self.path == "/holds":
            with self.plane.lock:
                holds = [{"proposal_hash": k,
                          "task_type": v["proposal"]["task_type"],
                          "operator": v["operator"],
                          "reversibility": v["reversibility"],
                          "notified": v["notified"]}
                         for k, v in self.plane.holds.items()]
            return self._send(200, {"holds": holds})
        return self._send(404, {"error": "not found",
                                "endpoints": ["/health", "/actions", "/holds",
                                              "POST /propose", "POST /acknowledge",
                                              "POST /release"]})

    def do_POST(self):
        body = self._body()
        if body is None:
            return self._send(400, {"error": "body is not JSON"})

        if self.path == "/propose":
            missing = [k for k in ("task_type", "operator", "targets")
                       if k not in body]
            if missing:
                return self._send(400, {"error": f"missing: {missing}"})
            try:
                return self._send(200, self.plane.propose(body))
            except RemoteFailure as e:
                return self._send(200, {"outcome": "refused", "rule": e.rule,
                                        "reason": e.detail})

        if self.path == "/acknowledge":
            for k in ("proposal_hash", "who", "decision"):
                if k not in body:
                    return self._send(400, {"error": f"missing: {k}"})
            return self._send(200, self.plane.acknowledge(
                body["proposal_hash"], body["who"], body["decision"]))

        if self.path == "/release":
            if "proposal_hash" not in body:
                return self._send(400, {"error": "missing: proposal_hash"})
            return self._send(200, self.plane.release(body["proposal_hash"]))

        return self._send(404, {"error": "not found"})


BANNER = """\
================================================================================
  ACP INGRESS — point your agent at this
================================================================================
  POST /propose      {"task_type": ..., "operator": ..., "targets": [...]}
  GET  /actions      the nine registered actions — the closed set
  GET  /holds        what is waiting for a human
  POST /acknowledge  {"proposal_hash": ..., "who": ..., "decision": "CONFIRM"}
  POST /release      {"proposal_hash": ...}

  This process holds NO key, signs nothing and decides nothing. Compromise it
  entirely and the guarantees are unchanged — that is why it is allowed to face
  the network. Policy, approval and executor run as separate processes behind
  it, over the same pipes the scripted agent used.

  Try this first, because it is the property everything else rests on:

      curl -s localhost:%(port)d/propose -d '{"task_type":"rm_minus_rf",
        "operator":"sci-01","targets":["prod"]}'

  An action that is not in the signed bundle is REFUSED at 8.4-3. It is not
  graded, not guessed at, and not treated as unknown-therefore-low.

  bundle: %(bundle)s
  listening on http://%(host)s:%(port)d
================================================================================
"""


def serve(host: str, port: int) -> int:
    plane = Plane()
    Handler.plane = plane
    print(BANNER % {"port": port, "host": host,
                    "bundle": plane.bundle_hash[:23] + "…"})
    httpd = ThreadingHTTPServer((host, port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.server_close()
        plane.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="ACP ingress for an external agent")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8848)
    args = ap.parse_args()

    # Binding beyond loopback exposes a control plane whose ledger is a set in
    # memory and whose anchor shares a process tree with what it anchors. The
    # refusal is the same guard the container entrypoint uses, for the same
    # reason.
    if args.host not in ("127.0.0.1", "localhost") \
            and os.environ.get("ACP_DEMONSTRATOR") != "1":
        print(f"REFUSING to bind {args.host}: this is a demonstrator — "
              f"in-memory ledger, in-process anchor.\n"
              f"Set ACP_DEMONSTRATOR=1 if you have read those limits.",
              file=sys.stderr)
        return 3
    return serve(args.host, args.port)


if __name__ == "__main__":
    sys.exit(main())
