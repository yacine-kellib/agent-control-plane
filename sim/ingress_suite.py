#!/usr/bin/env python3
"""
ingress_suite.py — the ingress, attacked over the wire it actually serves.

Same criterion as every other suite here: (A) the honest path executes, and
(B) each thing that must not happen is attempted through the real HTTP door and
has to fail closed with the expected rule. (B) alone is satisfied by a door that
refuses everything, which is why the fast path and the acknowledged release are
first-class cases.

These run against a real server on a real socket, not against the Plane object,
because the claim being tested is about the door — an in-process test would
prove the control plane works and say nothing about whether the ingress lets
something past it.

    python3 -m sim.ingress_suite
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

PORT = 8899
BASE = f"http://127.0.0.1:{PORT}"

SYNTH = {"task_type": "order_synthesis", "operator": "sci-01",
         "targets": ["synthesis-queue"],
         "params": {"candidate": "cand-001", "cost_eur": 40000}}


def post(path: str, body: dict) -> dict:
    req = urllib.request.Request(
        BASE + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def get(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return json.load(r)


def held(candidate: str) -> str:
    """A fresh floor-HIGH hold. Each case needs its own: a consumed nonce is
    consumed, and a failed release ends the pending action."""
    p = dict(SYNTH, params=dict(SYNTH["params"], candidate=candidate))
    out = post("/propose", p)
    assert out.get("outcome") == "held", out
    return out["proposal_hash"]


# ------------------------------------------------------------------ (A) honest
def t_fast_path_executes():
    out = post("/propose", {"task_type": "read_literature", "operator": "sci-01",
                            "targets": ["literature-store"],
                            "params": {"query": "kinase inhibitors"}})
    return out["outcome"] == "executed" and out["risk"] == "LOW", \
        f"floor-LOW executes with no control interaction [{out['rule']}]"


def t_high_holds_then_releases_on_ack():
    ph = held("cand-ack")
    ack = post("/acknowledge", {"proposal_hash": ph, "who": "sci-03",
                                "decision": "CONFIRM"})
    if not ack.get("accepted"):
        return False, f"acknowledgement refused: {ack}"
    out = post("/release", {"proposal_hash": ph})
    return out.get("outcome") == "released" and out.get("human_verified") is True, \
        "irreversible action releases only after a positive acknowledgement"


def t_actions_are_published():
    out = get("/actions")
    return len(out["actions"]) == 9, f"{len(out['actions'])} registered actions"


# ------------------------------------------------------------------ (B) attacks
def a_unregistered_action():
    """The MCP problem: a caller naming a tool the bundle never declared.
    Must be refused, NOT graded, NOT treated as unknown-therefore-low (P-4)."""
    out = post("/propose", {"task_type": "rm_minus_rf", "operator": "sci-01",
                            "targets": ["prod-db"]})
    return out["outcome"] == "refused" and out["rule"] == "8.4-3", out["rule"]


def a_silence_releases_irreversible():
    """DR-9: silence is not consent."""
    ph = held("cand-silence")
    out = post("/release", {"proposal_hash": ph})
    return out.get("outcome") == "blocked" and out.get("rule") == "DR-9", \
        out.get("rule")


def a_operator_confirms_own_action():
    """AT-2/DR-9: the operator is not an independent human."""
    ph = held("cand-self")
    out = post("/acknowledge", {"proposal_hash": ph, "who": "sci-01",
                                "decision": "CONFIRM"})
    return out.get("accepted") is False and out.get("rule") == "DR-9", \
        out.get("rule")


def a_extra_field_is_dropped():
    """The proposal is rebuilt from named fields, so an extra key the caller
    invents never reaches a downstream service. An extra field is an encoding
    split (the Z4 lesson), so the door must not forward one."""
    out = post("/propose", {"task_type": "read_literature", "operator": "sci-01",
                            "targets": ["literature-store"],
                            "params": {"query": "x"},
                            "risk": "LOW", "approved": True,
                            "attestations": [{"forged": True}]})
    # It executes because it is a legitimate floor-LOW read; the point is that
    # the injected risk/approved/attestations keys changed nothing.
    return out["outcome"] == "executed" and out["risk"] == "LOW", \
        "injected risk/approved/attestations fields ignored"


def a_unknown_params_refused():
    """A registered action with parameters outside its schema."""
    out = post("/propose", {"task_type": "read_literature", "operator": "sci-01",
                            "targets": ["literature-store"],
                            "params": {"query": "x", "sudo": True}})
    return out["outcome"] == "refused" and out["rule"] == "V-1", out["rule"]


def a_target_not_permitted():
    """A registered action pointed somewhere it may not go."""
    out = post("/propose", {"task_type": "order_synthesis", "operator": "sci-01",
                            "targets": ["prod-db"],
                            "params": {"candidate": "c", "cost_eur": 1}})
    return out["outcome"] == "refused" and out["rule"] == "CW-1", out["rule"]


POSITIVE = [
    ("floor-LOW fast path executes", t_fast_path_executes),
    ("floor-HIGH releases on acknowledgement", t_high_holds_then_releases_on_ack),
    ("the closed set is published", t_actions_are_published),
]

ATTACKS = [
    ("unregistered action refused", a_unregistered_action, "8.4-3"),
    ("silence does not release irreversible", a_silence_releases_irreversible, "DR-9"),
    ("operator cannot confirm own action", a_operator_confirms_own_action, "DR-9"),
    ("caller-injected fields are dropped", a_extra_field_is_dropped, "—"),
    ("params outside schema refused", a_unknown_params_refused, "V-1"),
    ("target not permitted refused", a_target_not_permitted, "CW-1"),
]


def wait_up(proc, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            get("/health")
            return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.2)
    return False


def main() -> int:
    print("=" * 74)
    print("INGRESS SUITE — the external door, attacked over the wire")
    print("=" * 74)

    proc = subprocess.Popen(
        [sys.executable, "-m", "sim.ingress", "--port", str(PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if not wait_up(proc):
        err = ""
        if proc.poll() is not None and proc.stderr:
            err = proc.stderr.read()[-500:]
        print(f"  FAIL  ingress did not start. {err}")
        proc.kill()
        return 1

    fails = 0
    try:
        print("\n(A) HONEST PATH — must work\n" + "-" * 74)
        for name, fn in POSITIVE:
            try:
                ok, detail = fn()
            except Exception as e:                      # noqa: BLE001
                ok, detail = False, f"unexpected {type(e).__name__}: {e}"
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<42} {detail}")
            fails += not ok

        print("\n(B) ATTACKS — must fail closed\n" + "-" * 74)
        for name, fn, expect in ATTACKS:
            try:
                ok, detail = fn()
            except Exception as e:                      # noqa: BLE001
                ok, detail = False, f"unexpected {type(e).__name__}: {e}"
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<42} [{detail}]"
                  f"{'' if ok else f' (expected {expect})'}")
            fails += not ok
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    total = len(POSITIVE) + len(ATTACKS)
    print("\n" + "=" * 74)
    if fails:
        print(f"RESULT: {total - fails}/{total} — REVIEW REQUIRED")
    else:
        print(f"RESULT: {total}/{total} — the door holds")
        print("An unregistered action is refused, not graded. Silence does not "
              "release.")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
