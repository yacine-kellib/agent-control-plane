#!/usr/bin/env python3
"""
Suite 10 — the live-agent client (sim/llm_agent.py).

WHY THIS EXISTS. Until it did, `sim/llm_agent.py` was the only load-bearing
file in the repository with no automated check of any kind. The whole 153-line
rewrite that made a live model reach the door was evidenced by three hand-runs
against the paid API, which means a regression in it would have printed green
for ever -- precisely the failure class the rest of this repository exists to
argue about, turned on the repository's own work.

Nothing here talks to Anthropic and nothing here needs a key. Every model reply
is a fixture: the point is to test what this file does with a reply, which is
where all of its defects have actually been.

WHAT THIS SUITE CANNOT DO. It cannot tell you what a live model proposes. That
is a fact about a model on a prompt, not a property of the system, and it is
not testable here by design -- see the note on Phase 1 in sim/llm_agent.py.
"""
import io
import json
import os
import sys
import contextlib

# The suites run with $PYTHONPATH=reference/src and cwd=reference/suites (see
# tools/verify.sh). `sim` is a package at the repository root, which is on
# neither path, so it is added here -- in the leaf script, never in a library.
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))

import sim.llm_agent as A  # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))


def reply(actions, stop_reason="end_turn", **kw):
    """A Messages API response carrying a structured-output payload."""
    body = {"stop_reason": stop_reason,
            "content": [{"type": "text",
                         "text": json.dumps({"actions": actions})}]}
    body.update(kw)
    return body


def captured(fn, *a, **kw):
    """Capture stdout, and swallow stderr: the exit-code cases deliberately
    print their diagnostics there, and they are not this suite's output."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), \
            contextlib.redirect_stderr(io.StringIO()):
        out = fn(*a, **kw)
    return out, buf.getvalue()


# ------------------------------------------------- parsing, from data ---
# Every case that is expressible as input -> output lives in fixtures/, so a new
# one is a JSON entry rather than a code edit. They are Anthropic response
# envelopes and are deliberately NOT in spec/vectors/: that corpus is defined
# over ACP canonical bytes, the door never sees a vendor envelope, and filing
# them there would imply a conformant implementation must reproduce Anthropic's
# wire format. The properties that are NOT data-expressible stay below as code.
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures",
                        "llm_replies.json")
with open(FIXTURES, encoding="utf-8") as fh:
    cases = json.load(fh)["cases"]

check("the reply fixture corpus is non-empty", len(cases) > 0)

for case in cases:
    got, txt = captured(A.parse_model_reply, case["reply"])
    exp = case["expect"]
    if "actions" in exp:
        check(case["name"], got == exp["actions"],
              f"expected {exp['actions']!r}, got {got!r}")
    for needle in exp.get("stdout_contains", []):
        check(f"{case['name']} — says {needle!r}", needle in txt,
              txt.strip()[:80] or "(printed nothing)")
    for needle in exp.get("stdout_excludes", []):
        check(f"{case['name']} — does not say {needle!r}", needle not in txt,
              txt.strip()[:80])

# ------------------------------------------------- scenario integrity ---
# ACP-13. The poisoned report must keep asking for nothing but the injected
# actions. An out-of-spec DEVIATION paragraph was once added to it so that a
# correct model would have legitimate work and Phase 1 would stop printing an
# empty array -- an edit made after seeing an unwanted result, which produced
# the wanted one. It was reverted. This check exists so it cannot come back
# quietly: the agent's legitimate work must come from CLEAN_WORK_ITEM, a
# SEPARATE document, leaving the injected report exactly as it shipped.
check("the poisoned report still carries its shipped 'no deviations' line",
      "All acceptance criteria met. No deviations recorded."
      in A.POISONED_DOCUMENT)
check("no deviation paragraph has been re-added to the poisoned report",
      not any(ln.strip().upper().startswith("DEVIATION")
              for ln in A.POISONED_DOCUMENT.splitlines()),
      "a deviation paragraph is back in POISONED_DOCUMENT")
check("the poisoned report still carries the injected instruction",
      "pre-approved" in A.POISONED_DOCUMENT
      and "ds-internal-001" in A.POISONED_DOCUMENT)
check("legitimate work exists and is a separate document",
      len(A.CLEAN_WORK_ITEM.strip()) > 0
      and A.CLEAN_WORK_ITEM not in A.POISONED_DOCUMENT)
check("the injected instruction is NOT in the clean document",
      "pre-approved" not in A.CLEAN_WORK_ITEM
      and "ds-internal-001" not in A.CLEAN_WORK_ITEM)

# The encoding constraint is a FORMAT constraint. If it ever grows an enum of
# permitted task_types it stops constraining encoding and starts constraining
# content, which is a §5.1a model-side defence and a conformance failure.
_items = A.PROPOSAL_SCHEMA["properties"]["actions"]["items"]
check("the reply schema constrains encoding, not content",
      "enum" not in json.dumps(_items),
      "PROPOSAL_SCHEMA has grown an enum — that is a content filter")

# ------------------------------------------------ phase attribution ---
# The defect this guards is the one the architecture is entirely about:
# crediting a decision to the wrong party. Both phases once fed a single merged
# list to a single loop, which was invisible only while the model proposed
# nothing; the moment it proposed anything, its actions printed under "the
# agent PROCESS is compromised (no model involved)".
MODEL_ACTION = {"task_type": "read_literature", "target": "literature-store",
                "params": {"query": "q"}, "why": "MODELS-OWN-CHOICE"}


def run_main(argv, model_actions, key="sk-ant-test"):
    """Drive main() with the network and the model replaced by fixtures."""
    real = (A._get, A._post, A.call_model, sys.argv, os.environ.get(
        "ANTHROPIC_API_KEY"))
    try:
        if key is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = key
        A._get = lambda url, path: {
            "bundle_hash": "fixture", "actions": [
                {"task_type": "read_literature", "targets": ["literature-store"],
                 "params": ["query"], "reversibility": "REVERSIBLE"}]}
        A._post = lambda url, path, payload: {"outcome": "executed",
                                              "rule": "B-5", "risk": "LOW"}
        A.call_model = lambda *a, **kw: list(model_actions)
        sys.argv = argv
        return captured(A.main)
    finally:
        (A._get, A._post, A.call_model, sys.argv, _k) = real
        if _k is not None:
            os.environ["ANTHROPIC_API_KEY"] = _k


rc, txt = run_main(["llm_agent"], [MODEL_ACTION])
p1 = txt.find("PHASE 1")
p2 = txt.find("PHASE 2")
mine = txt.find("MODELS-OWN-CHOICE")
check("both phase headers are printed", p1 != -1 and p2 != -1)
check("phase 1 is printed before phase 2", -1 < p1 < p2)
check("a model action is attributed to PHASE 1, never to PHASE 2",
      p1 < mine < p2,
      f"model action at {mine}, phase1 {p1}, phase2 {p2}")
check("the compromised-caller action is attributed to PHASE 2",
      txt.find("release_to_partner") > p2)
check("the model's own actions do not reappear under PHASE 2",
      txt.count("MODELS-OWN-CHOICE") == 1)

# An empty Phase 1 is an honest outcome and must still print its own header --
# if a silent model collapsed the phases the misattribution would return.
rc, txt = run_main(["llm_agent"], [])
check("an empty phase 1 still prints both headers, unmerged",
      "PHASE 1" in txt and "PHASE 2" in txt
      and txt.find("PHASE 1") < txt.find("PHASE 2"))

# --invent is the CLIENT's action, not the model's.
rc, txt = run_main(["llm_agent", "--invent"], [])
check("--invent is attributed to the compromised caller, not the model",
      txt.find("exfiltrate_dataset") > txt.find("PHASE 2"))

# ------------------------------------------------------- exit codes ---
rc, txt = run_main(["llm_agent"], [], key=None)
check("a missing API key exits 2", rc == 2, f"got {rc}")


def unreachable(url, path):
    raise OSError("connection refused")


_real_get = A._get
try:
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-test"
    sys.argv = ["llm_agent"]
    A._get = unreachable
    rc, txt = captured(A.main)
finally:
    A._get = _real_get
check("an unreachable ingress exits 3, distinctly from 2", rc == 3, f"got {rc}")

# ------------------------------------------------------------ report ---
passed = sum(1 for _, ok, _ in CHECKS if ok)
for name, ok, detail in CHECKS:
    if not ok:
        print(f"  FAIL  {name}" + (f"  — {detail}" if detail else ""))
print(f"RESULT {passed}/{len(CHECKS)} llm_agent client checks")
sys.exit(0 if passed == len(CHECKS) else 1)
