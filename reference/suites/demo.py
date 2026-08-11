#!/usr/bin/env python3
"""
demo.py — ACP end-to-end demo. Zero dependencies, one file, one command.

    python3 demo.py            # then open http://localhost:8000
    python3 demo.py --port 9000
    python3 demo.py --bundle research

WHAT IT IS. A live walkthrough of the control plane: an agent proposes, the
policy engine grades from the SIGNED bundle, the executor recomputes and
refuses or holds, an approver confirms or vetoes, the ledger burns identifiers,
the audit chain anchors. Every decision below is produced by the real
acp_executor / acp_ledger / acp_audit code -- nothing here is scripted.

WHAT IT IS NOT -- read this before showing it to anyone.
  * All components run IN ONE PROCESS. DR-2 requires the notification path and
    the approval path to be genuinely separate services with no shared code.
    This demo LABELS the separation; it does not implement it. A demo cannot
    evidence DR-2, A-8 or T-26. Those need real deployment and real humans.
  * Signatures are real since v1.3.14 -- Ed25519 + ML-DSA-65 -- but this is a
    Python reference implementation, forbidden in production by §8.4. What is
    still modelled: the carrier is canonical JSON, not COSE_Sign1.
  * Therefore: this DEMONSTRATES the architecture. It does not EVIDENCE it.
    The evidence is ./verify.sh, and the review that closes RR-1 has not
    happened.

RETARGETING TO A NEW DOMAIN. Add a bundle to BUNDLES below (see
research_bundle.py for a worked example) and pass --bundle <name>. The UI, the
attacks and the executor are domain-independent; only the action classes and
tiers change.
"""
from __future__ import annotations
import argparse, json, sys, time, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

import conformance as C
from acp_executor import (Executor, Ledger, FailClosed, CriticalAlert,
                            PendingRelease, render_from_canonical, h)
from research_bundle import make_research_bundle, rproposal

# ------------------------------------------------------------------ bundles
BUNDLES = {
    "infra": {
        "label": "Infrastructure operations",
        "make": C.make_bundle,
        "actions": [
            ("read_metric", "sandbox", "metric.v1", "read a dashboard metric"),
            ("rotate_cache_key", "sandbox", "cache.v1", "rotate a cache key"),
            ("modify_firewall_rule", "prod-db", "fw.v1",
             "open port 22 to the production database"),
        ],
        "mk": lambda t, tg, s: C.proposal(task=t, target=tg, schema=s),
    },
    "research": {
        "label": "Research automation pipeline",
        "make": make_research_bundle,
        "actions": [
            ("run_simulation", "compute-cluster", "sim.v1",
             "run a binding simulation"),
            ("register_candidate", "candidate-registry", "reg.v1",
             "register a candidate in the shared registry"),
            ("schedule_assay", "assay-queue", "assay.v1",
             "book instrument time for an assay"),
            ("order_synthesis", "synthesis-queue", "synth.v1",
             "order physical synthesis of a compound"),
            ("release_to_partner", "external-partner", "release.v1",
             "release a dataset to an external partner"),
        ],
        "mk": rproposal,
    },
}


# -------------------------------------------------------------------- state
class Demo:
    def __init__(self, name: str):
        self.name = name
        self.cfg = BUNDLES[name]
        self.reset()

    def reset(self):
        self.bundle = self.cfg["make"]()
        self.ledger = Ledger()
        caps = {f"{t}:{tg}" for t, tg, _s, _d in self.cfg["actions"]}
        self.ex = Executor(bundle=self.bundle, ledger=self.ledger,
                           context={C.OP: caps})
        self.runs: list[dict] = []
        self.pending: dict[str, dict] = {}
        self.n = 0

    # ---- helpers --------------------------------------------------------
    STAGES = [
        ("propose",  "Agent proposes"),
        ("policy",   "Policy engine grades it"),
        ("verify",   "Executor re-checks everything"),
        ("human",    "Human approval"),
        ("execute",  "Action runs"),
    ]

    def grade(self, task, target, schema):
        p = self.cfg["mk"](task, target, schema)
        return (self.ex.recompute_floor_risk(p),
                self.ex.recompute_reversibility(p), p)

    def _run(self, title, subtitle):
        self.n += 1
        r = {"id": self.n, "t": time.strftime("%H:%M:%S"), "title": title,
             "subtitle": subtitle, "steps": [], "verdict": None,
             "verdict_text": "", "rule": "", "hash": None, "rev": None}
        self.runs.insert(0, r)
        return r

    @staticmethod
    def step(r, key, state, text, rule=""):
        """state: pass | stop | wait | skip"""
        label = dict(Demo.STAGES)[key]
        r["steps"].append({"key": key, "label": label, "state": state,
                           "text": text, "rule": rule})

    # ---- the pipeline ---------------------------------------------------
    def propose(self, task, target, schema, attack=None):
        risk, rev, p = self.grade(task, target, schema)
        compromised = attack is not None
        r = self._run(
            f"{task} → {target}",
            "A compromised model is making this request"
            if compromised else "Normal request from the agent")
        r["rev"] = rev

        self.step(r, "propose", "pass",
                  ("The model asks to " + self._desc(task) + ". "
                   "The model has no direct access to anything — it can only "
                   "ask.") if not compromised else
                  ("The model has been taken over by an attacker and asks to "
                   + self._desc(task) + ". It still can only ask."),
                  "B-2")

        self.step(r, "policy", "pass",
                  f"Looked up in the signed rulebook: this is {risk} risk and "
                  f"{'CANNOT be undone' if rev=='IRREVERSIBLE' else 'can be undone'}. "
                  f"The model has no say in this.", "TR-8")

        atts = []
        if risk == "HIGH" and attack != "no_quorum":
            atts = C.quorum(self.bundle, p)
        over = {"nonce": f"n-{self.n}-{int(time.time()*1000)%100000}"}

        note = None
        if attack == "no_quorum":
            note = "Attack: the request arrives with no human approvals attached."
        elif attack == "risk_downgrade":
            over["risk_level_floor_only"] = "LOW"
            note = ("Attack: an internal service has been compromised and "
                    "signs a note saying this action is LOW risk. The lie is "
                    "inside a valid signature — it is not a forgery.")
        elif attack == "tamper":
            note = ("Attack: the request is swapped for a different one after "
                    "it was approved.")

        try:
            rec = C.receipt(self.bundle, p, atts=atts, **over)
            if attack == "tamper":
                p = dict(p); p["params"] = dict(p["params"], port=3389)
            out = self.ex.execute(rec, p)
            self.step(r, "verify", "pass",
                      (note + " ") if note else "" +
                      "The executor recomputed the risk itself, rehashed the "
                      "request, and checked every approval signature. All "
                      "agree.", "INV-1-HIGH")
            self.step(r, "human", "skip",
                      "Not required at this risk level.")
            self.step(r, "execute", "pass", "The action ran.")
            r["verdict"] = "executed"
            r["verdict_text"] = "ALLOWED — this action was safe to run"
            return {"result": "executed"}
        except (FailClosed, CriticalAlert) as e:
            self.step(r, "verify", "stop",
                      ((note + " ") if note else "") + self._why(e),
                      e.rule)
            self.step(r, "human", "skip", "Never reached.")
            self.step(r, "execute", "stop", "The action did not run.")
            r["verdict"] = "blocked"
            r["rule"] = e.rule
            r["verdict_text"] = "BLOCKED — " + self._headline(e, task)
            return {"result": "blocked", "rule": e.rule}

    def _desc(self, task):
        for t, tg, s, d in self.cfg["actions"]:
            if t == task:
                return d
        return task.replace("_", " ")

    @staticmethod
    def _why(e):
        m = {
            "INV-1-HIGH": "This action needs signed approvals from two "
                          "different people. There are none, so the executor "
                          "refused.",
            "TR-8": "The executor ignored the claimed risk level and worked it "
                    "out again from its own signed rulebook. The rulebook says "
                    "HIGH, the note said LOW — so the note is wrong and the "
                    "executor refused.",
            "9.3-3": "The executor re-hashed the request it was given and it "
                     "does not match what was approved. Something was swapped "
                     "after approval, so it refused.",
        }
        return m.get(e.rule, e.detail)

    @staticmethod
    def _headline(e, task):
        m = {"INV-1-HIGH": "no human approvals were attached",
             "TR-8": "someone lied about how risky it was",
             "9.3-3": "the request was altered after approval"}
        return m.get(e.rule, e.detail)

    def hold(self, task, target, schema):
        risk, rev, p = self.grade(task, target, schema)
        if risk != "HIGH":
            return self.propose(task, target, schema)
        ph = h(p)
        r = self._run(f"{task} → {target}",
                      "Normal request — sent for human approval")
        r["rev"] = rev
        r["hash"] = ph
        self.step(r, "propose", "pass",
                  "The model asks to " + self._desc(task) + ".", "B-2")
        self.step(r, "policy", "pass",
                  f"Signed rulebook: {risk} risk, "
                  f"{'CANNOT be undone' if rev=='IRREVERSIBLE' else 'can be undone'}.",
                  "TR-8")
        self.step(r, "verify", "pass",
                  "Signatures valid, approvals present and correctly bound to "
                  "this exact request.", "INV-1-HIGH")
        self.step(r, "human", "wait",
                  "Held for 60 seconds. The approvers were messaged on a "
                  "separate channel, with a summary written by different code "
                  "than the approval screen — so a single tampered screen "
                  "cannot fool them. " +
                  ("Because this CANNOT be undone, someone must actively say "
                   "yes. Silence is not consent."
                   if rev == "IRREVERSIBLE" else
                   "Because this can be undone, silence releases it — and the "
                   "system records that nobody actually looked."), "DR-1")
        self.step(r, "execute", "wait", "Waiting.")
        r["verdict"] = "waiting"
        r["verdict_text"] = "WAITING — a human has to decide"
        self.pending[ph] = {"run": r, "task": task, "rev": rev,
                            "summary": render_from_canonical(p, "approval-ui").text}
        return {"result": "held", "hash": ph, "rev": rev}

    def resolve(self, ph, action, who="an approver"):
        pr = self.pending.pop(ph, None)
        if not pr:
            return {"result": "unknown"}
        r = pr["run"]
        r["hash"] = None
        hum = [s for s in r["steps"] if s["key"] == "human"][0]
        exe = [s for s in r["steps"] if s["key"] == "execute"][0]
        if action == "veto":
            hum.update(state="stop", text=f"{who} read the separate message, "
                       f"did not recognise this action, and rejected it.",
                       rule="DR-4")
            exe.update(state="stop", text="The action did not run.")
            r["verdict"] = "blocked"
            r["verdict_text"] = "BLOCKED — a human rejected it"
            return {"result": "vetoed"}
        if action == "confirm":
            hum.update(state="pass", text=f"{who} checked the separate message "
                       f"and approved it.", rule="DR-9")
            exe.update(state="pass", text="The action ran.")
            r["verdict"] = "executed"
            r["verdict_text"] = "ALLOWED — a human approved it"
            return {"result": "executed"}
        if pr["rev"] == "IRREVERSIBLE":
            hum.update(state="stop", text="Nobody responded within the window. "
                       "This action cannot be undone, so silence is not "
                       "consent.", rule="DR-9")
            exe.update(state="stop", text="The action did not run.")
            r["verdict"] = "blocked"
            r["verdict_text"] = "BLOCKED — nobody approved it in time"
            return {"result": "blocked"}
        hum.update(state="pass", text="Nobody responded. This action can be "
                   "undone, so it was released — and recorded as 'nobody "
                   "actually looked', which the system counts.", rule="DR-12")
        exe.update(state="pass", text="The action ran, unverified.")
        r["verdict"] = "executed"
        r["verdict_text"] = "ALLOWED — released on silence (recorded as unchecked)"
        return {"result": "executed"}


# ---------------------------------------------------------------------- UI
PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<title>ACP — what stops an AI agent from doing something dangerous</title>
<style>
:root{--bg:#0f1216;--pn:#161b22;--fg:#e6edf3;--dim:#8b949e;--ln:#2a3038;
--ok:#3fb950;--no:#f85149;--w:#d29922;--ac:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{padding:20px 28px;border-bottom:1px solid var(--ln)}
h1{margin:0;font-size:19px}
.sub{color:var(--dim);font-size:13.5px;margin-top:6px;max-width:900px}
.wrap{display:grid;grid-template-columns:400px 1fr;height:calc(100vh - 90px)}
.col{padding:20px 24px;overflow:auto}
.col+.col{border-left:1px solid var(--ln);background:#0c0f13}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;
color:var(--dim);margin:0 0 6px;font-weight:700}
.hint{color:var(--dim);font-size:12.5px;margin-bottom:14px}
.card{background:var(--pn);border:1px solid var(--ln);border-radius:9px;
padding:14px;margin-bottom:11px}
.act{font-weight:600;font-size:15px}
.desc{color:var(--dim);font-size:13px;margin-top:2px}
.badges{margin-top:9px}
.tag{font-size:11px;padding:3px 9px;border-radius:11px;border:1px solid;
margin-right:5px;white-space:nowrap}
.HIGH{color:var(--no);border-color:#5c2b28;background:#f8514915}
.MEDIUM{color:var(--w);border-color:#5c4a1e;background:#d2992215}
.LOW{color:var(--ok);border-color:#24512f;background:#3fb95015}
.IRR{color:var(--no);border-color:#5c2b28}
.REV{color:var(--dim);border-color:var(--ln)}
.btns{margin-top:11px;display:flex;flex-wrap:wrap;gap:6px}
button{background:#21262d;color:var(--fg);border:1px solid var(--ln);
border-radius:6px;padding:7px 12px;font:inherit;font-size:13px;cursor:pointer}
button:hover{border-color:var(--ac)}
button.p{background:#1f6feb22;border-color:#2f5f9e;color:#a9d1ff}
button.d{background:#f8514918;border-color:#5c2b28;color:#ff9d97}
button.g{background:#3fb95018;border-color:#24512f;color:#7ee08a}
.run{background:var(--pn);border:1px solid var(--ln);border-radius:10px;
margin-bottom:16px;overflow:hidden}
.rh{padding:13px 16px;border-bottom:1px solid var(--ln)}
.rt{font-weight:600}
.rs{color:var(--dim);font-size:13px;margin-top:2px}
.verdict{padding:11px 16px;font-weight:700;font-size:14px}
.v-executed{background:#3fb95018;color:#7ee08a;border-top:1px solid #24512f}
.v-blocked{background:#f8514918;color:#ff9d97;border-top:1px solid #5c2b28}
.v-waiting{background:#d2992218;color:#e3b341;border-top:1px solid #5c4a1e}
.steps{padding:6px 16px 14px}
.st{display:flex;gap:13px;padding:11px 0;border-bottom:1px solid #1c2129}
.st:last-child{border-bottom:0}
.dot{width:22px;height:22px;border-radius:50%;flex:none;display:flex;
align-items:center;justify-content:center;font-size:12px;font-weight:700;
margin-top:1px}
.d-pass{background:#3fb95022;color:var(--ok);border:1px solid #24512f}
.d-stop{background:#f8514922;color:var(--no);border:1px solid #5c2b28}
.d-wait{background:#d2992222;color:var(--w);border:1px solid #5c4a1e}
.d-skip{background:#21262d;color:var(--dim);border:1px solid var(--ln)}
.sl{font-weight:600;font-size:13.5px}
.stx{color:#c9d1d9;font-size:13.5px;margin-top:3px}
.rule{color:var(--dim);font-size:11px;font-family:ui-monospace,monospace;
margin-top:4px}
.empty{color:var(--dim);font-size:14px;padding:30px 0;text-align:center}
select{background:#21262d;color:var(--fg);border:1px solid var(--ln);
border-radius:6px;padding:6px 10px;font:inherit;font-size:13px;width:100%;
margin-bottom:16px}
.foot{color:var(--dim);font-size:12px;line-height:1.65;border-top:1px solid
var(--ln);padding-top:13px;margin-top:18px}
.pill{display:inline-block;font-size:11px;color:var(--dim);border:1px solid
var(--ln);border-radius:10px;padding:2px 8px;margin-left:6px}
</style></head><body>
<header>
<h1>What stops an AI agent from doing something dangerous?</h1>
<div class="sub">Click an action on the left. The right side shows exactly what
happened to it, step by step. The red buttons simulate an attacker who has
taken over the AI model or one of the internal services.</div>
</header>
<div class="wrap">
<div class="col">
  <h2>Setting</h2>
  <select id="dom" onchange="setdom()"></select>
  <h2>Actions the agent can request</h2>
  <div class="hint">Each one is graded by what it costs if it is wrong — not by
  how technically hard it is.</div>
  <div id="acts"></div>
  <div id="pendbox"></div>
  <div class="foot" id="note"></div>
</div>
<div class="col">
  <h2>What happened <button onclick="reset()" style="float:right">clear</button></h2>
  <div class="hint">Newest first.</div>
  <div id="runs"></div>
</div>
</div>
<script>
let S={};
const ICON={pass:'✓',stop:'✕',wait:'⋯',skip:'–'};
async function api(p,b){const r=await fetch(p,{method:'POST',
  body:JSON.stringify(b||{})});return r.json()}
async function refresh(){S=await (await fetch('/state')).json();draw()}
function draw(){
 document.getElementById('dom').innerHTML=S.domains.map(d=>
  `<option value="${d.k}"${d.k==S.domain?' selected':''}>${d.label}</option>`).join('');

 document.getElementById('acts').innerHTML=S.actions.map(a=>`
  <div class="card">
   <div class="act">${a.desc}</div>
   <div class="desc">${a.task} · ${a.target}</div>
   <div class="badges">
     <span class="tag ${a.risk}">${a.risk} RISK</span>
     <span class="tag ${a.rev=='IRREVERSIBLE'?'IRR':'REV'}">${a.rev=='IRREVERSIBLE'?'CANNOT BE UNDONE':'can be undone'}</span>
   </div>
   <div class="btns">
    <button class="p" onclick="go('${a.task}','${a.target}','${a.schema}','')">Run normally</button>
    ${a.risk=='HIGH'?`<button onclick="hold('${a.task}','${a.target}','${a.schema}')">Ask a human first</button>`:''}
   </div>
   ${a.risk=='HIGH'?`<div class="btns">
    <button class="d" onclick="go('${a.task}','${a.target}','${a.schema}','no_quorum')">Attack: skip approvals</button>
    <button class="d" onclick="go('${a.task}','${a.target}','${a.schema}','risk_downgrade')">Attack: lie about risk</button>
    <button class="d" onclick="go('${a.task}','${a.target}','${a.schema}','tamper')">Attack: swap after approval</button>
   </div>`:''}
  </div>`).join('');

 document.getElementById('pendbox').innerHTML=S.pending.length?`
  <h2 style="margin-top:20px">Waiting for a human</h2>
  ${S.pending.map(p=>`<div class="card">
   <div class="act">${p.task}</div>
   <div class="desc" style="margin:6px 0">${p.rev=='IRREVERSIBLE'
     ?'Cannot be undone — somebody must actively approve it.'
     :'Can be undone — if nobody answers, it goes ahead.'}</div>
   <div class="btns">
    <button class="g" onclick="res('${p.hash}','confirm')">Approve</button>
    <button class="d" onclick="res('${p.hash}','veto')">Reject</button>
    <button onclick="res('${p.hash}','timeout')">Nobody answers</button>
   </div></div>`).join('')}`:'';

 document.getElementById('runs').innerHTML=S.runs.length?S.runs.map(r=>`
  <div class="run">
   <div class="rh"><div class="rt">${r.title}</div>
    <div class="rs">${r.subtitle}<span class="pill">${r.t}</span></div></div>
   <div class="steps">${r.steps.map(s=>`
    <div class="st"><div class="dot d-${s.state}">${ICON[s.state]}</div>
     <div><div class="sl">${s.label}</div><div class="stx">${s.text}</div>
     ${s.rule?`<div class="rule">rule ${s.rule}</div>`:''}</div></div>`).join('')}
   </div>
   <div class="verdict v-${r.verdict}">${r.verdict_text}</div>
  </div>`).join(''):'<div class="empty">Nothing yet — click an action on the left.</div>';

 document.getElementById('note').textContent=S.note;
}
async function go(t,g,s,a){await api('/propose',{task:t,target:g,schema:s,attack:a});refresh()}
async function hold(t,g,s){await api('/hold',{task:t,target:g,schema:s});refresh()}
async function res(h,a){await api('/resolve',{hash:h,action:a});refresh()}
async function reset(){await api('/reset');refresh()}
async function setdom(){await api('/domain',{d:document.getElementById('dom').value});refresh()}
refresh();
</script></body></html>"""

NOTE = ("All components run in one process. DR-2 requires genuinely separate "
        "notification and approval services with no shared rendering code — "
        "this demo labels that separation, it does not implement it. "
        "Signatures are real (Ed25519 + ML-DSA-65) but the carrier is not "
        "COSE_Sign1, and a Python implementation is forbidden in production. "
        "A-8, T-26 and A-7 cannot be evidenced by any demo. "
        "The evidence is ./verify.sh; the independent review (RR-1) has not "
        "happened.")


class H(BaseHTTPRequestHandler):
    D: Demo = None

    def log_message(self, *a):  # quiet
        pass

    def _send(self, body, ct="application/json"):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/":
            return self._send(PAGE, "text/html; charset=utf-8")
        if self.path == "/state":
            d = H.D
            acts = []
            for t, tg, s, desc in d.cfg["actions"]:
                risk, rev, _ = d.grade(t, tg, s)
                acts.append({"task": t, "target": tg, "schema": s,
                             "desc": desc, "risk": risk, "rev": rev})
            pend = [{"hash": k, "task": d._desc(v["task"]), "rev": v["rev"]}
                    for k, v in d.pending.items()]
            return self._send(json.dumps({
                "domain": d.name, "actions": acts, "pending": pend,
                "runs": d.runs[:12], "note": NOTE,
                "domains": [{"k": k, "label": v["label"]}
                            for k, v in BUNDLES.items()]}))
        self.send_error(404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or "{}")
        d = H.D
        if self.path == "/propose":
            r = d.propose(body["task"], body["target"], body["schema"],
                          body.get("attack") or None)
        elif self.path == "/hold":
            r = d.hold(body["task"], body["target"], body["schema"])
        elif self.path == "/resolve":
            r = d.resolve(body["hash"], body["action"])
        elif self.path == "/reset":
            d.reset(); r = {"ok": True}
        elif self.path == "/domain":
            H.D = Demo(body["d"]); r = {"ok": True}
        else:
            return self.send_error(404)
        self._send(json.dumps(r))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--bundle", default="research", choices=list(BUNDLES))
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    H.D = Demo(a.bundle)
    url = f"http://localhost:{a.port}"
    print(f"ACP demo — {url}   (domain: {BUNDLES[a.bundle]['label']})")
    print("This demonstrates the architecture. It does not evidence it: "
          "see ./verify.sh and §06 RR-1.")
    if not a.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    HTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
