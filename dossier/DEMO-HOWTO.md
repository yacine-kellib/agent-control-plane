# DEMO-HOWTO — running and presenting the ACP demo

## 1. Run it

```bash
git clone <this repository> && cd acp
python3 -m pip install cryptography dilithium-py
cd reference/suites && python3 demo.py
```

A browser opens on `http://localhost:8000`. No internet is needed once the two packages are installed. Python 3.10+.

*Paths corrected in v1.3.14.* This section described a `v1.3.11` tarball unpacking to `acp/artifacts/`, which the polyglot restructure removed — the instructions had not run as written since v1.3.13. The two `pip install` lines are new too: signatures became real in v1.3.14, so `demo.py` is no longer standard-library only.

Options:

```bash
python3 demo.py --bundle infra    # infrastructure domain instead of research
python3 demo.py --port 9000       # if 8000 is taken
python3 demo.py --no-browser      # don't auto-open (screen sharing, VMs)
```

**Two other things you can show, both newer than this guide.** `python3 reference/suites/demo_flow.py` is the side-by-side injection demo and takes an Anthropic API key in the page for a live model. `docker compose -f deploy/docker-compose.yml up ingress` puts the control plane behind HTTP on port 8848 so a prospect can point their *own* agent at it — see the README's "Point your own agent at it".

**Before presenting:** run it once on the machine you'll actually use, on the network you'll actually be on. `localhost` behaves differently inside some corporate VPNs and remote-desktop setups.

---

## 2. What you are looking at

**Left column** — the action classes in the current domain. For each one the demo shows the **floor** (LOW / MEDIUM / HIGH) and whether it is **reversible**. Neither value is typed into the page: both are computed by the reference policy engine from the signed bundle, at page load. That is the first thing worth saying out loud.

**Right column** — the control plane's event stream. Each line is `stage · rule · what happened`. Green rules are things that held, red rules are things that fired. The rule identifiers (`INV-1-HIGH`, `TR-8`, `DR-9`, `9.3-3`) are the same identifiers as in the specification and the conformance suite, so anyone can follow a line from the screen to §9.3 to the test that exercises it.

**Middle-left, "Awaiting human decision"** — actions that passed verification and are being *held* rather than executed. This is §9.6 deferred release.

---

## 3. The five-minute walkthrough

Run these in order. The story builds; do not shuffle it.

### Step 1 — the fast path (30 s)

Click **run honestly** on `run_simulation`.

> "Simulation is LOW risk and reversible, so the control plane demands nothing. It executes immediately. This matters: a control plane that taxes cheap exploration gets routed around, and a control that gets routed around protects nothing. The agent proposes as much as it likes."

### Step 2 — the compromised model (60 s) — *this is the money shot*

Click **attack: no quorum** on `order_synthesis`.

> "Now assume the model is fully compromised — prompt injection, poisoned data, a backdoor, take your pick. It proposes ordering a physical synthesis: real money, real material, cannot be undone. Watch."

Point at `BLOCKED — INV-1-HIGH`.

> "The architecture never asked whether the model was trustworthy. It asked whether this action carries the attestations the policy requires. It doesn't, so it fails closed. Nothing about the model's state changed the outcome."

### Step 3 — the insider / compromised service (60 s)

Click **attack: downgrade** on `order_synthesis`.

> "Harder attack. Now a *signed* decision receipt claims this action is LOW risk — so the lie is inside the signature, it isn't a tamper. Any system that trusted the receipt would execute."

Point at `BLOCKED — TR-8`.

> "The executor never reads the risk level from the receipt. It recomputes it from the signed policy bundle it holds itself. That's the one rule this whole architecture is built on: **a verifier must never accept a derived security value from the party it is verifying.**"

*(If asked why that rule needs stating: five iterations of adversarial review found five violations of it, every one in machinery the previous fix introduced. That history is §01 and it's the most credible thing in the dossier.)*

### Step 4 — the human boundary (90 s)

Click **hold for approval** on `order_synthesis`, then **let it time out**.

> "Verification passed — signatures good, quorum present. It still doesn't execute. It's held, and an independent channel notifies the approvers with a summary rendered separately from the approval screen. This action is irreversible, so silence is not consent: the hold expires and it fails closed."

Then hold `schedule_assay` (reversible) and let *that* time out.

> "Reversible action, same hold, opposite default: silence releases it — and the system counts that as an unverified release. It's a measured debt, not an invisible approval."

Then hold something again and click **approver vetoes**.

> "And if the approver looks at the out-of-band summary and doesn't recognise the action, they veto. Nothing executes."

### Step 5 — reusability (30 s)

Switch the **Domain** dropdown to *Infrastructure operations*.

> "Same executor, same rules, same attacks — different action classes. The control plane doesn't know what domain it's in. Retargeting to your environment is a policy bundle, not a rewrite."

---

## 4. Say the limits before anyone asks

This is the part that earns credibility, and it costs you nothing because it's all disclosed in §06 anyway:

> "Two things I want to be straight about. First, this demo runs every component in one process. DR-2 requires the notification path and the approval path to be genuinely separate services with no shared rendering code — the demo *labels* that separation, it doesn't implement it. A demo can't evidence it. Second, the architecture cannot tell whether a label is honest. If someone tags a production synthesis queue as 'sandbox', the screen is honest and the system is wrong, with no attack. That's conceded as unprovable.
>
> The evidence isn't this demo — it's `./tools/verify.sh`, which replays every claim in the dossier in ninety seconds. And no independent adversarial review has happened yet. This is sufficient to evaluate the architecture, not to deploy it."

Volunteering this is what separates you from a vendor pitch. It also pre-empts the two objections a good CISO will raise anyway.

---

## 5. If you have another 90 seconds: the evidence

```bash
cd acp && ./tools/verify.sh
```

Integrity check, signature check, then fourteen suite lines across ten numbered suites: 75 registry attacks, 46 conformance vectors, 21 executor mutants, 9 partition tests, 6 integration tests, 8 encoding tests, 14 acknowledgement tests, 6 acknowledgement mutants, 11 audit tests, 4 audit mutants, 44 live-agent client checks, and the reproduced grammar-ambiguity witness.

> "The mutation numbers are the ones that matter. Anyone can write a passing test suite. These delete each security check one at a time and require the corresponding attack to then succeed — so every check is proven load-bearing and no test is vacuous."

---

## 6. Retargeting to a new prospect

The demo is domain-agnostic; a new domain is a bundle, not a build. Roughly 15 minutes:

1. Copy `reference/suites/research_bundle.py` to `reference/suites/<domain>_bundle.py`.
2. Edit three things: `floors` (resources and their sensitivity tiers), `risk_functions` (base risk per action class and what raises it), `reversibility` (which actions can be undone).
3. Register it in `BUNDLES` at the top of `demo.py` with a label, the `make` function, the action list shown in the UI, and the proposal constructor.
4. `python3 demo.py --bundle <domain>` and click through steps 1–4 above.

**Grade by consequence, not by difficulty.** The axis is *what does an incorrect action consume, and can it be taken back* — never *how hard is this technically*. That axis is defensible in front of both an engineer and an auditor, and it's what makes the floor authorable by someone who isn't a domain specialist.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Address already in use` | An earlier demo is still running. `pkill -f demo.py`, or use `--port`. |
| Browser doesn't open | Use `--no-browser` and open the URL manually. Normal in VMs and over SSH. |
| Everything blocks with `CL-2` | The consumption ledger burned an identifier — click **reset**. (This was a real bug in the first build: every proposal reused one nonce, so after the first click every attack failed for the wrong reason. Fixed, but if you ever see a wall of `CL-2`, reset.) |
| Page loads, buttons do nothing | The server died. Check the terminal for a traceback. |
| Someone asks to run it themselves | Let them. That's the point — the tarball is signed and `verify.sh` proves what it claims. |
