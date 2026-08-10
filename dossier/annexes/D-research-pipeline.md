# Annex D — Worked example: action control in an agentic research pipeline

**Status:** illustrative, non-normative. Companion to ACP-SPEC-001 v1.3.11.
**Executable:** `python3 artifacts/research_bundle.py`

> **What this is not.** This annex describes no organisation's internal architecture and claims no knowledge of one. It is built from publicly known characteristics of AI-driven discovery workflows, by an author who does not work in the field. The action classes, tiers and thresholds below are a *method* applied to a domain, not a recommendation for anyone's pipeline — a real deployment must re-derive every value with the scientists and risk owners who own the consequences. Where the domain reasoning is wrong, the mapping is wrong; the control-plane properties are not affected, because they do not depend on the domain being modelled correctly.

---

## D.1 Why this domain

Most agentic deployments have a weak version of the problem this architecture addresses: the actions are reversible, cheap, and their consequences are legible within minutes. §01 says plainly that most agents should *not* work this way, because the overhead is unjustifiable for low-consequence work.

Research automation is one of the cases where the narrow claim actually bites:

- **Actions consume things that do not come back.** Instrument time, reagent, a synthesis run. An erroneous action is not rolled back; it is *paid for*.
- **The proposing component is exactly the kind of thing that should not hold authority.** A predictive model is superb at generating candidates and has no standing whatsoever to authorise the commitment of physical resources to one. This is not a criticism of the model — it is the same reason a scientist does not approve their own procurement.
- **The governance answer already exists socially and is unenforced mechanically.** Review boards, sign-offs, separation of duties, audit trails: the domain has all of it, in process. What it typically lacks is a mechanism that makes it *impossible* for an automated agent to route around, rather than merely against policy.
- **Consequence is legible to a non-specialist.** A reviewer who cannot judge a binding affinity can still judge whether an action spends material that cannot be un-spent. That legibility is what makes a risk floor authorable at all.

The last point deserves emphasis, because it determines the grading axis. **Actions are not graded by how difficult the science is. They are graded by what an incorrect action consumes and whether it can be taken back.** That is the only axis a control plane can act on, and it is the axis a policy author can defend in front of both a scientist and an auditor.

---

## D.2 The action classes

Produced by the policy engine from `artifacts/research_bundle.py`, not written by hand:

| Action | Target | Floor | Reversible | What the control plane demands |
|---|---|---|---|---|
| `run_simulation` | compute-cluster (T0) | LOW | yes | nothing — fast path |
| `read_dataset` | compute-cluster (T0) | LOW | yes | nothing — fast path |
| `register_candidate` | candidate-registry (T2) | MEDIUM | yes | policy evaluation, audited |
| `schedule_assay` | assay-queue (T2) | **HIGH** | yes | bound quorum + hold; releases on silence |
| `consume_reagent` | reagent-inventory (T3) | **HIGH** | **no** | bound quorum + **positive acknowledgement** |
| `order_synthesis` | synthesis-queue (T3) | **HIGH** | **no** | bound quorum + **positive acknowledgement** |
| `release_to_partner` | external-partner (T3) | **HIGH** | **no** | bound quorum + **positive acknowledgement** |

Three design points are worth naming, because each of them is a place where this kind of design usually goes wrong.

**The fast path is genuinely fast.** Simulation and reads carry no floor, no attestation and no hold. This is B-5, and it is not a concession — a control plane that taxes exploration gets routed around, and a control that gets routed around provides nothing. Unbounded proposing is the *point* of putting a model in the loop; the architecture constrains what a proposal can become, not how many there are.

**Reversibility is a separate axis from consequence.** `schedule_assay` is HIGH but reversible (cancellable up to a cutoff), so it holds and releases on silence. `consume_reagent` is HIGH and irreversible, so silence is not consent — it requires a positive acknowledgement from a party who is not the operator, and times out closed. Collapsing these two axes into one number is the common error, and it produces either a system that blocks reversible work or one that lets irreversible work through on a timeout.

**The unclassified default is IRREVERSIBLE.** A new action type nobody has graded yet is treated as the most demanding case until someone grades it. The fail-safe direction matters more than any individual entry in the table, because the table will always be incomplete.

---

## D.3 What the architecture guarantees here

A model that has been fully compromised — by prompt injection through a poisoned literature corpus, by training-data poisoning, by a backdoor — can emit `order_synthesis` against `synthesis-queue` continuously. **It cannot cause one to execute.** The floor is recomputed by the Executor from the signed policy bundle, never read from the proposal or the receipt; and INV-1-HIGH requires a fresh, single-use, quorum-satisfying set of attestations cryptographically bound to that action's canonical hash.

Run `python3 artifacts/research_bundle.py --attacks` for four attacks expressed in this domain's action classes: an uncompromised quorum requirement (`INV-1-HIGH`), a *signed* receipt downgrading a synthesis order to LOW (`TR-8`, recomputation), a receipt claiming a partner release is reversible (`RV-3`), and an ungraded action type defaulting to the strict case (`RV-1`). All four fail closed on the same rules that fire in the reference suite.

**A correction worth recording**, since this dossier's discipline is to publish these rather than quietly fix them: an earlier draft of this annex claimed the 44 conformance vectors could be replayed unchanged by swapping the bundle. That is false — the fixtures construct proposals with `modify_firewall_rule` / `fw.v1`, which do not exist here, so 34 vectors error on unknown task types rather than passing. The invariance that actually holds is of the **control plane**, not of the fixtures: the same rules fire, on the same recomputed values, against different action classes. Attacks must be re-expressed per domain; the mechanism is not re-derived.

The corresponding threat-model position: injection and poisoning stay explicitly *out of scope* (`AML.T0051`, `AML.T0054`, `AML.T0020`, `AML.T0018`). The architecture assumes they succeed. What it constrains is the step from a successful manipulation to an executed action.

---

## D.4 What it does not guarantee — and where the residuals bite hardest in this domain

**A-7 / RR-2, label honesty — the sharpest limit here.** The system guarantees that a resource labelled T3 triggers attestation. It cannot know whether the label is true. A synthesis queue mislabelled `compute-cluster`, or a reagent action typed as `run_simulation`, defeats the design with no attack at all: the screen is honest and faithfully displays an action the system believes is free. In a research pipeline where action types are added continuously as instrumentation evolves, **label drift is the realistic failure, not a clever adversary.** Disposition: RK-5 two-person offline control on every downgrade, plus drift detection between declared label and observed behaviour. That converts prevention into detection — a real reduction, not a closure.

**A-8, display fidelity.** A compromised presentation service gets a scientist to sign, in good faith, an order they never intended. Deferred release raises this from one compromise to two (independent notification path, veto window). But that independence is an organisational and code-structure property — two services, two repositories, no shared formatting library — and it is *auditable, not provable*. It is the same **kind** of assumption as A-7. Suite 2 already caught an implementation that looked independent and was not.

**T-26, notification habituation — the one to worry about operationally.** A control whose default outcome equals its approved outcome teaches its users to skip it. In a lab where approvals arrive constantly, this is not a hypothesis. And RES-2 composes: an availability attack on the anchoring service saturates approvers, and the predictable outcome of saturation is not refusal but rubber-stamping. AU-6 (implemented in v1.3.11) breaks that specific composition by suspending sampling during an outage; the general problem remains and is **the residual most deserving of measurement in a real deployment.**

**RR-1, independent adversarial review: absent.** No party without authorship history has reviewed this. Every fix after DS-6 is mechanized and tested and unconfirmed. This annex is sufficient to evaluate an approach. It is not sufficient to deploy one.

---

## D.5 How a deployment would actually start

Not with enforcement. With **detect-only**: run the control plane alongside the existing pipeline, evaluate every agent action, log what *would* have been blocked, and change nothing. Detect-only costs no availability and immediately answers the question that matters most — how often is the floor wrong, and how often is the label wrong — which is A-7 meeting reality for the first time. Enforcement follows per action class, irreversible classes first, once the floors have been argued about by the people who own the consequences.

---

*Annex D is illustrative and carries no conformance weight. The normative specification is ACP-SPEC-001 §§6–15; the residuals are §06; the reproduction instructions are §07.*
