# 01 — Executive summary

## I. Why this architecture exists

### The model is not defective. It is the wrong kind of thing to trust.

The premise underneath this entire design is easy to state and easy to misread: **a language model must never be a source of authority.**

That is not a complaint about model quality, and it does not get better as models improve. A language model is a probabilistic function over token sequences. It has no representational distinction between an instruction and a datum — both are text in the same context window, and "authority" is not a property it can carry, because nothing in its architecture marks one span of tokens as binding and another as merely observed. Asking a model to be trustworthy in the security sense is a **category error**, not an engineering shortfall. You are asking for a guarantee from a system whose output is a distribution.

This matters because it changes what the fix has to look like. If the problem were quality, the answer would be a better model. Because the problem is *kind*, no amount of capability closes it.

### Prompt injection is not a vulnerability class. It is a structural consequence.

Instructions and data share a channel. Every system built that way has had this problem, and the industry has met it repeatedly: format strings, SQL injection, cross-site scripting, macro viruses. In each case the durable fix was never better sanitisation of the shared channel — sanitisation is an arms race the defender loses at the margin — it was **separating the channels** so that content could no longer be promoted to control.

Parameterised queries did not make SQL injection harder. They made it *structurally impossible* for data to become a statement. ACP makes the same move one layer up: the model's output is never an instruction to anything. It is a proposal, in a typed and closed grammar, which is then evaluated against policy the model never sees and cannot influence.

This is why §02 of the threat model states plainly that prompt injection is **out of scope by design** rather than claiming to defend against it. The architecture assumes the injection succeeds. A successful injection produces, at best, a well-formed proposal — subject to exactly the same evaluation as a legitimate one.

### Why not fix the model instead?

Two reasons, and the second is the one that survives scrutiny.

**First, statistical systems do not produce guarantees.** A guardrail that holds 99.9% of the time is not a security property when the adversary chooses the input. The adversary is not sampling from your distribution; they are searching for the tail. Defences that are trained rather than constructed can be optimised against, and the attacker's optimisation is cheaper than the defender's retraining.

**Second, and more fundamentally: even a perfect model would not help.** The security question is not "did the model intend this action?" — it is "is this action authorised?" That is a question about policy, capability, tier, quorum and provenance. It is not a question the model has standing to answer, however good it is, any more than a well-meaning employee has standing to approve their own expense claim. Authority does not come from sincerity. **A perfectly aligned model still cannot be the authority on its own authorisation**, because authorisation is a property of the system's rules, not of the requester's intentions.

Once that is seen, alignment work and this work stop competing. Alignment reduces how often the model *wants* the wrong thing. This architecture makes it irrelevant whether it does.

### Why not use a model to check the model?

This is the most common alternative in shipped products — LLM-as-judge, model guardrails, a second model reviewing the first's output — and it deserves a direct answer rather than a dismissal.

**It does not change the trust class.** A second model is another component of the same kind. The verifier inherits the failure mode of the verified: the same instruction/data conflation, the same absence of any representational marker for authority, the same inability to produce a guarantee. You now hold two components with the property you were trying to escape, arranged so that one of them is called "the control."

**Their failures are correlated, which is worse than it sounds.** Defence in depth pays only when failures are independent. Two models typically share architecture, tokenizer, training distribution and post-training lineage. An input crafted to defeat one has a materially elevated chance of defeating the other — not by coincidence, but because they learned the same regularities. You pay for two checks and receive somewhere between one and two, with no way to measure where you landed.

This dossier contains a small, concrete instance of that exact error. DR-2 requires the notification channel to share no rendering code with the approval channel, because *two channels sourced from one renderer are one channel wearing two hats*. The mutation suite caught a version of that check which looked independent and was not (§05, Suite 2). The LLM-judge pattern is the same mistake at model scale, and it is harder to see precisely because the two models are visibly different programs.

**The judge is attacked through the channel it is obliged to read.** A judge must ingest the content it judges, and that content is attacker-influenced. You have granted the adversary write access to the reviewer's context window. This is not a hardened form of prompt injection; it is prompt injection with one additional required step.

**The regress has to terminate.** Who checks the checker? Either the chain ends at an unverified model, or it grounds out in something deterministic. If it must ground out in something deterministic anyway, put that thing at the boundary that matters and drop the intermediate hop — which otherwise adds latency, cost and attack surface while terminating nothing.

**Statistical checks are not conformance-testable in the adversarial case.** Every claim in §05 rests on mutation testing: delete a check, and the corresponding attack must succeed. That works because deterministic checks have a definite behaviour to remove. There is no equivalent for "the judge correctly recognised this as malicious" — you can measure a rate on a benchmark, but the adversary is not sampling from your benchmark. A control you cannot write a falsifying test for cannot carry an invariant.

**A model cannot be party to a quorum.** Attestation requires accountability: a distinct identity, a revocable capability, a signature someone stands behind, and — under AT-2 — distinctness from the operator. None of these are properties a model instance has. Adding a model "approver" to a quorum does not raise the bar; it dilutes a mechanism whose entire value is that each element is separately answerable.

**Note what this makes provable.** ACP's policy engine is a deliberately minimal, total, monotone expression language — no loops, no user functions, no regex — because that is what permits `FloorDominance` and order-independence to be mechanised at all (Annex B). Replace it with a model and there is nothing left to prove: not because the model would necessarily be wrong, but because "prove" stops being an available verb.

**What models are legitimately good for here.** This is not a dismissal of LLM judges. They are genuinely useful for triage, ranking, volume reduction, catching sloppy non-adversarial failures, and drafting — and §8.4's own B-5 goes further, instructing implementations to prefer the model-free path whenever a task is expressible without inference, because the model is a cost and a risk, never a default.

ACP does not forbid a model inside the control plane. It forbids a model from being **load-bearing for authorisation**. A model that reduces ten thousand proposals to the hundred worth evaluating is doing useful work. A model that says "this action is safe, execute it" is the category error again: it is being asked for authority, and authority is not a thing it can hold.

### Capability growth widens the gap, it does not close it

The instinct is that better models make control planes less necessary. The opposite holds. A more capable model is entrusted with more consequential actions — that is what capability *means* in deployment. The stakes rise on a substrate that still offers no guarantee. Assurance does not scale with capability; it scales with the effort spent constructing it. So the interval between what we let agents do and what we can demonstrate about them widens with every generation.

That interval is what this document is about.

### The inversion

The design move is old and it is not ours: **do not make the agent trustworthy; make its trustworthiness unnecessary.**

This is the same principle behind least privilege, capability systems, and separation of duties. It replaces a question you cannot answer — *is this component honest?* — with one you can — *what can this component do if it is not?* The architecture then commits to a single, testable claim:

> **INV-1-HIGH — no single compromised component can cause a high-impact action to execute without a fresh, single-use, quorum-satisfying set of attestations bound to that action's canonical hash.**

Note the shape of that sentence. It does not say the system is safe. It says what must be true simultaneously for it to fail, and every clause is mechanically checkable. **A claim that can be falsified is worth more than an assurance that cannot** — which is precisely the difference between this and a statement that a model has been trained not to misbehave.

### What this costs, stated honestly

Assurance is bought with expressiveness. The agent can only take actions someone specified in advance as a typed class, with a risk function and a tier floor. That forecloses the open-endedness which is the entire promise of agentic systems.

The claim is therefore **not** that all agents should work this way. Most should not — the overhead is unjustifiable for reversible, low-consequence work, and §8.4 deliberately keeps that path fast. The claim is narrower and, we think, harder to argue with: **where a mistake cannot be undone, the authority to act must not rest on a probabilistic component, however good it has become.**

### The principle that kept being violated, including by us

One rule generalises everything above:

> **A verifier must never accept a derived security value from the party it is verifying.**

Five iterations of adversarial review found five violations of that rule — every one in machinery the previous fix had introduced, and two of them inside the proof artifacts written to enforce it. That history is in §II below, and it is the strongest evidence in this dossier for a claim we would otherwise be making about ourselves: this principle is easy to state, genuinely hard to hold, and **only mechanical enforcement keeps it.**

---

## II. What was built, and what is known about it

### The mechanism

The Executor believes nothing. It **recomputes**.

It receives the action proposal independently, hashes it itself, recomputes the risk level from the signed policy it holds, reconstructs the exact bytes the human approvers signed, and checks that those bytes name **this** action. Any disagreement fails closed.

Every input consumed for a control decision is classified: **recomputed** by the consumer, **cryptographically bound** to something it already holds, or **trusted as transmitted**. The third class is the only one that produces vulnerabilities. The dossier records zero undisclosed instances (`02b-CLASSIFICATION-TABLE.md`), and shipping that table is now a conformance requirement — because the mechanical version of the classification found a critical defect that three narrative reviews had missed.

### Verification status

| Dimension | Result |
|-----------|--------|
| Mechanized proofs (Dafny 4.9.1 / Z3 4.12.1) | **36 verified, 0 errors** |
| Mutation controls on the proofs | **9/9 kill** |
| Conformance suite | **50/50** — 42 attacks fail closed, 8 honest paths execute |
| Implementation mutation testing | **24/24 kill** — every check is load-bearing |
| Ledger partition semantics | **9/9** — CL-6 holds |
| Executor × distributed ledger integration | **6/6** |
| Canonical CBOR encoding | **8/8** |
| Audit, anchoring, accumulators (AC-5/AU-6/AU-7/AU-8) | **11/11**, mutants **4/4** |

The mutation controls are what give the rest its weight: a passing test suite proves nothing until you show it can fail. Every check was deleted one at a time, and the corresponding attack must then succeed.

### Defect history — the most revealing item in this dossier

```
C2  → the risk value was trusted                 → fixed: recomputation
X1  → the derived value was trusted              → fixed: recomputation enforced
Y1  → the attestation↔action binding was trusted → fixed: verify from signed bytes
Z3  → the origin identifier was trusted          → fixed: ledger-pinned
W1  → the counter tracked decisions, not executions → fixed: count at release
```

Two further defects were found in the proof artifacts themselves and are disclosed (tautological postconditions, a non-covering mutant).

**What this says:** the architecture has a named, identified defect signature, now mandated as a conformance artifact. **What it also says:** after five iterations the reasonable inference is not that no defects remain, but that they are in the most recent fixes.

### Regulatory posture

Hybrid post-quantum signatures mandatory on every path (Ed25519 + ML-DSA-65, FIPS 204), per the French ANSSI hybridation doctrine. Composition is **conjunctive** — both signatures must verify — proven mechanically, including its converse: a disjunctive composition would be *weaker* than either primitive alone.

Cost measured rather than assumed: **13.2 kB of signatures per high-impact receipt (four signers) versus 256 B classical, a 53× increase**, and tens of milliseconds of verification on a pure-Python reference implementation. Both figures are emitted by `reference/src/acp_crypto.py`; each deployment must publish its own.

### The decision this dossier supports

It is sufficient to evaluate the architecture. It is **not** sufficient to deploy it: the independent adversarial review required by suite 11 has not happened (**RR-1**), and every fix after DS-6 is mechanized but unconfirmed by a third party. See §06.
