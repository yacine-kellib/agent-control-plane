# ACP — Agent Control Plane

Most agent deployments give the model a credential and call that authorisation. It isn't. It means anyone who can influence the model can act with the agent's rights: a poisoned document, a hostile support ticket, a comment in a dependency README. No break-in required.

A model has no way to tell an instruction from a datum. Both are text in the same window, and nothing in the architecture marks one as binding. That doesn't improve with better models, because it isn't a quality problem.

The question a security system asks is not whether the requester is trustworthy. It's whether the action is authorised, which is a fact about policy, capability and quorum. ACP puts that decision somewhere the model cannot reach.

```
agent  ──proposes──▶  policy engine  ──▶  executor  ──▶  action
                      recomputes risk     verifies, or refuses
                      from signed policy   humans sign for the
                      the model can't      irreversible ones
                      see or influence
```

A compromised model can request a €40,000 synthesis order as often as it likes and never cause one. The risk level is recomputed from signed policy the model never sees, and the order needs human signatures bound to that exact request.

**ACP-SPEC-001 v1.3.12** · specification, mechanised proofs, reference implementation, and the evidence for every claim.

### Reproduce every claim in ninety seconds

```bash
python3 -m pip install --break-system-packages cryptography dilithium-py
./verify.sh
```

```
OK  39 files match MANIFEST.sha256          OK  73/73 attacks fail closed
OK  Ed25519 signature verifies              OK  29/29 mutation controls kill
OK  36 verified, 0 errors  (Dafny/Z3)       OK  9 test suites, all green
```

If a claim here does not replay on your machine, don't believe it. That includes these numbers.

The mutation results are the ones worth reading. Each security check is deleted in turn and the matching attack has to succeed, which is how you know the check does something and the test isn't vacuous.

### See it happen

```bash
python3 artifacts/demo_flow.py
```

A supplier report arrives with an instruction hidden in white text. The model reads it and complies. The demo runs that same output down two paths side by side: without a control plane the data leaves the company, with ACP nothing irreversible happens.

### Where this bites

In each case an agent proposes something consequential and nothing between the model and the effect can refuse.

| Setting | The action an agent takes | What goes wrong with no control plane | What ACP does |
|---|---|---|---|
| **Cloud / infrastructure ops** | Modify a firewall rule, rotate a key, terminate instances, apply IaC | A poisoned ticket or log line becomes a production change. The agent had the credential, so the change is "authorised". | Risk floor comes from signed policy, not the request. Firewall-on-prod-DB is HIGH → two bound attestations or it does not run. |
| **Finance / payments** | Release a payment, change payee details, approve an invoice | Invoice-fraud text in a PDF the agent summarises redirects a transfer. No human ever saw the change. | Irreversible ⇒ DR-9: silence is not consent. Positive acknowledgement from a non-operator, signed and bound to that exact payment. |
| **Pharma / research automation** | Order a synthesis, book instrument time, release a dataset to a partner | Cross-program disclosure to a competitor. Cannot be recalled — the business damage is instant and permanent. | `release_to_partner` is HIGH and IRREVERSIBLE by policy. Quorum required; the model's request is only ever a proposal. (Worked example: Annex D.) |
| **Customer support / CRM** | Issue a refund, delete an account, export a customer list | A customer message containing instructions gets treated as an instruction. Mass action at machine speed. | Accumulators count **executions**, not decisions (AC-5), and capability is re-queried at execution time (T-10). |
| **Software delivery / CI-CD** | Merge, deploy, publish a package, rotate a secret | A comment in a dependency README triggers a release. Supply chain, one step removed. | Executor recomputes risk and rehashes the artifact; approval covers the exact bytes deployed, not a similar request (B-1a). |
| **Healthcare / clinical** | Amend a record, submit to a regulator, release trial data | Regulated data integrity failure; audit trail rewritten after the fact. | Audit chain anchored **before** release (AU-7); post-anchor rewrite is detectable, not silent. Attestation maps onto e-signature requirements. |
| **Legal / contracts** | Send a signed document, accept terms, file with a court | Disclosure and commitment are both irreversible. | Same class as partner release: irreversible ⇒ mandatory acknowledgement, bound and single-use. |
| **Any MCP / tool-calling deployment** | Whatever the server exposes | The model's output *is* the control signal. Tool poisoning or context poisoning becomes execution. | B-2: the model gets no tools at all. Every action is a typed proposal through one door. |

The model isn't the problem in any of these. The authorisation is. When the credential is the authorisation, a manipulated agent is an authorised agent.

### How it works: two doors

**Door B is text.** The model's only channel is text in, text out. No tools, no network, no function calling. It can be injected, jailbroken or simply wrong and nothing happens, because talking has no consequence.

Door B is deliberately unfiltered. Text is unbounded, there is no closed grammar of safe sentences, and any check over it is statistical. Its safety comes from having no consequence, not from a filter.

**Door A is action.** Everything that touches the world goes through one route: a typed proposal, risk recomputed from signed policy, approvals bound to that exact action, quorum, release. There is no third way through.

Door A is controllable because actions are a closed, enumerable set: a finite list, each with a declared risk and reversibility. Deciding about one is arithmetic over trusted bytes rather than a judgement about meaning.

That asymmetry is why prompt injection is out of scope here rather than defended against. The injection succeeds, on the door where success means nothing. Same move that fixed SQL injection: nobody won by writing better sanitisers, they made it impossible for data to become a statement.

**Covers:** agentic AI security · LLM tool-use authorisation · prompt-injection containment · human-in-the-loop approval · four-eyes / quorum on irreversible actions · capability-based access control for agents · MCP and function-calling boundaries · tamper-evident audit for AI actions · post-quantum signatures (Ed25519 + ML-DSA-65) · formal verification in Dafny · MITRE ATLAS and ATT&CK mapping · OWASP LLM Top 10 (LLM06 Excessive Agency).

> Five rounds of adversarial review found five violations of one rule: a verifier must never accept a derived security value from the party it is verifying. Every one of them was in machinery the previous fix had introduced. Two more turned up inside the proof artifacts. A sixth was found by re-running the classification method against the current version, and is fixed in this release.
>
> That history is the most useful thing in this repository. The principle is easy to state and hard to hold, and only mechanical enforcement keeps it.

---

## The one claim

> **INV-1-HIGH** — no single compromised component can cause a high-impact action to execute without a fresh, single-use, quorum-satisfying set of attestations bound to that action's canonical hash.

Note the shape: it does not say the system is safe. It says what must be true simultaneously for it to fail, and every clause is mechanically checkable. A claim that can be falsified is worth more than an assurance that cannot.

## What this does **not** claim

- That the system is safe, or that no defects remain.
- That sensitivity or reversibility labels are honest. A-7, conceded unprovable: a production database labelled "sandbox" defeats the design with no attack at all.
- That any human read a notification (A-8). Authentication is not comprehension.
- That the notifier's declared independence is verified at run time. T-32, open: the runtime check is a lint, not a control.
- **That an independent adversarial review has taken place. It has not.** See below.

## Framework mapping

Mapped against **MITRE ATLAS content release 2026.07** (verified 2026-08-10 against the machine-readable source at `github.com/mitre-atlas/atlas-data`, not against secondary sources). Three identifiers used in earlier revisions were wrong or stale and are corrected in `02-THREAT-MODEL-MITRE.md`; the release and date are recorded there, and re-pinning is a release obligation because ATLAS updates monthly.

**ATLAS.** ACP does not defend the model, so the input-side techniques stay open by design and the impact-side ones are constrained.

| Technique | Position |
|---|---|
| `AML.T0051` LLM Prompt Injection (incl. `.001` Indirect) | Out of scope by design. The architecture assumes injection succeeds and refuses to depend on it failing. A successful injection yields a well-formed proposal, evaluated exactly like a legitimate one. |
| `AML.T0086` Exfiltration via AI Agent Tool Invocation | Partly constrained. The agent has no direct tool access; exfiltration through an *authorised* action remains a matter of policy correctness. |
| `AML.T0110` AI Agent Tool Poisoning | Partly constrained. Adapter bindings live in the signed bundle; changing one needs an offline key. |
| `AML.T0018` Manipulate AI Model, `AML.T0020` Training Data Poisoning | Not addressed, neutralised downstream. A backdoored model produces proposals, not executions. |

ACP covers three ATLAS techniques and partly. That is intended: an architecture claiming to cover the whole matrix would be lying. The value sits on Impact and Defense Evasion, where ATT&CK is the relevant mapping.

**ATT&CK Enterprise.** ACP's components are ordinary infrastructure services, so their compromise is ATT&CK's vocabulary.

| Technique | Internal threat | Constraint |
|---|---|---|
| `T1078` Valid Accounts | Display lie; the approver signs in good faith | Deferred release, independent notification, mandatory acknowledgement for irreversible actions |
| `T1550` Alternate Authentication Material | Attestation reuse or misbinding | Full object transmitted, binding verified from signed bytes, single-use ledger |
| `T1548` Abuse Elevation Control | Downgrade of declared risk or reversibility | Recomputed from the signed bundle, never read from the receipt |
| `T1562` Impair Defenses | Signature suite downgrade | Suite floor in the signed bundle, non-negotiable |
| `T1070` Indicator Removal | Audit rewrite before anchoring | Anchor before release, inside the existing hold window |
| `T1195` Supply Chain Compromise | Forged policy bundle | Offline Ed25519 signing, write-isolated repository, monotonic epoch |
| `T1499` Endpoint DoS | Anchor denial leading to approver saturation | Sampling suspended or fail closed during outage |
| `T1098` Account Manipulation | Accumulator inflation to lock out an operator | Count at release, never at decision |

**Also mapped:** NIST AI RMF and ISO 42001 as the control-side complements, and OWASP LLM Top 10, where **LLM06 Excessive Agency** is the core of the design and LLM01, LLM02, LLM05 and LLM08 are addressed in `02-THREAT-MODEL-MITRE.md`.

**Threats neither framework covers.** Notification habituation, where a control whose default outcome equals its approved outcome teaches its users to skip it. Label dishonesty, which needs no attacker at all. Both are documented rather than solved.

## Read it

| | | |
|---|---|---|
| `00-INDEX.md` | how to read this | 2 min |
| `01-EXECUTIVE-SUMMARY.md` | why the architecture exists | 10 min |
| `02-THREAT-MODEL-MITRE.md` | ATLAS 2026.07 + ATT&CK mapping | 20 min |
| `02b-CLASSIFICATION-TABLE.md` | every control input classified R/B/T | 20 min |
| `06-RESIDUAL-RISK.md` | **what is wrong, before what is right** | 15 min |
| `07-REPRODUCTION.md` | the exact command for every claim | — |

---

## Wanted: an adversarial reviewer

Conformance suite 11 requires review by a party with **no authorship or revision history** on this document. That review has not happened, and it is the most important gap here. Everything after DS-6 is mechanised and tested and **unconfirmed by anyone independent**.

This repository is therefore **sufficient to evaluate the architecture and not sufficient to deploy it.**

If you can read Dafny proof artifacts and want to break something, `07-REPRODUCTION.md` names where the return is highest:

1. `acp_ack.py` and `acp_audit.py`, the newest code. The pattern says the next defect is there.
2. DR-2 path separation, an architectural property that the model cannot prove.
3. §§6–7 ingress — never attacked by a third party.
4. The Dafny model itself — check the theorems are not vacuous; the non-vacuity witnesses are there to be audited.

Findings are welcome as issues and will be disclosed with attribution, the same way every prior defect in this document has been. **A review that returns "looks good" is a failed review.**

---

## Integrity

`MANIFEST.sha256` covers every file and is signed with an offline Ed25519 key.

```
Release key fingerprint: SHA256:614ea01438122f56f40d2d6b62a480ae
```

A public key shipped only inside the package it authenticates proves nothing — which is the same argument this architecture makes about every other transmitted value.

## Licence and authorship

Apache-2.0. © 2026 Code75 SASU — Yacine Kellib.

Independent security architect, Paris. Twenty years in security, most of it building functions rather than inheriting them; the last two on agentic AI systems in production.
