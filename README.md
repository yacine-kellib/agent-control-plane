# ACP — Agent Control Plane

**Two doors.**

**Door B is text.** The model talks, is injected, is jailbroken — and nothing happens, because talk is inert. B-2 gives it no tools, no network egress, no function calling, no channel but text-in/text-out. Door B is unconstrained *by design*, and it has to be: text is unbounded, there is no closed grammar of safe sentences, and any filter on it would be statistical. Its safety comes from having no consequence, not from any check.

**Door A is action.** Anything that reaches the world passes through it, and there is no third route: a typed proposal, risk recomputed from signed policy, attestations bound to that exact action, quorum, release.

Door A is controllable precisely because actions are a **closed, typed, enumerable** set. That asymmetry is the whole design — and it is why prompt injection is out of scope rather than defended against. Injection succeeds, on the door where success means nothing.

This specification is Door A.

**ACP-SPEC-001 v1.3.12** · specification, mechanised proofs, reference implementation, and the evidence for every claim.

> Five iterations of adversarial review found five violations of one rule — *a verifier must never accept a derived security value from the party it is verifying* — and **every one was in machinery the previous fix had introduced.** Two more were found inside the proof artifacts. A sixth was found by re-running the classification method against the current version, and is fixed here.
>
> That history is the most useful thing in this repository. The principle is easy to state, genuinely hard to hold, and only mechanical enforcement keeps it.

---

## Reproduce everything in ninety seconds

```bash
python3 -m pip install --break-system-packages cryptography dilithium-py
./verify.sh
```

Integrity, manifest signature, the Dafny proofs, and every test suite. **If a claim in this repository does not replay on your machine, it should not be believed** — including these.

```
OK  38 files match MANIFEST.sha256
OK  detached signature verifies against release-key.pub
OK  36 verified, 0 errors                          (Dafny 4.9.1 / Z3 4.12.1)
OK  73/73 consolidated attack registry
OK  19/19 + 4/4 + 6/6 mutation controls
OK  9/9 partition · 6/6 integration · 8/8 encoding · 11/11 audit · 14/14 acknowledgement
```

The mutation numbers are the ones that matter. A passing test suite proves nothing until you show it can fail: every security check is deleted one at a time and the corresponding attack must then succeed.

---

## The problem

A language model must never be a source of authority. Not because models are bad — because "authority" is not a property a probability distribution can carry. It has no representational distinction between an instruction and a datum; both are text in the same context window. Asking a model to be trustworthy in the security sense is a category error, and it does not improve as models improve.

Prompt injection is not a vulnerability class, it is a structural consequence of instructions and data sharing a channel. The industry has met this before — format strings, SQL injection, XSS, macro viruses — and the durable fix was never better sanitisation. It was **separating the channels** so content could not be promoted to control. Parameterised queries did not make SQL injection harder; they made it structurally impossible for data to become a statement.

ACP makes the same move one layer up. The model's output is never an instruction. It is a **proposal**, in a typed and closed grammar, evaluated against policy the model never sees and cannot influence.

**Prompt injection is out of scope by design.** The architecture assumes the injection succeeds. A successful injection produces, at best, a well-formed proposal — subject to exactly the same evaluation as a legitimate one.

## The one claim

> **INV-1-HIGH** — no single compromised component can cause a high-impact action to execute without a fresh, single-use, quorum-satisfying set of attestations bound to that action's canonical hash.

Note the shape: it does not say the system is safe. It says what must be true simultaneously for it to fail, and every clause is mechanically checkable. A claim that can be falsified is worth more than an assurance that cannot.

## What this does **not** claim

- That the system is safe, or that no defects remain.
- That sensitivity or reversibility labels are honest — **A-7, conceded unprovable.** A production database labelled "sandbox" defeats the design with no attack at all.
- That any human read a notification — **A-8.** Authentication is not comprehension.
- That the notifier's declared independence is verified at run time — **T-32, open.** The runtime check is a lint, not a control.
- **That an independent adversarial review has taken place. It has not** — see below.

## Try it

```bash
python3 artifacts/demo_flow.py       # a poisoned document, with and without the control plane
python3 artifacts/attack_registry.py -i   # browse all 73 attacks, with explanations
python3 artifacts/attack_registry.py --coverage   # and what nothing covers
```

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

1. `acp_ack.py` and `acp_audit.py` — the newest code. The pattern says the next defect is there.
2. DR-2 path separation — an architectural property, not provable by the model.
3. §§6–7 ingress — never attacked by a third party.
4. The Dafny model itself — check the theorems are not vacuous; the non-vacuity witnesses are there to be audited.

Findings are welcome as issues and will be disclosed with attribution, the same way every prior defect in this document has been. **A review that returns "looks good" is a failed review.**

---

## Integrity

`MANIFEST.sha256` covers every file and is signed with an offline Ed25519 key.

```
Release key fingerprint: SHA256:c6334fda510760d9125e94ce8c900e56
```

A public key shipped only inside the package it authenticates proves nothing — which is the same argument this architecture makes about every other transmitted value.

## Where this came from: the cell

The architecture began as a mapping, not a threat model. A cell is a system that survives in a hostile medium without trusting anything that arrives:

| Biology | What it became here |
|---|---|
| Phospholipid bilayer | Everything entering is transformed before it reaches the interior |
| Receptor-mediated endocytosis | The parser: only specific shapes pass, through dedicated channels |
| The nucleus | **Read-only policy enclave** — the rulebook is read, never rewritten by what it governs |
| Quorum sensing | **No single element acts alone; a threshold must be reached** |
| Vesicles and lysosomes | Isolated compartments; foreign material is contained, never mixed |
| MHC presentation | Continuous display of internal state for inspection — the audit chain |
| Apoptosis | Detected compromise fails closed rather than degrading |

Two of these are load-bearing in the shipped specification rather than decorative: the read-only nucleus is the signed policy bundle the model never sees, and quorum sensing is INV-1-HIGH. The rest were the route to the design, and are kept here because where an idea came from is worth recording honestly.

## Licence and authorship

Apache-2.0. © 2026 Code75 SASU — Yacine Kellib.

Independent security architect, Paris. Twenty years in security, most of it building functions rather than inheriting them; the last two on agentic AI systems in production.
