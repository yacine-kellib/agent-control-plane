# ACP — Agent Control Plane
**Security dossier**
**Structured-input control plane for AI agent actions**
**Specification version:** ACP-SPEC-001 v1.3.12
**Date:** August 2026
**Classification:** internal / shareable under NDA

---

## How to read this dossier

Two layers. The **summary** layer (01, 02, 06) reads in twenty minutes and is enough to decide. The **evidence** layer (03, 04, 05, 07 + `artifacts/`) exists for a sceptical reader: every claim is tied to a replayable artifact, with its command and hash.

This dossier is built to be **attacked**, not merely read. If a claim looks doubtful, §07 gives the exact command that verifies or refutes it.

| # | Document | Audience | Time |
|---|----------|----------|------|
| 01 | Executive summary | CISO, leadership | 10 min |
| 02 | Threat model and MITRE ATLAS / ATT&CK mapping | Analyst, auditor | 20 min |
| 02b | Field-and-relation classification table (**regenerated v1.3.11**) | Auditor | 20 min |
| 03 | Full normative specification | Architect, implementer | 3 h |
| 04 | Formal verification | Formal reviewer | 45 min |
| 04b | Prior adversarial review (partial independence) | Auditor | 30 min |
| 05 | Test evidence (suites 1–7) | Auditor, assessor | 30 min |
| 06 | Residual risk and limits | CISO, risk management | 15 min |
| 07 | Reproduction | Any verifying party | — |

## What this dossier claims

One property, and everything else serves it:

> **INV-1-HIGH — no single compromised component can cause a high-impact action to execute without a fresh, single-use, quorum-satisfying set of attestations bound to that action's canonical hash.**

## What it does not claim

That the system is safe. That any human read a notification — acknowledgement is now authenticated (ACK-1..6, v1.3.12) but authentication is not comprehension (A-8). That the notifier's declared independence is verified at run time — it is not (T-32). That no defects remain. That sensitivity labels are honest (A-7, conceded unprovable). That the independent adversarial review required by conformance suite 11 has taken place — **it has not** (RR-1), and §06 explains why that is the most important gap in this dossier. That the two rendering paths behind the A-8 reduction are genuinely independent: that is an auditable property of a deployment, not a proven one.

## Integrity

`MANIFEST.sha256` covers every file:

```bash
sha256sum -c MANIFEST.sha256      # or: ./verify.sh  (integrity + full replay)
```

The manifest itself is signed. `MANIFEST.sha256.sig` is an Ed25519 detached signature under the offline release key; the fingerprint is published in `RELEASE.md`. An unsigned manifest is a list, not a commitment — the same objection this architecture makes everywhere else.

## Version

v1.3.11. Changes from v1.3.10 are in `RELEASE.md`: AC-5/AU-6/AU-7/AU-8 implemented and tested, Suite 5 given the tests it always claimed, residual identifiers disambiguated (RR-n), and three defects disclosed from building the new machinery.
