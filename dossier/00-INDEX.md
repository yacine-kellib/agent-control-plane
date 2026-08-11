# ACP — Agent Control Plane
**Security dossier**
**Structured-input control plane for AI agent actions**
**Specification version:** ACP-SPEC-001 v1.3.13
**Date:** August 2026
**Classification:** internal / shareable under NDA

---

## How to read this dossier

Two layers. The **summary** layer (01, 02, 06) reads in twenty minutes and is enough to decide. The **evidence** layer (03, 04, 05, 07 + `reference/suites/`) exists for a sceptical reader: every claim is tied to a replayable artifact, with its command and hash.

This dossier is built to be **attacked**, not merely read. If a claim looks doubtful, §07 gives the exact command that verifies or refutes it.

| # | Document | Audience | Time |
|---|----------|----------|------|
| 01 | Executive summary | CISO, leadership | 10 min |
| 02 | Threat model and MITRE ATLAS / ATT&CK mapping | Analyst, auditor | 20 min |
| 02b | Field-and-relation classification table (**regenerated v1.3.11**) | Auditor | 20 min |
| 03 | Full normative specification — now `spec/ACP-SPEC-001.md` | Architect, implementer | 3 h |
| 04 | Formal verification | Formal reviewer | 45 min |
| 04b | Prior adversarial review (partial independence) | Auditor | 30 min |
| 05 | Test evidence (suites 1–10) | Auditor, assessor | 30 min |
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
sha256sum -c MANIFEST.sha256      # or: ./tools/verify.sh  (integrity + full replay)
```

The manifest itself is signed. `MANIFEST.sha256.sig` is an Ed25519 detached signature under the offline release key; the fingerprint is published in `RELEASE.md`. An unsigned manifest is a list, not a commitment — the same objection this architecture makes everywhere else.

## Version

v1.3.13, the polyglot restructure. Full notes in `RELEASE.md`. A structural release: no rule changed, and every number that replayed in v1.3.12 replays here. The repository was reorganised from a Python-only dossier into a polyglot monorepo so a second implementation surface (Rust, TypeScript) can be held to the same evidence — `spec/` is now the only normative source, `reference/` the permanent Python implementation.

Two consequences a reader should know before verifying. The gate is **split**: `./tools/verify.sh --suites` runs the proofs and all 13 suites without the release key and is green at every commit, while full `verify.sh` adds integrity and signature and is green only at a tagged release — sections 1–2 red between releases is a property of offline signing, not a finding. And **Rust and TypeScript are scaffold**: the services exit non-zero so they cannot be mistaken for a running control plane, and `spec/vectors/` — the shared corpus that would make "44/44" mean the same in both languages — is not yet extracted. Five new residuals (RES-P1..P5) are disclosed in §06; the load-bearing one is that splitting the notifier and approval codebases does **not** close T-32.
