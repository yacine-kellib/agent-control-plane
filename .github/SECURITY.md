# Security policy

This repository is a specification, a reference implementation and the evidence for both. It is **not deployed software**. That shapes what a security report means here.

## What this project wants

The most valuable thing you can send is a **defect in the argument** — a case where the design, the reference implementation, or the proofs do not hold what the documents claim they hold.

`dossier/06-RESIDUAL-RISK.md` states the known limits before the positive claims, and `README.md` has a "What this does not claim" section. **Neither is a disclaimer against reports.** If something in those lists is worse than stated, that is a finding.

The central invariant, and the thing worth attacking:

> **INV-1-HIGH** — no single compromised component can cause a high-impact action to execute without a fresh, single-use, quorum-satisfying set of attestations bound to that action's canonical hash.

## Where the return is highest

From `dossier/07-REPRODUCTION.md`, in order:

1. **`reference/src/acp_ack.py` and `reference/src/acp_audit.py`** — the newest code. Every defect in this project's history was found in machinery the previous fix had introduced, so the pattern says the next one is here.
2. **DR-2 path separation** — an architectural property no model can prove. T-32 is open: the notifier self-certifies its own independence.
3. **§§6–7 ingress** — never attacked by a third party.
4. **The Dafny model** — check the theorems are not vacuous. Non-vacuity witnesses are included precisely so they can be audited.

A finding that shows a check is **decorative** — that deleting it kills no attack — is as welcome as one that shows a check is missing. This project has removed two such checks rather than keeping them as defence in depth.

## How to report

**Open a public issue**, using the *Security finding* template.

Public by default is deliberate, and it is the opposite of the usual policy. Nothing here is deployed, so there is no window during which users are exposed and no patch to co-ordinate. The documents make public claims, and a defect in a public claim is corrected in public. Every prior defect — C2, X1, Y1, Z3, W1, V1, V2, V3 — was disclosed this way, in `RELEASE.md` and the dossier.

**One exception.** If you believe a finding creates real risk for somebody actually running this — a deployment we do not know about — use GitHub's [private vulnerability reporting](https://github.com/yacine-kellib/agent-control-plane/security/advisories/new) instead and say why. We will agree a disclosure date with you.

## What we commit to

- **Attribution**, unless you ask otherwise. Findings are credited by name or handle in `RELEASE.md`.
- **Publication**, including when the finding is embarrassing. Corrections are published, not quietly fixed.
- **An honest verdict.** If a report is not a defect we will say so and explain why, rather than filing it politely.
- No bounty. This is unfunded independent work; the only currency is credit.

## Before you report

Please run the gate, so we are looking at the same thing:

```bash
python3 -m pip install --break-system-packages cryptography dilithium-py
./tools/verify.sh --suites      # proofs + 13 suites, no release key needed
```

Two things that are **not** defects:

- **Red integrity or signature between releases.** `MANIFEST.sha256` is signed with an offline key. Sections 1–2 of the full `verify.sh` are expected red on a working tree; only a tagged release makes them green. This is a property of offline signing.
- **A successful prompt injection.** The architecture assumes injection succeeds and refuses to depend on it failing. An injection that produces a well-formed proposal is the design working. The finding would be an injection that causes an **action** to execute.

## Scope

| In scope | Out of scope |
|---|---|
| `spec/`, `dossier/`, `reference/` — the specification, the argument, and the Python implementation | Anything in `crates/`, `services/`, `orchestrator/`, `deploy/` behaving as scaffold — those `main()`s exit non-zero on purpose |
| The Dafny proofs in `reference/proofs/` | The absence of `spec/vectors/` — known, tracked, not yet built |
| `tools/verify.sh`, `tools/sign-release.sh`, `tools/selftest.sh` — a defect in the tooling that prints a false green is a serious finding | Dependency CVEs in `cryptography` or `dilithium-py` — report those upstream |
| `sim/` where it misrepresents what the control plane does | `sim/` numbers that are placeholders — it says so |
