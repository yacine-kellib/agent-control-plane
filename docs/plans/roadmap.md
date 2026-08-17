# Where this repository is going — the two tracks, and what was deferred

> Working document. Outside the signed roots, like everything in `docs/`.
> **Written 2026-08-18** because the same context was reconstructed from scratch three
> times: the deployment-substrate decision lived only in a plan file outside the repo,
> and each new session rediscovered it or, worse, did not.
>
> **This file lives on `main` deliberately.** A roadmap committed to a feature branch is
> invisible to anyone working anywhere else, which is the same failure as keeping it
> outside the repo — it was written on `feat/rule-store` first and moved here for exactly
> that reason. Read it from any branch, without checking anything out, with:
>
> ```bash
> git show main:docs/plans/roadmap.md
> ```
>
> Update it the same way: commit changes to `main`, not to whatever branch is in hand.
> `docs/` is outside the signed roots, so a commit here never invalidates
> `MANIFEST.sha256` — which is what makes updating `main` directly safe for this file and
> not for most others.

There are **two live tracks**. They interlock but they are not the same work, and a
handoff that names only one of them is how this got lost.

---

## Track A — the rule store, and then something that runs

**The question this answers:** a customer wants to deploy the control plane. What do they
build, in what order, in what language?

Nothing in the control plane can run without a **policy bundle** to evaluate against.
Every service's decision path reads one. So the bundle — authoring it, signing it,
distributing it, verifying it on read — is the first buildable thing, and everything else
is blocked behind it.

The full plan lives at `~/.claude/plans/is-this-schema-is-greedy-unicorn.md`
(**outside this repo, not tracked** — that is the defect this file exists to mitigate).
Its build order:

| # | Step | State |
| --- | --- | --- |
| 1 | `spec/schemas/bundle/` — JSON Schema for the §8.2 tree | **done** — 7 schema files |
| 2 | `acp-crypto`: native Ed25519 + ML-DSA-65 primitives | not started |
| 3 | `acp-crypto/custody.rs` — `Signer` trait, key custody tiers T0–T3 | not started |
| 4 | `acp-bundle/tree.rs` — canonical walk, SHA-256 tree hash | not started |
| 5 | `acp-bundle/verify.rs` — verify on **every read**, not at load | not started |
| 6 | `acp-bundle-cli` — offline authoring and signing binary | not started |
| 7 | `reference/src/acp_bundle.py` + the differential assertion | not started |

Then the other five services. Then, and only then, the deployment substrate.

Two constraints from that plan worth repeating here, because both are the kind of thing
that gets "helpfully" undone:

- **The attester registry is inside the tree hash.** Omit it and two Executors trusting
  *different* attesters agree they hold the same bundle. This was already found once, at
  `acp_executor.py:312`, and is the PB-KEY fix.
- **The custody tier cannot be self-certified.** A bundle's own claim about how its key is
  held is a value from the party being verified — RES-8, again. The verifier is configured
  out-of-band with the expected public key.

### Why Kubernetes and Terraform are not on this list yet

This decision was taken deliberately on 2026-08-17 and then promptly forgotten, so it is
recorded here rather than in a plan file nobody opens.

**The rule store needs none of it.** Authoring and signing are air-gapped (PB-1, PB-4),
and no orchestrator models an air gap.

When each one starts to matter:

- **Podman** — rootless and daemonless is a genuine reduction in attack surface, and
  quadlet/systemd suits one VM per trust domain. **The trap: a Podman *pod* shares a
  network namespace.** Two trust domains in one pod talk over localhost, with no mTLS, and
  the architecture's "no implicit trust across this boundary" becomes decorative. If
  Podman: one pod per domain, never one pod for the system. It is single-host, so the
  "×N replicas" in the diagram does not hold.
- **Kubernetes** — worth it only if the customer already runs it. You are buying
  NetworkPolicy and replicas; nothing else in it is load-bearing here.
- **Terraform** — yes, eventually, and for a specific reason: the security-relevant
  substrate **is** network segmentation, the egress allow-list, and KMS/HSM provisioning.
  Those are the actual controls, so reviewable infrastructure-as-code is worth more here
  than it usually is. Premature before a bundle exists.

**There is no UI track.** No ticket, no code, no design. `services/approval` and
`services/notifier` are TypeScript scaffolds whose `main()` exits non-zero. The file
`~/Downloads/acp-deployment-architecture.html` is a diagram, not an interface.

---

## Track B — shared conformance vectors

**The question this answers:** Python prints 52/52 and Rust prints nothing. What would
make those two numbers mean the same thing?

Linear project *ACP — Shared conformance vectors*. Nine tickets, ~19 points.
`docs/plans/spec-vectors-roadmap.md` is the detailed version; the ticket-to-VEC mapping is
scrambled and is written down there.

Execution order: **VEC-1 (ACP-1)** → VEC-2 (ACP-2) → VEC-3 (ACP-4) → VEC-4 (ACP-5) →
VEC-5 (ACP-6) → VEC-6 (ACP-3) → VEC-7 (ACP-7) → VEC-8 (ACP-9) → VEC-9 (ACP-8).

The payoff is VEC-8: `crates/acp-conformance` is an empty scaffold waiting on this corpus.

**Where the two tracks touch:** Track A's step 1 says "sequence with ACP-2 rather than
duplicating it". The bundle schema and the vector file format are two descriptions of the
same objects, and two descriptions of one object is the encoding-split defect at the
source level. Whichever track moves first, the other's schema work must not fork it.

---

## Track C — the defect backlog, which is not a track

Defects get filed and fixed as they are found; they do not queue behind either track.
Eight are In Review as of 2026-08-18 (ACP-28 → ACP-35), all committed on
`feat/rule-store` and **unpushed**. Two hygiene items sit in Backlog and are worth doing
before a release rather than after: **ACP-16** (the offline release key is in the home
directory) and **ACP-17** (an editor auto-format keeps silently invalidating the signed
manifest).

---

## Known stale claims

Recorded so the next reader does not have to rediscover them.

- **`CLAUDE.md` says `deploy/` contains `k8s/`. It does not** — `deploy/` holds only
  `docker-compose.yml`. Flagged 2026-08-17, still stale.
- **`~/Downloads/acp-deployment-architecture.html`** conflates the spec version with the
  package release version (`v1.3.13` vs package `v1.3.14`), shows **ACK-4** as though it
  were a spec clause when it lives only in `reference/`, and depicts running services that
  today exit non-zero. It needs a **"target architecture"** label. It is outside the repo,
  so whether it was corrected is unknown.
- **The branch name `feat/rule-store` no longer describes its contents** — of its commits,
  two are rule-store step 1 and the rest are defect fixes and the spec moving to v1.3.15.
