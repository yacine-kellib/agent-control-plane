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
| 2 | `acp-crypto`: native Ed25519 + ML-DSA-65 primitives | **done** — `b8bd429` (ACP-36) |
| 3 | `acp-crypto/custody.rs` — `Signer` trait, key custody tiers T0–T3 | **done** — `a4d8347` (ACP-37) |
| 4 | `acp-bundle/tree.rs` — canonical walk, SHA-256 tree hash | **done** — `0c84bc1` (ACP-38) |
| 5 | `acp-bundle/verify.rs` — verify on **every read**, not at load | **done** — `b3528f7` (ACP-39) |
| 6 | `acp-bundle-cli` — offline authoring and signing binary | **done** — `d17fd47` (ACP-40) |
| 7 | `reference/src/acp_bundle.py` + the differential assertion | **done** — `630b8c6` (ACP-41) |

**Track A's rule store is complete as of 2026-08-18**, on `feat/rule-store`, unpushed. The
whole lifecycle runs: author a directory, walk it canonically, sign it offline under a
hybrid suite, distribute it, and verify it on **every read** at runtime. Both differential
directions are checked — Python's signatures verify in Rust, Rust's verify in Python, and
the two implementations agree on a bundle's tree hash, verdict and *refusal name* across
eleven cases.

Two things were found by building it, and both were defects in this project rather than in
a dependency:

- **PB-8 is new, and §8.2 was wrong.** The file listing described `SIGNATURE` as "Ed25519
  over SHA-256 of canonical bundle tree" — one classical primitive — while Part V requires
  hybrid composition conjunctively. An implementer following the listing emits a
  classical-only signature over the highest-leverage artifact in the system and is CR-3
  non-conformant *while conforming to the sentence they read*. Nothing downstream detects
  it, because the post-quantum leg is absent rather than wrong.
- **A vector may not name a seed alone.** `spec/vectors/CLASSIFICATION.md` rested 47 of 85
  cases on seed portability, verified only across two Python processes — which shows
  determinism and cannot show agreement between libraries. It does agree (`fips204` and
  `dilithium-py` implement FIPS 204 Algorithm 6 compatibly), but what is portable is the
  seed **plus the declared derivation**. An implementation choosing its own domain
  separators derives a different identity and refuses every signature in the vector, which
  at the verifier is indistinguishable from a forgery. **This is a hard constraint on
  VEC-2.**

What comes next is below. Then, and only then, the deployment substrate.

Two constraints from that plan worth repeating here, because both are the kind of thing
that gets "helpfully" undone:

- **The attester registry is inside the tree hash.** Omit it and two Executors trusting
  *different* attesters agree they hold the same bundle. This was already found once, at
  `acp_executor.py:312`, and is the PB-KEY fix.
- **The custody tier cannot be self-certified.** A bundle's own claim about how its key is
  held is a value from the party being verified — RES-8, again. The verifier is configured
  out-of-band with the expected public key.

### The rest of Track A — from a verified bundle to a control plane

Written 2026-08-18, immediately after the rule store landed, because the question "is
there actually a path from here to something that runs" deserves an answer that can be
checked rather than assumed.

**The ordering rule.** Each phase must leave the gate green, and every new control must
kill a mutant. A phase that cannot state which attack succeeds when its check is deleted
has not produced a control — it has produced documentation, and this repository has
already published one of those (RV-1 was reachable only through the floor-HIGH gate for
four releases; DR-13 gave it effect).

**THE GOAL, stated 2026-08-20 because it was not written down and the table below was
being read as if it were the goal.** *"A complete architecture working from end to end —
all the services built, console and so on."* Not a library another product links against;
a system that runs. That reading was recorded wrongly for two days as "a Rust control
plane embedded in the user's own SaaS", which is true about the language and wrong about
the deliverable.

**Two consequences the table below did not carry**, both now ticketed:

- **ACP-62 is load-bearing, not a side ticket.** Ingress, KMS, audit and egress proxy have
  no source directory at all. "End to end" is unreachable without them and no phase owns
  them.
- **ACP-77 — there is no console, and the specification requires humans who have no
  interface.** DR-9/AT-* need two named people to read a proposal and sign; DR-13 needs an
  addressee to receive a notice; A-8's lying-screen defence needs a screen. Door A is the
  machine door and is nearly built. Door B is the human door and does not exist. Note the
  DR-2 constraint before any of it is designed: a single console rendering both the notice
  and the approval **is** the shared render path the rule forbids.

Counting what the goal actually needs: **ten services and a console**, of which six are
scaffold, four have no source, and one has never been mentioned.

| # | Phase | Why it is here and not later | Blocked until |
| --- | --- | --- | --- |
| 8 | **Generated types** — `tools/codegen.sh` from `spec/schemas/` to Rust and TS | Cheapest now, when there is exactly ONE consumer. `acp-bundle/verify.rs` reads five named fields out of `serde_json::Value`, which is field access. Five services hand-writing structs is five second definitions of one object — the encoding-split defect multiplied, in the layer where it is least visible. | nothing |
| 9 | **The decision path in Rust** — §8.4 grading, floors, RV-1, DR-13, CR-3/CR-4, AT-* quorum | This is the authorisation logic itself. Today it exists only in Python; the bundle is its *input*, and an input with no evaluator is a rule store nothing reads. | 8 |
| 10 | **Ledger and anchor** — append-only, AU-7 anchor-before-release, CL-1..7 partition behaviour | Ordering and temporal properties. `OBLIGATIONS.md` already records that these are **not vector-expressible**, so they need per-implementation tests and cannot be inherited from a corpus. | 9 |
| 11 | **The two doors** — `services/notifier`, `services/approval` *(now in the PRIVATE product repo — ACP-66 moved `services/` out; the Executor-side check that closes T-32 stays here)* | Where **T-32 closes**. It has been OPEN because the notifier self-certifies its own independence, and closing it needs the Executor to check *two distinct signed service identities named in the signed bundle*. The bundle can now carry them and is verified on read — so this is the open conformance item the rule store actually unblocks. | 9 |
| 11.5 | **The four with no source** — ingress, KMS, audit, egress proxy (ACP-62) | Added 2026-08-20. They are named all through the architecture and exist nowhere. A refusing scaffold first, like the other six, so the gap lives in the build rather than in a ticket. | 9 |
| 12 | **Wire it together** — the demonstrator stops being a demonstrator | Services stop exiting non-zero **one at a time, each when it is real**. §9.7's latency budget must be **re-measured**: verify-on-every-read costs one hybrid verification per read, and that number was written before the cost existed. | 10, 11 |
| 12.5 | **The console** (ACP-77) — the approval surface, the notice surface, and the operator view | Added 2026-08-20. **Its architecture must be decided before its first commit**: DR-2 forbids the notifier and the approval path sharing anything above the wire format, so this is two separately-built consoles or the render-path distinctness claim dies. Cheap to decide now, close to unpayable after a component library is chosen. | 11, 12 |
| 13 | **Substrate** — Podman / Kubernetes / Terraform | Unchanged from the reasoning below. Deliberately last — **and, under the goal above, not optional**. A system that runs end to end has to run somewhere. | 12 |

**Where Track B joins.** The vector corpus is not on this critical path and should not be
allowed to block it. It pays off at phase 9: the Rust decision path needs a differential
against Python's 52 conformance cases, and vectors make that a data file instead of
hand-built code. Tonight's eleven-case bundle differential was hand-built and worked
fine, so phase 9 can proceed either way — but doing VEC-2/VEC-3 first makes it cheaper
and makes "passes the corpus" mean the same thing in both languages, which is the point of
VEC-8.

**What "success" means here, stated so it can be failed.** Not "the services start". The
claim this repository makes is that *every claim replays on the reader's machine*. So the
finish line is: a running control plane in which every normative clause has a control,
every control kills a mutant, both implementations agree on the same corpus, and the
numbers in the prose equal the numbers the tooling prints. Phases 8–13 are necessary for
that and are not sufficient for it.

**The three risks that phases 8–13 do not retire**, and it is worth being blunt because
the path above is otherwise a straight line:

1. **RR-1 — no independent adversarial review.** This is the largest open gap in the
   project and *we cannot close it ourselves*. Every suite here was written by the same
   party that wrote the code, and §15 already records the limit: agreement between two
   implementations is evidence about consistency and never about correctness, weakest
   exactly where it feels strongest. ACP-23 (ask the formal-methods community to find a
   vacuous theorem in `binding.dfy`) is the cheapest real attempt at this and does not
   depend on any phase above.
2. **Nothing runs end to end today except `sim/`.** The simulation is the only artifact
   that exercises the architecture as a system, and it is a companion to Annex D rather
   than the control plane. Phase 12 is where that stops being true, and it is five phases
   away — a schedule built on anything sooner is building on the sim.
3. ~~**The offline release key is in a home directory (ACP-16).**~~ **Closed
   2026-08-20**, and verified rather than assumed: `/Users/yakine/acp-release.key` no
   longer exists, and the replacement is passphrase-encrypted, which is why signing needs
   a real terminal and cannot happen from an agent session. The key was **rotated**, not
   merely relocated — an agent session had already read it, and a key an agent has read is
   spent whatever happens to the file afterwards. Left in the list, struck through, for
   the reason the `k8s/` entry below gives. *A second project's `doora-release.key` is
   still unencrypted in the same directory; it is out of this repository's scope and is
   flagged to the key holder.*

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
`services/notifier` are TypeScript libraries with no entry point at all — and since
ACP-66 they are not in this repository, they are in the product one. The deployment
architecture document is a diagram, not an interface.

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

**A stale claim inside Track B's own tickets.** ACP-2 (VEC-2) still says "the Python
reference signs with modelled HMAC". That has been false since v1.3.14 — both sides use
FIPS 204 and RFC 8032. The conclusion it supports (vectors are defined over canonical
bytes and declared mutations, never over signatures) is still correct, but for a different
reason: ML-DSA signing is hedged, and a vector carrying a signature would have to carry key
material to be checkable. Fix the ticket before anyone plans from it.

**Where the two tracks touch:** Track A's step 1 says "sequence with ACP-2 rather than
duplicating it". The bundle schema and the vector file format are two descriptions of the
same objects, and two descriptions of one object is the encoding-split defect at the
source level. Whichever track moves first, the other's schema work must not fork it.

---

## Track C — the defect backlog, which is not a track

Defects get filed and fixed as they are found; they do not queue behind either track.
As of 2026-08-18 the In Review set is ACP-28 → ACP-43, all committed on `feat/rule-store`
and **unpushed**. **ACP-43 is the third recurrence of a published number drifting from the
number the tooling prints** — `README.md` said "Rust: 7 tests" while the workspace ran 47,
and `selftest.sh` published 34 assertions while making 45. Four self-checks now assert
these by command, including one that counts itself. Two hygiene items sit in Backlog and are worth doing
before a release rather than after: **ACP-16** (the offline release key is in the home
directory) and **ACP-17** (an editor auto-format keeps silently invalidating the signed
manifest).

---

## Known stale claims

Recorded so the next reader does not have to rediscover them.

- ~~**`CLAUDE.md` says `deploy/` contains `k8s/`. It does not.**~~ Fixed. Flagged
  2026-08-17; `CLAUDE.md` and `README.md` both now say "no k8s/ — the substrate is
  deliberately deferred". Left in the list because an entry that says "still stale"
  about something already fixed is the same defect one level up, and it survived here
  for two days.
- **`~/Downloads/acp-deployment-architecture.html`** conflates the spec version with the
  package release version (`v1.3.13` vs package `v1.3.14`), shows **ACK-4** as though it
  were a spec clause when it lives only in `reference/`, and depicts running services that
  today exit non-zero. It needs a **"target architecture"** label. It is outside the repo,
  so whether it was corrected is unknown.
- **The branch name `feat/rule-store` now describes its contents again** — as of
  2026-08-18 the branch carries the whole rule store, steps 1–7, alongside the defect
  fixes and the spec at v1.3.15. Resolved, and left here because the reverse observation
  was recorded above it.
- ~~**Phase 9 is half done, and the table above does not say so.**~~ Superseded
  2026-08-21: all six of `ACP-45`'s slices have shipped, and the first of the three this
  entry called "not started" landed under five hours after the entry was written.
  Slice 4, the receipt gate (CR-1/CR-3/CR-4), at `4c1accd`/`f489fe4`; slice 5, the AT-*
  quorum, at `d64299d`; slice 6, §9.3 composed in Rust with suite 12's R/B/T
  classification, at `a85b776`. **The limit first: the §9.3 differential landed PARTIAL
  and prints that it did.** `acp-decision` implements the STATELESS half, so the cases
  that turn on a durable ledger (ACP-46), the Context Store (§8.8), the deferred-release
  gate (ACP-47), or a refusal that lands at bundle load before §9.3 is entered
  (`acp-bundle`) are reported BLOCKED with their owners named, not dropped from the
  denominator — six slices shipped is not phase 9 closed. The slice breakdown still lives
  in ACP-45's comments, not here, because a table that tracks progress is a number that is
  wrong on the next commit (see below), which this entry has just demonstrated on itself.
- **`CLAUDE.md`'s "Current state" no longer publishes a commit count.** It said "11
  commits ahead" and was wrong within a day; any number written there is wrong on the next
  commit. `git log --oneline main..HEAD` is written down instead. Same class as ACP-43.
