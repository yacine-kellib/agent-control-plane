# ACP-SPEC-001 — package release v1.3.14

**Specification version: unchanged at ACP-SPEC-001 v1.3.13.** This release
changes the reference *implementation*, not the normative document. Nothing in
`spec/ACP-SPEC-001.md` moved: PB-KEY below is the reference finally doing what
§8.2 already required. Under the specification's own release rule (X5) a version
string maps to exactly one document, so re-stamping an unchanged document would
be its own collision — the package version and the spec version are therefore
allowed to differ, and are.

**Date:** August 2026
**Package:** `spec/` + `dossier/` + `reference/` + `crates/` + `services/` + `packages/` + `orchestrator/` + `sim/` + `deploy/` + `tools/`
**Integrity:** `MANIFEST.sha256`, Ed25519 detached signature `MANIFEST.sha256.sig`
**Release key fingerprint:** `SHA256:c6334fda510760d9125e94ce8c900e56` *(verify out of band)*

Reproduce everything in one command:

```bash
./tools/verify.sh            # integrity + signature + proofs + 14 suites + harness
./tools/verify.sh --suites   # proofs + suites only, no release key needed
```

---

## Unreleased since v1.3.14 — the audit chain the specification described was not the one anybody built

Two defects in `spec/ACP-SPEC-001.md` itself, both found by reading the document after the
phase-8 work was finished, and both of the same shape as the schema defects below:
**normative text with no executable consumer.** That makes three instances in one day.

### AU-1's formula and the reference's disagreed, so AU-3a did not hold

`ACP-57`. §11.2 specified the audit chain as:

```
chain_hash_n = SHA-256(chain_hash_{n-1} ‖ canonical(record_n))
```

`reference/src/acp_audit.py` has always computed the canonical encoding of the two-key map
`{prev, record}`. Different preimage, different chain from record 1 onward.

The consequence is not that an implementer fails to match. **AU-3a is normative** — "every
anchor MUST be independently verifiable by any party holding the anchor public keys" — and
AU-4 classifies a head that fails to extend a previously anchored head as a *critical
integrity alert*. A third party implementing AU-1 literally recomputes a different head on
an **honest, untampered** chain and raises that alert. The normative text routed an honest
verifier into this system's own critical-alert channel, with no attacker present, and at
the verifier the result is indistinguishable from the tampering AU-4 exists to detect.

A second ambiguity sat inside the first: AU-1 never typed `chain_hash_{n-1}`. The reference
feeds forward the 71-character `"sha256:…"` string; `‖` invites raw digest bytes. Two
readings of one clause before the map-versus-concatenation difference is reached.

**The specification moved, not the code** — against the default, so the reasoning is
published rather than assumed. `canonical()` is this repository's *one* encoding rule
(AT-8a, Suite 5, 8 cases). `‖` is a *second* one: a framing discipline no canonicaliser
expresses, no suite exercises and no vector can carry. That is the encoding-split defect
this document exists to prevent, sitting in the clause that defines tamper-evidence.
Routing the whole preimage through `canonical()` deletes the second rule instead of
documenting it. AU-1 and AU-8 now share one pinned hash notation.

**What closes it is not the edit.** Suite 7 gains a case that derives a head from the
clause as written — its own `H`, not an import of `acp_audit._h`, because re-using the
implementation's helper would agree with whatever either side adopts — and asserts equality
with both `append()` and `recompute_heads()`. Verified by reintroducing the old
concatenation: the suite goes red naming **head 1**, which is where the ticket predicted the
divergence begins. Suite 7 is **11/11 → 12/12**.

Why eleven passing cases and four killed mutants missed it: every one of them tests the
chain against **itself** — consistent, tamper-evident, rewrite-detecting. None compared it
to AU-1. `spec/vectors/CLASSIFICATION.md` recorded the audit suite as **0 of 11
vector-expressible**, so the one suite with no shared-corpus path was the one whose formula
drifted. It now reads 1 of 12: the new case is the only pure function in the suite, and the
file records why it is expressible but not yet extractable. Consistency evidence is not conformance evidence.

### `CL-7` was two different normative rules, and both were already cited

`ACP-56`. §9.3.1 defined CL-7 twice: "ledger writes are check-then-mutate" (v1.3.9) and
"every claim operation MUST be audited" (older). The v1.3.9 insertion landed *above* CL-6
and took an id already in use two lines below it, so the list read CL-5, CL-7, CL-6, CL-7.

The ambiguity was **live, not latent**: §1 cites CL-7 as check-then-mutate twice, while
§10's threat table cited "CL-7 auditing" meaning the other rule. A reader resolving the id
in one place got the wrong clause in the other, and "CL-7 satisfied" was unfalsifiable —
an implementation could satisfy either and cite the clause honestly.

No code defect; `reference/src/acp_ledger.py` implements check-then-mutate and Suites 3 and
4 cover it. What was damaged is the **citation graph**, which `spec/vectors/OBLIGATIONS.md`
keys obligations to. The **older** rule was renumbered **CL-8** and the list reordered — the
v1.3.9 id is cited in released prose and in this file, and an id already published is the
one that must not move.

**The class fix, not the instance:** `tools/selftest.sh` now asserts that every clause id in
the document is defined exactly once, across every family and not just `CL-*`. Run against
the spec as committed before this change it names `CL-7`; against the corrected document it
is clean. It manufactures a collision on every run and requires the detector to name it, so
a regex that silently stops matching cannot pass as a clean document.

### The tool that said "move the key to offline media" is what put it in `$HOME`

`ACP-16`. `sign-release.sh keygen` hardcoded `~/acp-release.key`, wrote the release key
there, and then printed *"move to offline media, chmod 600"*. The exposure the dossier's
two-gate argument denies was **manufactured by the repository's own tooling**, and moving
the file by hand would have left the generator to recreate it on the next rotation.

A second property was worse. `keygen` had **no overwrite guard**. `sign` already builds
into `.tmp` files and moves them into place only after the signature exists, so a mistyped
path cannot destroy the last valid manifest — the key itself had nothing. The asymmetry is
backwards: a clobbered manifest can be re-signed, while a destroyed release key makes
**every signature it ever produced permanently unverifiable**. `keygen` also had no test
coverage at all, so this shipped untested for the life of the script.

The path is now required — no `$HOME` default — and `keygen` refuses to overwrite, exiting
**3** rather than merely non-zero, because `1` is usage and a check accepting any failure
would pass a refusal for the wrong reason. Three assertions added, all proved by firing
them against a decoy. The real key is never an argument to a test: a test that can reach
the signing key is the defect it is testing for.

### The location was never the fix — the encryption is

The ticket asked for the key to be moved to removable media. That answer was accepted too
quickly and is wrong on its own: a USB stick protects a key only while it is *unplugged*,
which is every moment except the one where it is actually used. Mounted at `/Volumes/…` it
is exactly as readable as `$HOME` was, and it adds a stick to forget to remove.

The real defect was one argument: `load_pem_private_key(..., password=None)`. An
unencrypted PEM is usable by any process running as this user, and **no directory changes
that**. `keygen` now refuses to produce anything else — `BestAvailableEncryption`, a
12-character minimum, confirmed twice, and it will not run without a terminal rather than
silently emitting an unencrypted key. The plaintext key exists only in memory, for the
seconds it signs. Where the file sits stops mattering.

`sign` prompts **only** when the key is actually encrypted, and only on a TTY. Both halves
are load-bearing. It branches on `TypeError` ("encrypted, no password") and never on the
`ValueError` an unparseable file raises, so the existing "unparseable key fails" assertion
keeps failing for its own reason rather than stopping at a prompt. And a prompt reached
from selftest, CI or cron would hang forever — **a gate that hangs is worse than one that
fails, because it reports nothing at all.** Asserted with a pipe for stdin, exactly as
automation sees it. Unencrypted keys still load, so the tooling does not break the
existing release to force the rotation.

What this does **not** fix is disclosed rather than implied. Encryption is prevention, not
remediation: the *current* key has sat unencrypted since 2026-08-10, readable by every
agent session in this repository — including the one that made this fix — and it signed
the manifest `main` ships. Rotation remains open on `ACP-16`, and rotating is cheapest
now, while no adopter has recorded the published fingerprint.

### `sync-counts.sh` destroyed a dossier file and reported success

Found while propagating 11/11 → 12/12, and disclosed because it is the more dangerous
defect of the three. The script substitutes with `sed` using `|` as its delimiter; a
replacement string written for a **markdown table row** carried an unescaped `|`, `sed`
failed, and the script wrote the empty result over a 134-line file while printing `SYNC`.
The damage was caught by reading `git diff --stat`, not by any check.

Its guard was "did the bytes change?", which answers *yes* to a `sed` that produced garbage.
Two guards now sit in front of the write: a failed `sed` halts, and — since every one of
these substitutions is in-line — a change in **line count** halts. Both exit `2`, distinct
from `1` for drift, and neither writes. Both were proved by firing them: the malformed
pattern that caused the damage, and a replacement injecting a newline. A tool that silently
destroys the prose it exists to keep accurate is worse than the drift it removes.

Suite 7's count is now **derived** by `sync-counts.sh` across all seven sites that publish
it, rather than hand-maintained. It had been hand-work, and hand-work on published counts
has already recurred twice.

The consolidated attack registry is derived for the same reason, and it is the sharper case:
`attack_registry.py` iterates `audit_suite.TESTS` wholesale, so **one new case in suite 7 moved
the registry 80/80 → 81/81** and turned the gate red on a line nothing had edited. That coupling
was invisible until it failed. Both counts are now re-derived by running the suites, across
eleven published sites in total.

---

## Unreleased since v1.3.14 — four defects in `spec/schemas/`, found by reading it for the first time

`spec/schemas/bundle/` held seven normative JSON Schema files. **Nothing in the
repository opened any of them.** No consumer, no validator, no gate line — verified by
grep across every language root. `packages/acp-types/src/index.ts` had said since the
polyglot restructure that its types "will be GENERATED from `spec/schemas/*.schema.json`",
and nothing generated them.

Phase 8 (`tools/codegen.sh`) is the first thing that ever read them. It found four defects
on its first pass, one of them a live quorum bypass. That is the finding worth publishing;
the code generator is the instrument, not the result.

### PB-7 was defeated by editing a role string

`ACP-53`, and it is the serious one. PB-7 requires attester verification keys to be
pairwise distinct, "compared over the complete suite". Both implementations compared whole
registry **entries** for equality, and an entry is `{role, classical, pq}` — so the check
fired only when two entries were byte-identical. Measured, both sides:

| registry | verdict | PB-7 |
| --- | --- | --- |
| entries identical | `RegistryKeysNotDistinct` | correct |
| same keys, **different `role`** | **accepted** | must refuse |
| differ in classical, **share `pq`** | **accepted** | must refuse |
| share classical, differ in `pq` | **accepted** | must refuse |

The attack is one string. Enrol `alice` as `approver` and `bob` as `confirmer` with the
same key: two identities, one private key, `quorum_k = 2` satisfied alone — and
approver-plus-confirmer is exactly the pairing DR-9 demands for an irreversible action at
floor-HIGH. INV-1-HIGH defeated by a single compromise, reached through the registry rather
than through the threshold. That is the attack PB-7 was written in v1.3.15 to close.

**Three of this repository's own controls reported the check as sound**, and that is the
part that generalises:

- **The differential agreed.** Both implementations were wrong identically, so
  `check-bundle-differential.py` passed. §15 already states the limit — agreement is
  evidence about consistency and never about correctness, and it is weakest exactly where
  it feels strongest. This is a clean instance rather than a hypothetical one.
- **A deletion mutant would still have died.** Remove the loop and the byte-identical case
  goes red, so the check registered as load-bearing. `dossier/05` already says deletion
  mutants cannot catch a check that is present and means the wrong thing; here it was.
- **The fixture could not express the attack.** Every registry helper in all three places
  set both legs from one string and emitted no `role`, so "shares a key" and "is
  byte-identical" were the same condition. The suite proved the check fires on the case
  that was written, and that case was the only one it caught.

Fixed by comparing **per leg** across identities with `role` excluded; either leg colliding
is a collision, and an entry missing a leg is refused because a key that is absent cannot
be shown distinct from anything. The fixtures were rebuilt before the cases, since none
could express the attack. Every new case was run against the old check before being
trusted — 4 red in Rust, 4 red in Python, 4 divergences in the differential — and in each
run the identical-entries case and the positive path stayed green, which is the blind spot
drawn to scale.

### The normative schema described an artifact nobody builds

`ACP-50`. `bundle.schema.json` declared a tree index — a `members` array of path and digest
pairs — and a signature object of two fixed base64 fields named `classical` and `pq`.
Neither exists. §8.2's file listing contains no index file, because the covered set is
established by the canonical walk; and PB-8 specifies one value per primitive, which is a
map keyed by primitive name, hex-encoded, and is what both implementations write.

So the normative source held two descriptions of one object and they disagreed: the
encoding-split defect, inside the document that exists to prevent it, introduced by the
v1.3.15 revision that fixed the same defect one paragraph away. It is now
`signature.schema.json` and describes the artifact that exists.

### RK-1's fail-safe default was stated in the wrong domain

`ACP-51`. One hand-written `RiskTier { Low, Medium, High }` in `acp-core`, whose doc
comment read "a resource absent from `floors.json` is **T3**" — annotating an enum with no
T3. TypeScript carried it one step worse, as a value:
`UNCLASSIFIED_RESOURCE_TIER: RiskTier = 'HIGH'`.

The schemas define two ordered domains over different subjects: `Tier` (`T0 < T1 < T2 <
T3`, how sensitive a resource is) and `Risk` (`LOW < MEDIUM < HIGH`, how dangerous an
action is). §8.4 composes both with `max`, which is exactly why one type served for both
until someone read the schemas as a producer of types — every wrong composition
typechecked. Latent rather than live: nothing consumed either value, and phase 9 is where
a floors lookup would have started returning `High`. The Python reference was correct
throughout.

### The generator, and the rule it will not guess

`tools/codegen.sh` emits Rust and TypeScript from the schemas, with the output committed so
the repository stays clonable without a codegen toolchain. It is hand-rolled rather than
`typify` or `quicktype` for one reason: every off-the-shelf generator emits `Option<T>` and
`#[derive(Default)]`, and those are precisely the mechanisms that turn *absent* into
*permissive*.

The fail-safe defaults are therefore carried **in the schema as data**, under
`x-acp-absent`, rather than in a table beside the generator — a generator-local table would
be a second definition of RK-1, which is the same defect one layer down. The open maps are
emitted with a **private** field and one accessor returning the fail-safe value, so the
permissive answer is unreachable rather than discouraged. And the generator **halts** on a
lookup table with no declared rule, exactly as `sign-release.sh` halts on an unrecognised
file type. A generator that guesses a default eventually guesses the permissive one.

`x-acp-ordered` is applied only where the schema declares an order. `SuiteId` deliberately
has none: CR-4's floor is satisfied by **containment** of primitives, never by rank, and a
derived `Ord` would make `declared >= floor` compile — which is the downgrade. A test
asserts the absence against the generated source, because Rust cannot express "this type
does not implement `Ord`".

Each of those controls was proved failable rather than asserted: flipping `x-acp-absent`
to `T1` turns the floors test red, adding `x-acp-ordered` to `SuiteId` turns the ordering
test red, and deleting either annotation makes the generator halt with exit 2.

### What this does not claim

**Nothing validates a bundle against these schemas.** `ACP-52` is open, and it is not
closed by any of the above. Codegen makes the schemas *executable* for the first time,
which is a partial mitigation and deliberately less than validation. Every bundle fixture
in this repository is in fact schema-invalid — `custody` legs are written as strings where
the schema requires objects — and nothing notices, because both loaders read only the
security fields they need, by name.

Note also the standing limit before anyone builds that validator: PB-7 and the three
absent-⇒-fail-safe rules are **not expressible in JSON Schema** and live in the loader,
which is precisely where the defect above was found. A bundle that validates is not a
bundle that is well-formed, and a green schema check must not be published as though it
were.

**The reference does not bound integers to the schema's declared domain.** `ACP-54`, found
by the differential's new cases and pinned rather than hidden: a negative `bundle_epoch`
and a `quorum_k` above `2^64` are refused by Rust and accepted by Python. The differential
asserts *both* sides' verdicts for those three cases, so the divergence disappearing or
moving turns it red — a known divergence recorded is worth more than a suite quietly
sized to avoid it.

---

## Unreleased since v1.3.14 — 48 of 86 suite cases could be shared data; the rest cannot

`spec/vectors/` gains its first two files, and neither is a vector. **ACP-1 (VEC-1)**
classified every case in the four suites the shared conformance corpus would cover —
52 conformance, 8 canonical CBOR, 14 signed acknowledgement, 11 audit — against three
tests: is the discriminating input serialisable, is the decision reached in one call,
and is the expected outcome a verdict rather than state.

**48 are vector-expressible. 38 are not, and the audit suite is 11 of 12 obligations.** On top of
those sit the 35 mutation cases, which delete a line of the implementation's own source
and can never travel as data.

`spec/vectors/CLASSIFICATION.md` carries the per-case table; where a case fails closed,
the rule and the raising function were taken from a run rather than from its docstring.
Three rows moved as a result: the operator-substitution attack (AT-2) refuses under the
default capability context, so its fixture's context change is scene-setting rather than
the discriminator; the receipt-claims-reversible attack (RV-3) refuses inside `execute`
with no deferred gate present, despite its gate fixture; and the one-key-two-identities
attack (PB-DISTINCT) never reaches an Executor at all, so the corpus needs a
bundle-load verdict class it does not yet have.

`spec/vectors/OBLIGATIONS.md` is the first draft of the other half, and states the limit
plainly: **passing every vector is a partial claim.** Three of the six defects fixed on
this branch would have been invisible to any vector in the corpus — a bundle hash that
dropped a field, a file count that had drifted, and a fail-safe default that set a value
nothing read. None of them changes a verdict on any input. It also records what the
corpus cannot carry and what replaces it: signatures are not transportable, so vectors
declare **seeds**, not keys, and rely on `HybridKey` deriving both halves
deterministically — a property `sim.supervise` already requires for its own reasons.

This is the gate ticket for the vectors project: the 47 sizes extraction (VEC-3/VEC-5),
and the 38 plus the mutants size VEC-6. It also says VEC-2 is underestimated — eight
cases need a declared signature-mutation vocabulary, fourteen need a pending-release
precondition block, and one needs the bundle-load verdict class above. None exists.

---

## Unreleased since v1.3.14 — a fourth released defect, found by somebody else's attacks

**Specification: DR-13 is added to §9.6 in v1.3.15**, alongside PB-6, PB-7 and
AT-9 below. The version does not move again; v1.3.15 is unreleased and has no
readers, so the clause is folded in rather than minted as a v1.3.16 that would
describe a document nobody ever held.

**The defect (ACP-32).** Risk is recomputed from the *target resource's* tier
floor; reversibility is a property of the *action class*. They are orthogonal,
so an action can be `IRREVERSIBLE` and `LOW` at the same time — and every clause
governing what happens to an irreversible action lived behind DR-1, which scopes
the deferred-release gate to floor-HIGH. Below HIGH the Executor computed the
reversibility class, compared it against the receipt for RV-3, and **discarded
it**. An irreversible action on a T0/T1 target executed with no notification, no
acknowledgement, and no record that a human existed. RV-1's fail-safe default —
absent from `reversibility.json` ⇒ `IRREVERSIBLE` — set a value that nothing on
that path read, which makes it documentation rather than a control.

Mail exfiltration is exactly this shape, and it is the most common goal in the
public indirect-prompt-injection corpora. Floor an inbox at T1, which is the
natural choice because reading mail is routine, and an injected `send_email`
goes out unseen.

**How it was found, which is the part worth keeping.** Not by reading, and not
by any suite in this repository. `reference/suites/art_harness.py` — added in the
same batch of work, to run an external adversarial corpus against Door A instead
of the author's own attack list — printed it on its **first run**, as case
`fx-04`. Every other suite here was written by the party being defended, so the
attack list and the clause list shared one blind spot: mutation testing cannot
find a check that was never written, and the prose differential compares two
readings of a document that does not mention the case. The harness was built on
the argument that this would eventually happen. It happened immediately.

**The fix, and what it deliberately is not.** DR-13 requires that an
`IRREVERSIBLE` action graded below floor-HIGH commit a **notice** — to the
Executor's own durable state, before the action executes — addressed to a
recipient set named in the **signed bundle**. It does **not** require
acknowledgement. DR-9's friction is affordable at floor-HIGH because a human
quorum has already been paid for; below HIGH there is no quorum and the traffic
is the bulk of a deployment, so demanding acknowledgement there would page a
human for routine work at volume, which is T-26 habituation and AT-7
rubber-stamping — and W2 already recorded that saturating approvers produces
assent, not refusal. **Detection instead of prevention, and stated as the weaker
guarantee it is.**

Three consequences, each stated in the clause rather than left to be discovered:

- **The recipient set is bundle policy, not notifier configuration.** A
  notification service that picks its own audience is certifying its own
  coverage, which is RES-8 and the exact shape of the still-open T-32. In the
  bundle, "who would have found out" is readable off signed policy.
- **An irreversible class below HIGH with no recipients named fails closed.** A
  notice with no addressee is not a detection channel, and DR-8's rule does not
  become false because the risk grade is lower. The deployment names recipients
  or floors the class at T2+ and moves it onto the deferred path under DR-9.
- **EO-2 is respected by weakening the obligation on purpose.** EO-2 budgets
  25 ms p99 end-to-end for LOW and MEDIUM decisions, and a synchronous confirmed
  delivery does not fit — two normative requirements that cannot both hold, the
  DR-6 defect class. So what DR-13 makes a precondition of execution is the
  *local durable commit*, not delivery. That is genuinely weaker than DR-8, and
  the residual is named: a notice committed and never delivered leaves an audit
  record and no human. Reconciling committed notices against delivery outcomes
  is a deployment obligation, counted separately from DR-12 because releases on
  this path are unacknowledged by construction and would otherwise swamp the
  signal DR-12 exists to carry.

**What did not change: the harness's floors.** `inbox` is still T1 and
`public-web` still T0. Raising them would have made the finding disappear and
proved the harness can be tuned, which is the failure mode it was written to
avoid. What moved is the Executor. `fx-04` now reports a new outcome,
`EXECUTED_NOTIFIED`, which sits between `ESCALATED` and `EXECUTED_SILENTLY`
because nobody was asked but a record exists. Reversible low-tier actions still
execute silently and should — DR-7's argument is that silence is acceptable
exactly where a missed detection is bounded by reversibility.

**The action still happens.** DR-13 makes it loud, not safe. Whether an inbox
should have been floored at T1 is A-7, and A-7 remains conceded unprovable.

Evidence: conformance 50 → 52, consolidated registry 79 → 80, executor mutants
24 → 25 (35 across all suites). One mutant, not two: the block has a branch that
refuses when no recipients are named, and a `record_notice` call that raises
nothing. Mutation scoring measures branches that can refuse, so a mutant
deleting only the commit would SURVIVE — not because the commit is dead code but
because "the attack now succeeds" is the wrong instrument for it. The commit is
covered by a positive-path assertion and labelled as one, rather than dressed up
as a control. Same reasoning already recorded here for `need_roles = b.quorum_k`.

**A third silent drop in `ResearchBundle.hash()`, and a check so it is the last.**
`sim/bundle.py`'s subclass **restates** the parent's hash dict rather than
extending it, so every field added to `Bundle.hash()` must be added there by
hand. `notice_targets` was the third to be missed — after `quorum_k` and the
attester registry — and nothing failed on any of the three: the subclass hash is
self-consistent whatever it covers, and no line of the `--suites` gate runs that
file. Two research bundles that would notify different people would have agreed
they held the same policy, which is the PB-KEY defect class and the argument
written in that method's own comments.

Fixed, and then made unrepeatable: `sim.bundle --check` gains a case that
enumerates fields from `dataclasses.fields` and requires every one to move the
hash. Enumerated rather than listed, so a field added tomorrow joins the check
without anyone remembering — a hand-written list of field names would be a second
definition of the class's field set, the encoding-split defect inside the check
meant to catch it. Proven non-vacuous by removing `notice_targets` from the
subclass hash again and confirming it fails **and names the field**. 14/14 → 15/15.

**A separate defect, found by re-running the tooling self-test.** The published
covered-file count said **128** while the signer covered **129** — the harness
commit added a file and did not update the prose. `tools/selftest.sh` asserts
exactly this equality and was red at `HEAD` before this change, which the prior
session's handoff had recorded as passing. Now **130**, `notice_targets.schema.json`
having landed with DR-13. Filed as ACP-34, because the interesting part is not
the number: the assertion existed and did its job, and nobody ran it.

**Both DR-13 branches are covered by something that can fail, and this was
checked rather than claimed.** The refusal branch has the 25th mutant (KILL).
For the commit, the executor was edited to drop *only* `record_notice` while
keeping the refusal — conformance goes **51/52 NOT CONFORMANT** and the harness
raises `AssertionError: irreversible below-HIGH execution left no notice`. A
positive-path obligation asserted to be covering something is worth exactly as
much as the experiment that shows it failing.

---

## Unreleased since v1.3.14 — INV-1-HIGH did not hold, CR-4 was ordering the unorderable, and the specification is why

**Specification version moves to ACP-SPEC-001 v1.3.15** (from v1.3.13; there is
no v1.3.14 — see below).


**Read this before anything else in this file.** v1.3.14 as tagged and signed
contains three defects in released code. Two are the same defect wearing
different clothes: in both, the holder of **one** attester key satisfies a
floor-HIGH quorum without forging anything. The third lets a signed
post-quantum floor be met by a suite that does not implement the algorithm the
floor names.

**The threshold (ACP-28).** §9.3 step 7b computed the quorum size as
`entries[0]["obj"]["required_count"]` — out of the Attestation Object, which is
the artifact under verification. One compromised key signs one genuine,
correctly-bound object saying the quorum required is one, and the action
executes. Sixth recurrence of the RES-8 class, and the first not found at the
frontier: it sat in the receipt-consumption path, the oldest surface the
classification table covers and the one that document had recorded as needing
no re-examination. Fixed with `Bundle.quorum_k` — required, un-defaulted, inside
`Bundle.hash()` — recomputed at verification time. `required_count` stays in
AT-1 as evidence of what the attester was shown, consumed by nothing.

**The registry (PB-DISTINCT).** `quorum_k` counts distinct attester *names*, and
the registry maps a name to a key. Two names against one key let one holder sign
two objects with different nonces and satisfy k=2 alone. Refused at bundle
construction. JSON Schema cannot state it — there is no uniqueness keyword for
the values of a map — so `attesters.schema.json` states the rule and names the
loader as the enforcement point.

**Two unshipped defects, in the `feat/rule-store` code, fixed before it lands.**
The bundle tree hash covered `members` and not `signature.suite`, leaving the
field that names *which primitives to require* outside the signature it belongs
to — CR-3 downgrade reintroduced by the code written to prevent it. And
`verify_hybrid` took no suite, so the caller decided how many primitives a
hybrid signature needed. Both fixed; `acp_bundle`'s pinned Python differential
constant moved with the hashed shape and was regenerated from Python, not
adjusted until Rust agreed with itself.

**A third released defect, in CR-4 itself.** The suite floor was compared by a
rank table — `{ed25519: 0, slhdsa128s: 1, hybrid: 2}` — which is a total order
over sets of primitives that are not comparable. `hybrid` is `{classical, pq}`
and contains no `pq-slh`, yet it outranked `slhdsa128s`: a deployment whose
signed floor said "hash-based post-quantum, no lattice assumption" accepted a
signature whose post-quantum leg was ML-DSA, and the floor check reported
satisfaction. Not a stronger suite accepted — a different hardness assumption
substituted. CR-4 is **containment** now, in both languages: the offered suite
satisfies the floor iff it carries every primitive the floor names. The rank
table is deleted, and the Rust test that pinned its values against the Python
ones is replaced by one pinning the primitive sets. The ranks agreed across both
implementations and were wrong in both, which is the thing to remember about a
differential test: agreement is evidence about consistency, never about
correctness.

**The specification moves too — v1.3.13 → v1.3.15.** All three released defects
were downstream of a gap in the normative text, so fixing only the reference
would leave a second implementation free to rebuild them and be conformant while
doing so. `PB-6` gives the quorum threshold a home in the signed bundle; `AT-9`
makes it recomputed-only *and* requires the attestation's stated count to match;
`PB-7` requires attester keys to be pairwise distinct and makes a violating
registry an invalid bundle; `CR-4` is restated as containment; §9.3 step 7b(iii)
and (vi) are rewritten to say which side is authoritative. There is no
specification v1.3.14 and never will be — the package release v1.3.14 shipped
with the document unchanged at v1.3.13, and minting a spec v1.3.14 now would put
two artifacts behind one version string, which is the X5 collision this document
wrote a rule against. §1 says so where a reader will find it.

**A correction inside the correction, and the more useful half.** The first pass
at ACP-28 recomputed the threshold and *deleted* the check comparing the
attestation's stated `required_count` against it, arguing that the bundle hash
already binds the threshold transitively so an equality test kills no mutant.
Every step of that is true and the conclusion is wrong: it enumerated only
attacks that **lower** the threshold. Raising the stated count is not an attack
on INV-1-HIGH at all — it is an attack on **consent**. Attesters shown "3
approvals required" sign on that basis; executing after two removes a reviewer
they were relying on, with every signature valid and the invariant intact. It
has its own attack and its own mutant, and AT-9 now mandates both halves and
says explicitly that neither substitutes for the other.

Restoring it then *masked* the threshold mutant — the fourth masking recorded
here — which was resolved by admitting that `need_roles = b.quorum_k` raises
nothing and is therefore not a check but a choice of data source. The two
branches that can refuse are AT-9's equality and AT-3's comparison; both are
mutation-proven, and `a_AT3_partial_quorum` (one genuine approval, honestly
stating two) is the only quorum attack here that no earlier check catches.

*The general form, twice demonstrated in one fix:* **"this check is redundant"
is a claim about the attacks you enumerated, not about the check.**

Evidence: conformance 45 → 50, consolidated registry 74 → 79, executor mutants
20 → 24 (34 across all suites), Rust tests 25 → 32. Every check that can refuse
is mutation-proven load-bearing.

The CR-4 mutant is the first in this repository that does not delete anything:
it swaps the set comparison for a scalar one. Every previous mutant asked "is
this check load-bearing?" and none could ask "does this check mean the right
thing?" — which is why a present, load-bearing, wrong CR-4 survived four
releases. Recorded in `dossier/05-TEST-EVIDENCE.md` as a limit of the method,
alongside a new §15 RES-0 in the specification stating what differential
evidence cannot tell you: the rank table was byte-identical across two
implementations and a passing differential test asserted their agreement.

`dossier/05-TEST-EVIDENCE.md` also carried a stale conformance total (44/36
against a suite printing 45); corrected in the same pass.

---

## Unreleased since v1.3.14 — the live-agent client is covered, and a scenario edit is withdrawn

Three changes to `sim/llm_agent.py` and its documentation. None of them touches
the specification, the Executor or any control.

**Suite 10 (44 checks) — the client is no longer untested.** `sim/llm_agent.py`
was the one load-bearing file with no automated check of any kind; its evidence
was hand-runs against the paid API, so a regression in it would have printed
green indefinitely. `call_model()` is split so `parse_model_reply()` can be
handed fixtures, and the suite needs no key and no network. It was mutation-
checked rather than trusted for passing first time. Six mutations, all killed:
disabling the `stop_reason` check kills 5 and reproduces the original defect
verbatim, re-adding a deviation paragraph to the report kills 2, and removing
code-fence stripping, dropping an undecodable `params`, or failing to wrap a
non-list `actions` value kill 1 each. A sixth corrupts an expectation in the
fixture corpus itself, so the data comparison is demonstrably not vacuous. The gate now
prints **17** result lines (a harness line was added since). Coverage was **118** files at that point and is
**130** now, the bundle schemas, `acp-bundle`, the external-corpus harness and
DR-13's `notice_targets` schema having landed since.

**A scenario edit is withdrawn.** The poisoned supplier report had been given an
out-of-spec deviation paragraph so that a correct model would have legitimate
work and Phase 1 would stop printing an empty array. That edit was made after
seeing an unwanted result and it produced the wanted one — the shape of changing
the test until it passes. It is reverted; the report is byte-identical to the one
that shipped. The agent's legitimate work now comes from a **separate** document
in the same triage batch, which also gives the demo a property the deviation
never did: the legitimate work and the injected instruction have different
sources, so a reader can see whether text planted in one produces actions
attributed to the other.

**Structured outputs are now disclosed, not just commented.** The client
constrains the *encoding* of the model's reply via a JSON schema on the request.
This is documented as **RES-L1** in §06 with the encoding/content distinction
stated explicitly, and pinned by a suite check that fails if the schema ever
grows an enumeration of permitted actions — which would turn it into a §5.1a
model-side defence. **RES-L2** records the matching limit: no suite can say what
a live model will propose, so Phase 1's outcome is never evidence about the
control plane.

---

## What changed in v1.3.14 — the reference Executor uses real asymmetric signatures

Through v1.3.13 the Python reference modelled signature primitives with
HMAC-SHA256, on a stated and — for almost everything — correct ground:
substituting real COSE changes no control flow, so the protocol properties the
suites test are unaffected by which primitive signs the bytes.

**That ground did not cover the headline claim.** HMAC is symmetric. Verifying a
signature means holding the key that produced it, so `Bundle.attester_keys` and
`Bundle.receipt_key` were *signing* keys, and the Executor held all of them. An
Executor that could verify a quorum could mint one. **INV-1-HIGH — no floor-HIGH
action executes without k independent human attestations — did not hold against a
compromised Executor**, which is one of the adversaries it names. No amount of
protocol testing could have found this, because the defect was key **custody**,
not control flow: all 44 conformance cases passed throughout, and were right to.

What changed:

- **Real primitives.** `classical` → Ed25519 (RFC 8032), `pq` → ML-DSA-65
  (FIPS 204), through `reference/src/acp_crypto.py`, which already implemented
  both. Composition is untouched: CR-1..CR-5 stay conjunctive.
- **The Bundle carries public keys only** (`HybridPub`). No signing key is
  reachable from the verifier, and the type now says so.
- **Deterministic key derivation.** `HybridKey` derived its Ed25519 half from
  its seed but took its ML-DSA half from an *unseeded* `keygen()`. Harmless
  while a key never left one process; fatal across the seven OS processes of
  `sim.supervise`, where each would have minted a different post-quantum key for
  the same identity and every hybrid signature would have failed closed at the
  process boundary. Both halves now derive from the seed (FIPS 204
  `KeyGen_internal`). Seeds are simulation material; a deployment loads keys
  from a KMS.
- **Cost, measured rather than assumed.** `--suites` goes from seconds to
  minutes: pure-Python ML-DSA-65 signs in ~210 ms and verifies in ~34 ms against
  microseconds for HMAC. The gate is a release artifact, not a dev loop, and the
  number is itself the point — `reference/src/acp_crypto.py` prints it.

**Still open, named so it is not mistaken for done:** the carrier is canonical
JSON via `canon()`, not COSE_Sign1 — canonical CBOR is implemented and tested in
`acp_crypto` but is not yet the envelope. And `slhdsa128s` (SLH-DSA, FIPS 205)
is **declared in `SUITES` and not implemented**; it now has its own primitive
name so it cannot be silently satisfied by an ML-DSA key, and it fails closed.

### A correction worth recording — the bundle hash did not cover the key registry

Making the keys asymmetric moved the weight of the design onto the key registry,
and exposed that `Bundle.hash()` never covered it. Spec §8.2 puts `attesters/` —
"approver + confirmer public keys" — inside the bundle tree and signs "SHA-256 of
canonical bundle tree". The reference hashed the floors, the risk functions, the
adapters, the schemas, the reversibility table and the suite floor, and not the
keys.

The honest scope is narrower than it first sounds, and worth stating precisely
because the temptation is to state it larger. It was **not** a live quorum
bypass: an Executor verifies attestations against its own registry, so swapping
one Executor's registry never pushed a forged quorum through another. What broke
is **identity, and therefore audit**. Two bundles authorising different approvers
hashed identically, so `policy_bundle_hash` did not determine who was allowed to
approve — and P-3, "Decisions are replayable bit-for-bit from audit", did not
hold, because the record did not distinguish them. RES-8 family, again: a claimed
binding must be verifiable from the signed bytes of both artifacts.

Closed by **PB-KEY**: the registry is hashed, as a fingerprint over *both*
primitives of each public key — a fingerprint over the classical half alone would
let an ML-DSA key be swapped without moving the bundle hash, which is the
conjunctive CR-3 guarantee undone at the registry rather than at the verifier.
Conformance goes 44 → **45** and the executor mutants 19 → **20**; the new mutant
deletes the coverage and confirms the attack then succeeds, so the check is
load-bearing rather than defence in depth.

---

## What changed in v1.3.13 — the polyglot restructure

A structural release: no rule changed, and every number that replayed in v1.3.12 replays here. The repository was reorganised from a Python-only dossier into a polyglot monorepo so a second implementation surface (Rust, TypeScript) can be held to the same evidence.

- **New layout.** `spec/` (the normative source), `dossier/` (the argument), `reference/` (the Python implementation, `src/ suites/ proofs/`), `crates/` and `services/` (Rust), `packages/`, `orchestrator/`, `deploy/`, `tools/`. `docs/` holds working documents and sits deliberately outside the signed roots.
- **Two gates.** `./tools/verify.sh --suites` runs proofs and all 13 suites without the release key and is the per-commit gate; full `verify.sh` adds integrity and signature and is the release gate. Between releases, sections 1–2 are expected red — a property of offline signing, not a finding. See `dossier/07-REPRODUCTION.md`.
- **Manifest coverage** is now three allowlists (roots, git-tracked, extension) with the signer **halting on an unrecognised file type**, rather than an extension allowlist that silently skipped `.json`, `.rs`, `.ts` and the poisoned `.html` attack fixture. `.gitignore` is itself signed, because the signer derives its file set from it. `sign` builds into temporaries so a mistyped key path cannot destroy the last valid manifest.
- **Five new residuals** from the second implementation surface (RES-P1..P5) are disclosed in `dossier/06-RESIDUAL-RISK.md`. The load-bearing one: splitting the notifier and approval codebases improves build-time provenance but does **not** close T-32, which stays open.
- **Rust and TypeScript are scaffold.** `crates/acp-core` and `acp-crypto` carry the fail-safe defaults and CR-3 hybrid composition with tests; the services exit non-zero so a scaffold cannot be mistaken for a running control plane. `spec/vectors/` — the shared conformance corpus that makes "44/44" mean the same in both languages — is not yet extracted.

### A correction worth recording — the published fingerprint was wrong

For the whole v1.3.13 window, `README.md` published the release-key fingerprint `SHA256:614ea014…`, which belongs to a **superseded key**. `RELEASE.md`, `release-key.pub` and `MANIFEST.sha256.sig` were correct and consistent throughout: the true fingerprint is `SHA256:c6334fda510760d9125e94ce8c900e56`.

Nothing was mis-signed, and no signature ever verified against the wrong value. The damage is narrower and more embarrassing: a reader who performed the out-of-band check the README itself instructs them to perform would have got a **mismatch on an authentic package** — precisely the failure an out-of-band anchor exists to prevent. The document told its most careful readers to distrust it.

Two things are worth noting about how it survived. It was proofread repeatedly without being caught, because a 32-character hex string reads as opaque and correct to a human eye. And it was mechanically derivable from `release-key.pub` the entire time — this repository's own rule is that anything checkable by a command must be checked by a command, and this was not. The rule was right; it had simply never been applied here.

`tools/selftest.sh` now recomputes `sha256(raw pubkey)[:32]` from `release-key.pub` and asserts that **every** `SHA256:` fingerprint in every git-tracked Markdown file matches it, failing also when it finds none, so deleting the line cannot turn the assertion green. The self-test went from 27 assertions to 29, and to **34** in v1.3.14 with the mutant-import guard below and a covered-file-count check. Reintroducing the stale value was confirmed to fail it.

## What changed since v1.3.10

### 1. AC-5, AU-6 (revised), AU-7, AU-8 — implemented

These were normative text with no mechanism: §06 listed them as "closed on paper, not exercised". They are now implemented in `reference/src/acp_audit.py` and attacked in `reference/suites/audit_suite.py` (11/11, plus 4/4 mutants).

The module **extends** the frozen reference gate rather than editing it, so all 44 conformance vectors and all 19 original mutants still pass unchanged.

- **AU-8** — chain genesis is the hash of an anchored tenant-creation record, anchored immediately. A tenant chain destroyed inside its first window still leaves evidence it existed.
- **AU-7** — a floor-HIGH release is covered by an external anchor **before** the action is released; an unreachable anchor fails closed. T-29's pre-anchor rewrite gap is gone; the only rewrite left is post-anchor, which reconciliation detects.
- **AC-5** — accumulators count executions, not Decisions. Repudiated and timed-out actions increment nothing, so T-28's attributed-then-repudiated lockout of a victim operator does not accumulate. A DS-3 re-drive counts once.
- **AU-6** — during an anchoring outage, DR-10 sampling is suspended, so the ATTEST cap cannot compound with DR-9 acknowledgement into approver saturation (T-30 / W2).
- **§11.3 (g)/(h)** reconciliation implemented: executed floor-HIGH records covered by an anchor dated at or before release; every accumulator increment traced to one released execution.

### 2. Suite 5 now has the tests it always claimed

v1.3.10 reported "canonical CBOR 8/8". The validating decoder existed; **no test asserted any of it**. `reference/suites/cbor_suite.py` supplies the eight cases (canonical round-trip, key order, non-shortest argument, indefinite length, trailing bytes, duplicate keys, floats, two-encodings-one-value).

This was a green number with no artifact behind it, in a dossier whose §07 opens by telling the reader not to believe exactly that. Recorded rather than quietly fixed.

### 3. Three defects found while building the above — disclosed

The pattern C2 → X1 → Y1 → Z3 → W1 continues, in the newest machinery, as predicted:

| | Defect | Caught by |
|---|---|---|
| **V1** | **Anchor-then-mutate.** The release record was anchored as `pending`, then set to `executed`; the anchor committed to a superseded chain. The CL-7 shape — mutation after the commitment point — reintroduced one layer up by an author who had just read the CL-7 fix. | reconciliation check (g) |
| **V2** | **A masked mutant.** The first AC-5 mutant did not isolate the counter: the T-28 repudiation attack is blocked upstream by DR-4 and never reaches it. Same masking as X1 and B-1a in Suite 2. Re-isolated on the re-drive path. | mutation harness |
| **V3** | **A redundant check.** An up-front anchor-reachability pre-check survived mutation — the terminal guard already fails closed. Removed rather than retained as decorative defence in depth. | mutation harness |

V3 is the one worth reading twice: the harness refused to credit a check that stopped no attack, and the correct response was deletion, not a better story about it.

### 4. Identifier hygiene

- **RR-n** now denotes residual risks in §06 (was R1/R2, which collided with the R1–R10 *relation* series in `02b`). RR-1 is the absent independent review; RR-2 is A-7 label honesty.
- §01's verification table no longer reads "44/44 fail closed": the suite is 36 attacks failing closed **and** 8 honest paths executing, which is the criterion §05 actually states.
- The 13,492 B figure is identified as a four-signer floor-HIGH receipt (4 × 3,373 B), so it is derivable from what `acp_crypto.py` prints.
- Artifact outputs carry the spec version they were generated against.

### 5. Two concessions added to §06

- **A-8's "two independent compromises" is conditional.** Path independence (DR-2) is an organisational and code-structure property, not one provable from trusted bytes — the same *kind* of assumption as A-7, and Suite 2 already caught an implementation that looked independent and was not.
- **A third composition is named.** On the reversible path the only human control is notification; T-26 says notification degrades through use; A-7 now covers reversibility labels. An action mislabelled `REVERSIBLE` therefore inherits the weakest control in the system, with no attack required.

---

## What has *not* changed

**RR-1 is still open.** No independent adversarial review has taken place. Everything after DS-6 — including all of the above — is mechanized and tested, and **unconfirmed by any party without revision history on this document**. The v1.3.11 machinery is the newest and therefore the most suspect.

**RR-2 is still open and always will be.** No mechanism decides whether a sensitivity or reversibility label matches the world.

This package is sufficient to **evaluate** the architecture. It is not sufficient to deploy it.

---

## Signing

```bash
./tools/sign-release.sh keygen                     # once, on an offline host
./tools/sign-release.sh sign ~/acp-release.key   # regenerate manifest + sign
```

Publish the fingerprint **out of band** — repository README, talk, review brief. A public key that ships only inside the package it authenticates proves nothing, which is the same argument this dossier makes about every other transmitted value.

---

## Open decisions before external publication

Two items need a human decision, not a code change:

1. **ATLAS pinning (§02).** The methodological warning says the ATLAS version and date "must be recorded here" and the field is still blank. Pin it, and resolve `AML.T0110`: it is included with a note that only one source corroborates it, while `AML.T0048` was excluded under a stated two-source rule. Either apply the rule to both or state the exception.
2. **Reviewer selection (RR-1).** The reviewer must read Dafny proof artifacts, not only run a penetration test. §07 names where to start; `acp_audit.py` should be item zero.
