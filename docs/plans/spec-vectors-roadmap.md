# spec/vectors/ — roadmap and tickets

> **Tracked in Linear** — project *ACP — Shared conformance vectors*, team `ACP`.
> VEC-1 → ACP-1 · VEC-2 → ACP-2 · VEC-6 → ACP-3 · VEC-3 → ACP-4 · VEC-4 → ACP-5 ·
> VEC-5 → ACP-6 · VEC-7 → ACP-7 · VEC-9 → ACP-8 · VEC-8 → ACP-9.
> (Ticket numbers follow creation order, not VEC order — blockers are wired in Linear.)

**Is it important?** It is the single most important next piece. Everything on the
Rust/TypeScript side is unverifiable until it exists. "A second implementation of the
control plane" is only a real claim if both implementations are held to the *same*
evidence, and this corpus is that shared evidence. Without it, a Rust "45/45" would
just be Rust agreeing with tests a Rust author wrote — no link to the Python bar.

**How big?** Two tiers. Tier 1 (VEC-1..7, VEC-9) makes the corpus real and proves the
Python implementation still passes when driven from it — achievable in a few focused
sessions, no new cryptography or Rust logic required. Tier 2 (VEC-8) is Rust actually
passing the corpus, which needs enough of the Rust executor to evaluate a case, and is
better treated as its own milestone.

**The honest catch, up front.** Not every check can become a shared data file. Some are
sequences (an approval used twice), some are structural (two render paths that must be
distinct), and the 30 mutation checks work by deleting a line of source. Those stay
per-implementation obligations. Sorting which is which is the first ticket, not an
afterthought.

---

## Tier 1 — the corpus, and Python parity

| ID | Ticket | Size | Critical path |
|----|--------|------|---------------|
| VEC-1 | Classify every suite case (45 conformance, 8 encoding, 14 ack, 11 audit) as **vector-expressible** (one input → one verdict) or **obligation** (sequence / structural / source-mutation). Output: a classification table + the first draft of `spec/vectors/OBLIGATIONS.md`. | M | ✅ |
| VEC-2 | Define the vector file format and its JSON schema: `id`, `rule`, `scenario`, `mutation`, `expect`. Defined over **canonical bytes and declared mutations, never signatures** (RES-P5), so it is portable to real-crypto Rust. Ship one hand-written example that actually runs. | S | ✅ |
| VEC-3 | Extract the ~30 vector-expressible conformance cases from the Python fixtures into `spec/vectors/conformance/*.json`. | M | ✅ |
| VEC-4 | Python vector **runner**: make `conformance.py` execute *from* the vectors and prove the pass/fail set is byte-identical to today (45/45 unchanged, every attack still fails on the same rule). This is the parity proof — the corpus is only trustworthy once the reference passes from it. | M | ✅ |
| VEC-5 | Extract and run the remaining input→verdict cases: encoding/CBOR (8), and the ack/audit cases that qualify. | S | |
| VEC-6 | Write `OBLIGATIONS.md` properly: the 30 mutants (20/6/4), AU-7 anchor-before-release ordering, partition behaviour, render-path distinctness, prose differential — each naming the property and why no vector can express it. This is what stops a green total from implying more than it checked. | S | ✅ |
| VEC-7 | Corpus index + integrity: `spec/vectors/MANIFEST.json` listing every vector (id, rule, category), and fold the vector files into the signed release manifest. | S | |
| VEC-9 | Update the dossier (`05-TEST-EVIDENCE`, `07-REPRODUCTION`) to describe the corpus and the two-tier claim: vectors prove input→verdict across implementations, obligations are proven per-implementation. | S | |

## Tier 2 — Rust actually passes it (own milestone)

| ID | Ticket | Size | Notes |
|----|--------|------|-------|
| VEC-8 | Rust vector runner in `crates/acp-conformance`: read the same corpus, evaluate each case, report pass/fail. **A correction worth recording:** this row used to place the Executor work across the repository boundary, on the grounds that it left with the services (ACP-66). That is contradicted — ACP-45 slice 6 composed the §9.3 checklist in *this* repository, in `crates/acp-decision`, over `acp-core`'s generated types and `acp-crypto`. The blocker is the corpus: `spec/vectors/` holds `CLASSIFICATION.md` and `OBLIGATIONS.md` and no vectors, so a runner has nothing to read. What is left after that is a residual rather than a boundary — `acp-decision` implements the stateless steps only and names each absent one with its owner (nonce single-use and DS-6 origin pinning need the ledger, ACP-46; the deferred-release gate, ACP-47; the live capability recheck waits on a Context Store provider), so a corpus case whose verdict depends on one of those must be classified blocked, not counted green. Likely splits into several tickets once VEC-1 reveals the corpus shape. | L | Blocked by VEC-1..4 |

---

## Suggested order

VEC-1 → VEC-2 → (VEC-3 ∥ VEC-6) → VEC-4 → VEC-5 → VEC-7 → VEC-9, then Tier 2.

VEC-1 is the gate: its classification decides how many cases VEC-3/VEC-5 extract and how
much lands in VEC-6, so nothing downstream can be sized until it is done.
