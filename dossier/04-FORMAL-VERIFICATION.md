# 04 — Formal verification

**Tool:** Dafny 4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2, Z3 4.12.1
**Command:** `dafny verify --function-syntax:4 reference/proofs/binding.dfy`
**Result:** `36 verified, 0 errors` — raw output in `reference/proofs/dafny-output.txt`

## What the model covers, and its boundary

The model proves **protocol reasoning**, not cryptography. Hashing is an injective uninterpreted function; signing is a key-indexed relation over exact bytes. That SHA-256 or Ed25519 resist anything is assumption A-3, outside the model.

Part V models signature **composition**, not primitives: "broken primitive" is `Forge`, an explicit forgery function producing an accepting signature for any message.

Part IV models the release decision only. **Human acknowledgement enters as an input, never as evidence that a human read anything.**

## Load-bearing theorems

| Theorem | What it establishes |
|---------|---------------------|
| `Y1_AttackBlocked_Generalized` | No misbound attestation verifies, against an attacker holding **arbitrarily many** observed signatures |
| `DR9_IrreversibleRequiresNonOperatorAck` | For an irreversible action, **no receipt and no sampling draw** permits release without acknowledgement from a non-operator party |
| `CR3_AND_SurvivesPQBreak` | Hybrid composition holds when one primitive is **totally** broken |
| `CR3_OR_IsWeakerThanEitherAlone` | Disjunctive composition is **weaker than either primitive alone** — the counter-theorem justifying the choice of AND |
| `Z3_MembershipCheckDoesNotPinOrigin` | A membership test is not a pinning test — the defect, mechanized |

Defects are mechanized as thoroughly as fixes. Proving closure without proving the hole existed is illustration, not verification.

## Negative controls

Nine mutants, all kill. Axiom-consistency smoke test: `assert false` **fails to verify**, so no theorem is vacuous by contradiction. Four non-vacuity witnesses, because most results are negations: without them, they would hold because nothing ever verifies.

## Two defects found inside the proof artifacts, disclosed

**Tautological postconditions.** Two lemmas asserted a derived key was "independent of the receipt" when the claimed value was **not an argument** of the function: true by typing, worthless as proof. Withdrawn. Parts IV and V deliberately keep the claimed value as a **live parameter** ignored by the body, so the independence lemmas constrain the body. The control is empirical: a mutant that makes the body read the parameter breaks five lemmas.

**A non-covering mutant.** Removing `operator` from the preimage killed nothing: no theorem keyed on it, so the Y4 fix was structurally present but formally unexercised. `Y4_OperatorTamperDetected` was added in response.

**Modelling note.** `Broken` was first written `forall m :: exists sig`. The nested existential gives the solver no trigger, and three proofs failed. Rewritten with an explicit Skolem function: `Forge` **is** the attacker's algorithm, and naming it is more honest than hiding it behind an existential.

## What is not proven

That any human read a notification. That a deployment's notification path is genuinely independent of its presentation path (a property of code, checked by conformance suite 3). That the cryptographic primitives resist anything. That sensitivity labels are honest.
