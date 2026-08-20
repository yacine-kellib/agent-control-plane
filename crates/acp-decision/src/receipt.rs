//! The §9.3 receipt gate: canonical bytes, CR-1, CR-4, CR-3, and the two
//! refusals that precede every other check.
//!
//! `grade.rs` decides what an action *needs*. This module decides whether the
//! thing claiming that need was actually issued by the signing substrate, and
//! it is the first code in Rust that reads `manifest.min_suite`.
//!
//! # Why the order in [`verify_receipt`] is not negotiable
//!
//! CR-4 runs **before** the signature, copying the worked precedent in
//! `acp_bundle::verify`. A suite below the floor is refused even when its
//! signature is impeccable: the floor exists to rule out *primitives*, not
//! forgeries, and checking the signature first would mean spending the
//! verification on bytes the deployment already declined to accept. It also
//! keeps the refusal honest — `SuiteBelowFloor` says the deployment's policy
//! was not met, which is a different fact from "this signature is bad".
//!
//! # The floor comes from the signed bundle, and this is its first consumer
//!
//! `manifest.min_suite` has existed since the rule store landed and **nothing
//! has ever read it** — `acp-bundle`'s verifier deliberately does not, because
//! a bundle cannot be its own floor without asking the party under verification
//! how strictly to judge it. A receipt is a different object: the floor for a
//! receipt lives in the bundle, the bundle's own floor comes from the
//! verifier's out-of-band configuration, and that asymmetry is the whole point.
//! Reading `min_suite` here rather than from the receipt is TR-8 at the suite
//! boundary.

use acp_core::generated::SuiteId;
use acp_crypto::{verify_ed25519, verify_mldsa65, Primitive, PrimitiveVerdict, Suite};

use crate::Refusal;

/// §9.3 step 1 — the signature did not verify under the bundle's receipt key.
pub const CLAUSE_SIGNATURE: &str = "9.3-1";
/// §9.3 step 2 — the decision was not ALLOW.
pub const CLAUSE_DECISION: &str = "9.3-2";
/// CR-1 — the suite name is not one this build knows.
pub const CLAUSE_UNKNOWN_SUITE: &str = "CR-1";
/// CR-4 — the offered suite does not contain every primitive of the floor.
pub const CLAUSE_SUITE_FLOOR: &str = "CR-4";
/// AT-8a — the structure is not canonically encodable.
pub const CLAUSE_CANONICAL: &str = "AT-8a";

/// Bridge the **generated** wire vocabulary to the **hand-written** one.
///
/// Two `from_wire` tables have described one wire vocabulary since phase 8 —
/// `SuiteId`, generated from `spec/schemas/bundle/`, and `Suite`, hand-written
/// in `acp-crypto` because the crypto crate must not depend on the schema
/// generator. Until this module they never had to meet, so nothing would have
/// noticed them drifting apart.
///
/// This match is **exhaustive and total by construction**: adding a variant to
/// the generated enum stops the crate compiling until it is mapped here. That
/// is deliberate and is stronger than a runtime lookup returning `Option`,
/// which would let an unmapped suite become a runtime refusal in a build that
/// compiled cleanly. `suites_agree_on_every_wire_name` covers the other
/// direction, which the compiler cannot see.
pub const fn suite_of(id: SuiteId) -> Suite {
    match id {
        SuiteId::Ed25519 => Suite::Ed25519,
        SuiteId::HybridEd25519Mldsa65 => Suite::HybridEd25519MlDsa65,
        SuiteId::Slhdsa128s => Suite::SlhDsa128s,
    }
}

/// CR-1 — parse a suite name, refusing an unknown one rather than defaulting.
///
/// An unknown suite is never resolved to a known one. The asymmetry with a
/// deployment profile is worth keeping in view: a suite *is* announced by the
/// signer and then checked against a floor, so parsing one costs nothing
/// because the announcement is not believed. That is exactly why this function
/// exists and why a profile has no equivalent.
pub fn parse_suite(name: &str) -> Result<Suite, Refusal> {
    Suite::from_wire(name).ok_or_else(|| Refusal::new(CLAUSE_UNKNOWN_SUITE, "unknown signature suite"))
}

/// AT-8a — the canonical bytes, reproducing `reference/src/acp_executor.py`.
///
/// Sorted keys, no whitespace, no floats, UTF-8. `serde_json::Map` is a
/// `BTreeMap` unless the `preserve_order` feature is on, so key order is sorted
/// by construction here; `to_string` emits no whitespace, matching Python's
/// `separators=(",", ":")`; and serde emits raw UTF-8 rather than `\uXXXX`,
/// matching `ensure_ascii=False`.
///
/// # The float guard is TOP-LEVEL ONLY, and that is deliberate — see ACP-75
///
/// The reference raises on a float only when the *whole object* is one, so its
/// guard has never fired in practice: every receipt carries float timestamps
/// **inside** the structure (`issued_at: 1000.0`). Making this one recursive
/// would be correct in isolation and would refuse every real receipt while
/// Python accepted it — a divergence that stops the differential rather than a
/// residual it can pin.
///
/// So this matches the reference **bug for bug, on purpose**, and the defect is
/// fixed on both sides at once under ACP-75. Changing the wire format inside a
/// slice that is trying to verify signatures over it would be the worst
/// possible moment.
pub fn canon(value: &serde_json::Value) -> Result<Vec<u8>, Refusal> {
    if value.is_f64() {
        return Err(Refusal::new(
            CLAUSE_CANONICAL,
            "float in canonical structure: not deterministic",
        ));
    }
    serde_json::to_vec(value)
        .map_err(|_| Refusal::new(CLAUSE_CANONICAL, "structure is not canonically encodable"))
}

/// The public keys a receipt is checked against, taken from the signed bundle.
///
/// Both halves, because hybrid composition is conjunctive (CR-3): a verifier
/// holding only the classical key could not tell a stripped post-quantum leg
/// from a suite that never had one.
#[derive(Debug, Clone)]
pub struct ReceiptKey {
    pub classical: [u8; 32],
    pub pq: Vec<u8>,
}

/// One primitive's signature as presented on the wire.
#[derive(Debug, Clone)]
pub struct SignaturePart {
    pub primitive: Primitive,
    pub bytes: Vec<u8>,
}

/// The §9.3 gate, steps 1 and 2, with CR-1/CR-4/CR-3 in the order stated above.
///
/// `floor` is the suite floor read from the **signed bundle manifest**, never
/// from the receipt. `decision` is the receipt's own field: it is the one value
/// here that is read rather than recomputed, and step 2 exists precisely so
/// that reading it can only ever cause a refusal.
pub fn verify_receipt(
    alg: &str,
    floor: SuiteId,
    key: &ReceiptKey,
    signed_bytes: &[u8],
    parts: &[SignaturePart],
    decision: &str,
) -> Result<(), Refusal> {
    // CR-1 first: an unparseable suite has no floor relation at all, so asking
    // whether it meets one would be a category error, not a refusal.
    let suite = parse_suite(alg)?;

    // CR-4 before the signature, per the module docs. Containment, never rank:
    // `hybrid-ed25519-mldsa65` is {classical, ML-DSA} and contains no SLH-DSA,
    // so it does NOT satisfy an `slhdsa128s` floor however "strong" it looks.
    if !suite.satisfies_floor(suite_of(floor)) {
        return Err(Refusal::new(
            CLAUSE_SUITE_FLOOR,
            "signature suite does not contain every primitive of the bundle floor",
        ));
    }

    // CR-3: verify every declared primitive and hand the whole verdict set to
    // the conjunctive combiner. The suite is a PARAMETER of that combiner --
    // the caller must not decide how many primitives a suite needs, because a
    // caller that decides can be persuaded to decide "one".
    let mut verdicts = Vec::with_capacity(parts.len());
    for part in parts {
        let verdict = match part.primitive {
            Primitive::Classical => verify_ed25519(&key.classical, signed_bytes, &part.bytes),
            Primitive::Pq => verify_mldsa65(&key.pq, signed_bytes, &part.bytes),
            // Declared, not implemented. Never a pass, and never silently
            // dropped from the set either -- dropping it would let a suite
            // naming it be satisfied by the primitives that remain.
            Primitive::PqSlh => PrimitiveVerdict::Unsupported,
        };
        verdicts.push((part.primitive, verdict));
    }
    acp_crypto::verify_hybrid(suite, &verdicts)
        .map_err(|e| Refusal::new(CLAUSE_SIGNATURE, format!("{e:?}")))?;

    // Step 2 is LAST among the cryptographic checks and that ordering is not
    // arbitrary: a receipt whose signature does not verify is not evidence of
    // anything, including of its own `decision` field. Reading the field first
    // would mean refusing an unsigned DENY under `9.3-2` and reporting a
    // decision value the substrate never actually asserted.
    if decision != "ALLOW" {
        return Err(Refusal::new(CLAUSE_DECISION, "decision is not ALLOW"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bridge, in the direction the compiler cannot check.
    ///
    /// `suite_of` is exhaustive over `SuiteId`, so a suite added to the schema
    /// breaks the build until it is mapped. What the compiler cannot see is the
    /// **wire spelling**: two tables could map the same variant to two
    /// different strings and both compile. This asserts they agree on every
    /// name, in both directions, for every generated variant.
    ///
    /// Without it, a schema rename would silently produce a build where a
    /// bundle's floor and a receipt's `alg` no longer refer to the same suite —
    /// and CR-4 would compare two vocabularies while looking correct.
    #[test]
    fn suites_agree_on_every_wire_name() {
        // Every variant the generated enum has. Adding one to the schema and
        // not to this list is caught by the exhaustive match below.
        let all = [
            SuiteId::Ed25519,
            SuiteId::HybridEd25519Mldsa65,
            SuiteId::Slhdsa128s,
        ];
        for id in all {
            // exhaustiveness canary: this match must have an arm per variant.
            match id {
                SuiteId::Ed25519 | SuiteId::HybridEd25519Mldsa65 | SuiteId::Slhdsa128s => {}
            }
            let generated = id.as_wire();
            let handwritten = suite_of(id).as_wire();
            assert_eq!(
                generated, handwritten,
                "the schema and acp-crypto disagree on the wire name for {id:?}"
            );
            // ...and the hand-written parser round-trips the generated spelling.
            assert_eq!(
                Suite::from_wire(generated),
                Some(suite_of(id)),
                "acp-crypto cannot parse the schema's spelling of {id:?}"
            );
        }
    }

    #[test]
    fn cr1_refuses_an_unknown_suite_and_does_not_default() {
        let e = parse_suite("ed25519-but-not-really").unwrap_err();
        assert_eq!(e.clause, CLAUSE_UNKNOWN_SUITE);
        // The control: a real name still parses, so the check is not passing by
        // refusing everything.
        assert_eq!(parse_suite("ed25519").unwrap(), Suite::Ed25519);
    }

    #[test]
    fn cr4_is_containment_and_a_hybrid_does_not_satisfy_an_slhdsa_floor() {
        // The published CR-4 correction, asserted here because this module is
        // the first receipt-side consumer of a floor: hybrid outranks slhdsa on
        // any numeric scale and contains none of its primitives.
        let hybrid = suite_of(SuiteId::HybridEd25519Mldsa65);
        let slh = suite_of(SuiteId::Slhdsa128s);
        assert!(
            !hybrid.satisfies_floor(slh),
            "a lattice signature satisfied a hash-based floor -- CR-4 re-committed"
        );
        // Control: the floor it does satisfy.
        assert!(hybrid.satisfies_floor(suite_of(SuiteId::Ed25519)));
    }

    #[test]
    fn canon_matches_the_reference_on_key_order_and_whitespace() {
        let v = serde_json::json!({"b": 1, "a": 2});
        assert_eq!(canon(&v).unwrap(), br#"{"a":2,"b":1}"#.to_vec());
    }

    #[test]
    fn canon_emits_raw_utf8_like_ensure_ascii_false() {
        let v = serde_json::json!({"k": "é"});
        // Python's ensure_ascii=False emits the character, not é.
        assert_eq!(canon(&v).unwrap(), "{\"k\":\"é\"}".as_bytes());
    }

    #[test]
    fn canon_refuses_a_top_level_float_and_accepts_a_nested_one() {
        // Both halves are the ACP-75 disclosure, asserted so the divergence
        // cannot vanish or move without this test saying so.
        assert_eq!(
            canon(&serde_json::json!(1.5)).unwrap_err().clause,
            CLAUSE_CANONICAL
        );
        // The nested float is ACCEPTED, matching the reference. When ACP-75 is
        // fixed on both sides, this assertion is the one that must change, and
        // it should change deliberately rather than be discovered.
        assert!(canon(&serde_json::json!({"issued_at": 1000.0})).is_ok());
    }
}
