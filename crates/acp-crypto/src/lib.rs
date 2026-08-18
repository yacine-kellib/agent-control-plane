//! Hybrid signature composition (CR-1..CR-5).
//!
//! Since v1.3.14 the Python reference uses the same real primitives this crate
//! does (Ed25519 + ML-DSA-65); it no longer models them with HMAC-SHA256.
//!
//! What is implemented here:
//!
//! - [`verify_hybrid`] — the conjunctive composition. Implemented first and
//!   deliberately: CR-3 is protocol logic, not cryptography, and the downgrade
//!   attack it prevents is a control-flow property testable without a single
//!   real signature.
//! - [`suite`] — the suite table, its CR-4 ordering, and the fact that
//!   `pq-slh` is declared and not implemented.
//! - [`primitives`] — Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204), which is
//!   what produces the verdicts the composition consumes. Added in rule-store
//!   step 2; until then this crate composed verdicts that nothing could
//!   compute. An `Unsupported` primitive is refused, never skipped.
//!
//! **The primitives interoperate with the Python reference, and that is
//! asserted rather than assumed.** `crates/acp-crypto/tests/python_interop.rs`
//! verifies signatures produced by `dilithium-py` and `cryptography` against
//! a committed fixture. Two crates naming the same standard does not make their
//! bytes interchangeable; carrying bytes across is the only thing that shows it.
//!
//! - [`custody`] — the `Signer` trait, the key material behind it, and the
//!   custody tiers T0–T3. This crate can now produce as well as verify, so the
//!   opposite direction — **Python verifying a Rust signature** — is no longer
//!   an undischarged obligation: `tools/check-rust-signatures.py` carries the
//!   bytes across and `tools/selftest.sh` runs it. T2 and T3 are declared and
//!   not implemented, behind the `kms` and `hsm` features, and refuse rather
//!   than downgrade.
//!
//! A custody tier is never read from the artifact being verified — it is a
//! property of a key, configured out-of-band, held by `custody::TrustedKeys`.
//! That is RES-8, and `custody.rs` opens with why the API is shaped around it.
//!
//! NEVER REINTRODUCE A SYMMETRIC PRIMITIVE, not even behind a test feature.
//! Through v1.3.13 the reference used HMAC-SHA256 on the argument that
//! substituting real signatures changed no control flow. That was true of
//! every property except custody: HMAC is symmetric, so the verifier held the
//! signing keys, and a compromised Executor could mint its own quorum.
//! INV-1-HIGH did not hold against the adversary it names, and no protocol
//! test could have found it.

pub mod custody;
pub mod primitives;
pub mod suite;

pub use custody::{
    CustodyError, CustodyTier, Environment, HybridSignature, KeyMaterial, OfflineSigner, Signer,
    TrustedKeys, VerifyingKeys,
};
/// T2 custody. Exported only where the feature that implements it is on, so a
/// build without a KMS backend cannot name the type and then discover at
/// runtime that the tier is unavailable — the refusal happens at compile time,
/// which is where an unavailable tier should be least convenient to ignore.
#[cfg(feature = "kms")]
pub use custody::{KmsBackend, KmsSigner};
pub use primitives::{verify_ed25519, verify_mldsa65};
pub use suite::{Primitive, Suite};

/// Outcome of verifying one primitive within a declared suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveVerdict {
    Valid,
    Invalid,
    /// The declared suite names a primitive this build cannot verify.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridError {
    /// At least one declared primitive failed to verify.
    PrimitiveInvalid,
    /// A declared primitive is not supported. Never treated as a pass:
    /// CR-1, an unknown suite is refused rather than ignored.
    PrimitiveUnsupported,
    /// The primitives presented are not exactly the primitives the declared
    /// suite requires — one missing, one extra, or one presented twice.
    ///
    /// This variant absorbed the former `Empty`. Once the suite is a parameter
    /// there is no suite requiring zero primitives, so "nothing was presented"
    /// is the extreme case of "the wrong things were presented" and cannot be
    /// reached by any other route. Two names for one refusal is two
    /// definitions of one thing, and the second one is the one that rots.
    SuiteMismatch,
}

/// Verification is **conjunctive over the DECLARED suite**: the primitives
/// presented must be exactly those the suite requires, and every one of them
/// must verify.
///
/// This is the whole point of CR-3. An `any`-shaped check lets an attacker
/// strip the post-quantum signature, present a genuine classical one, and be
/// accepted — the downgrade the hybrid suite exists to prevent.
///
/// **Why `suite` is a parameter.** The first version of this function took a
/// bare `&[PrimitiveVerdict]` and answered "did everything the caller chose to
/// check pass?". That is not the CR-3 question. It made the CALLER the
/// authority on how many primitives a `hybrid-ed25519-mldsa65` signature needs,
/// so a caller that verified one leg and presented one verdict got `Ok(())` and
/// the downgrade went through *underneath* the check written to stop it. The
/// composition rule and the suite table are one rule; splitting them across two
/// files put the security-determining half where nothing enforced it.
///
/// The suite passed here MUST come from the signed bundle, never from the
/// message being verified — RES-8. `acp_bundle::Tree` hashes it for that
/// reason.
pub fn verify_hybrid(
    suite: Suite,
    verdicts: &[(Primitive, PrimitiveVerdict)],
) -> Result<(), HybridError> {
    // (1) COMPLETENESS. Compare as multisets, so a primitive presented twice
    // cannot stand in for a primitive not presented at all: `[classical,
    // classical]` against a hybrid suite is a stripped PQ leg wearing its
    // sibling's coat.
    let mut presented: Vec<Primitive> = verdicts.iter().map(|(p, _)| *p).collect();
    presented.sort();
    if presented != suite.primitives() {
        return Err(HybridError::SuiteMismatch);
    }

    // (2) Unsupported before Invalid: an unimplemented primitive is a refusal
    // about this BUILD, not about the signature, and reporting it as an
    // invalid signature would send whoever reads the alert hunting the wrong
    // failure.
    if verdicts
        .iter()
        .any(|(_, v)| *v == PrimitiveVerdict::Unsupported)
    {
        return Err(HybridError::PrimitiveUnsupported);
    }
    if verdicts
        .iter()
        .any(|(_, v)| *v == PrimitiveVerdict::Invalid)
    {
        return Err(HybridError::PrimitiveInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Primitive::*;
    use super::PrimitiveVerdict::*;
    use super::*;

    const HYBRID: Suite = Suite::HybridEd25519MlDsa65;

    #[test]
    fn all_valid_passes() {
        assert_eq!(
            verify_hybrid(HYBRID, &[(Classical, Valid), (Pq, Valid)]),
            Ok(())
        );
    }

    #[test]
    fn stripped_pq_signature_is_refused() {
        // Classical genuine, post-quantum invalid: the CR-3 downgrade.
        assert_eq!(
            verify_hybrid(HYBRID, &[(Classical, Valid), (Pq, Invalid)]),
            Err(HybridError::PrimitiveInvalid)
        );
    }

    #[test]
    fn unknown_suite_is_refused_not_ignored() {
        assert_eq!(
            verify_hybrid(HYBRID, &[(Classical, Valid), (Pq, Unsupported)]),
            Err(HybridError::PrimitiveUnsupported)
        );
    }

    #[test]
    fn empty_is_not_vacuously_true() {
        // Formerly `Err(Empty)`. The property is unchanged — nothing presented
        // is still a refusal, never a vacuous pass; only the name of the
        // refusal moved when the suite became a parameter.
        assert_eq!(verify_hybrid(HYBRID, &[]), Err(HybridError::SuiteMismatch));
    }

    #[test]
    fn omitting_the_pq_leg_entirely_is_refused() {
        // THE DEFECT THIS SIGNATURE EXISTS TO CLOSE. Under the old
        // `verify_hybrid(&[PrimitiveVerdict])` this call presented one genuine
        // classical verdict and returned Ok(()) — the caller decided how many
        // primitives a hybrid signature needed, and it decided one.
        assert_eq!(
            verify_hybrid(HYBRID, &[(Classical, Valid)]),
            Err(HybridError::SuiteMismatch)
        );
    }

    #[test]
    fn one_primitive_presented_twice_does_not_stand_in_for_two() {
        // The same downgrade dressed as completeness: two verdicts, both
        // genuine, both about the leg the attacker can forge.
        assert_eq!(
            verify_hybrid(HYBRID, &[(Classical, Valid), (Classical, Valid)]),
            Err(HybridError::SuiteMismatch)
        );
    }

    #[test]
    fn an_extra_primitive_is_refused() {
        // Mirrors the Python reference's suite-completeness check ("no extra,
        // no missing"), whose deletion `mutate_executor.py` kills via
        // a_CR3_extra_primitive. An accepted extra leg means the suite name no
        // longer determines what was verified.
        assert_eq!(
            verify_hybrid(HYBRID, &[(Classical, Valid), (Pq, Valid), (PqSlh, Valid)]),
            Err(HybridError::SuiteMismatch)
        );
    }

    #[test]
    fn a_declared_but_unimplemented_suite_cannot_pass() {
        // slhdsa128s parses, so a deployment can name it. Presenting the one
        // primitive it requires still fails closed, because the build cannot
        // verify it. Naming is not implementing.
        assert_eq!(
            verify_hybrid(Suite::SlhDsa128s, &[(PqSlh, Unsupported)]),
            Err(HybridError::PrimitiveUnsupported)
        );
    }

    #[test]
    fn verdicts_may_arrive_in_any_order() {
        // Completeness is a set property. A caller that reports PQ first is
        // not presenting a different signature.
        assert_eq!(
            verify_hybrid(HYBRID, &[(Pq, Valid), (Classical, Valid)]),
            Ok(())
        );
    }
}
