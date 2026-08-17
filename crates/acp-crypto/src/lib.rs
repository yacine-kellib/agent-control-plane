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
//!
//! Still absent: the primitives themselves. Nothing here can check an actual
//! Ed25519 or ML-DSA signature, and the composition above is what decides what
//! happens once something can — an `Unsupported` primitive is refused, never
//! skipped.
//!
//! NEVER REINTRODUCE A SYMMETRIC PRIMITIVE, not even behind a test feature.
//! Through v1.3.13 the reference used HMAC-SHA256 on the argument that
//! substituting real signatures changed no control flow. That was true of
//! every property except custody: HMAC is symmetric, so the verifier held the
//! signing keys, and a compromised Executor could mint its own quorum.
//! INV-1-HIGH did not hold against the adversary it names, and no protocol
//! test could have found it.

pub mod suite;

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
    /// No primitives were presented at all.
    Empty,
}

/// Verification is **conjunctive**: every declared primitive must verify.
///
/// This is the whole point of CR-3. An `any`-shaped check lets an attacker
/// strip the post-quantum signature, present a genuine classical one, and be
/// accepted — the downgrade the hybrid suite exists to prevent. An empty set
/// is refused rather than treated as vacuously true, which is the same defect
/// wearing a different hat.
pub fn verify_hybrid(verdicts: &[PrimitiveVerdict]) -> Result<(), HybridError> {
    if verdicts.is_empty() {
        return Err(HybridError::Empty);
    }
    if verdicts.contains(&PrimitiveVerdict::Unsupported) {
        return Err(HybridError::PrimitiveUnsupported);
    }
    if verdicts.contains(&PrimitiveVerdict::Invalid) {
        return Err(HybridError::PrimitiveInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::PrimitiveVerdict::*;
    use super::*;

    #[test]
    fn all_valid_passes() {
        assert_eq!(verify_hybrid(&[Valid, Valid]), Ok(()));
    }

    #[test]
    fn stripped_pq_signature_is_refused() {
        // Classical genuine, post-quantum missing/invalid: the CR-3 downgrade.
        assert_eq!(
            verify_hybrid(&[Valid, Invalid]),
            Err(HybridError::PrimitiveInvalid)
        );
    }

    #[test]
    fn unknown_suite_is_refused_not_ignored() {
        assert_eq!(
            verify_hybrid(&[Valid, Unsupported]),
            Err(HybridError::PrimitiveUnsupported)
        );
    }

    #[test]
    fn empty_is_not_vacuously_true() {
        assert_eq!(verify_hybrid(&[]), Err(HybridError::Empty));
    }
}
