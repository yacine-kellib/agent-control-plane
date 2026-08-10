//! Hybrid signature composition (CR-1..CR-5).
//!
//! The Python reference models signatures with HMAC-SHA256 (`CRYPTO-SWAP`).
//! This crate is where real Ed25519 and ML-DSA-65 land. Neither primitive is
//! implemented yet.
//!
//! What *is* implemented is the composition, deliberately: CR-3 is protocol
//! logic, not cryptography, and the downgrade attack it prevents is a
//! control-flow property that can be tested without a single real signature.

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
