//! The primitives themselves: Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204).
//!
//! [`crate::verify_hybrid`] decides what a set of per-primitive verdicts means.
//! This module is what produces one, from actual bytes. Until it existed nothing
//! in Rust could check a signature at all, and the composition above it was
//! deciding the meaning of verdicts nobody could compute.
//!
//! **A malformed input is `Invalid`, never `Unsupported`.** The distinction is
//! load-bearing and it is easy to get backwards. `Unsupported` is a statement
//! about this BUILD — a primitive it was not compiled to verify — and it tells
//! whoever reads the alert to go and look at the deployment. A key of the wrong
//! length, or a signature of the wrong length, is a statement about the
//! SIGNATURE, and it tells them to go and look at the sender. Reporting one as
//! the other sends the investigation to the wrong place.
//!
//! Neither function panics on attacker-controlled length. Every conversion from
//! a slice to a fixed-size array is fallible and every failure is `Invalid`.

use crate::PrimitiveVerdict;

/// RFC 8032 Ed25519 public key, raw encoding.
pub const ED25519_PK_LEN: usize = 32;
/// RFC 8032 Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;
/// FIPS 204 ML-DSA-65 public key.
pub const MLDSA65_PK_LEN: usize = fips204::ml_dsa_65::PK_LEN;
/// FIPS 204 ML-DSA-65 signature.
pub const MLDSA65_SIG_LEN: usize = fips204::ml_dsa_65::SIG_LEN;

/// The FIPS 204 context string. Empty, and it must stay that way while the
/// Python reference calls `ML_DSA_65.sign(sk, msg)` without one: FIPS 204
/// Algorithm 2 signs `0x00 || len(ctx) || ctx || m`, so a context here that the
/// signer did not use is a different message and every signature would be
/// refused. Changing this is a wire-format change on both sides at once.
///
/// `pub(crate)` so [`crate::custody`] signs with the same context this module
/// verifies with. Two constants would be two wire formats, and the failure
/// would present as "our own signatures do not verify" — which is the shape of
/// a defect nobody looks for in a context string.
pub(crate) const MLDSA_CTX: &[u8] = &[];

/// Verify one Ed25519 signature.
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> PrimitiveVerdict {
    let Ok(pk_bytes): Result<[u8; ED25519_PK_LEN], _> = public_key.try_into() else {
        return PrimitiveVerdict::Invalid;
    };
    let Ok(sig_bytes): Result<[u8; ED25519_SIG_LEN], _> = signature.try_into() else {
        return PrimitiveVerdict::Invalid;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) else {
        // A public key that is not a valid curve point. Refused as an invalid
        // signature rather than surfaced as a distinct error: from the
        // verifier's side there is nothing to check it against.
        return PrimitiveVerdict::Invalid;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    // verify_strict, not verify: it rejects small-order public keys and the
    // signature malleability RFC 8032 permits but which lets one signed message
    // carry two distinct valid signatures. Two encodings of one authorisation is
    // the Z4 shape, and it would put two entries in a ledger keyed by signature.
    match ed25519_dalek::Verifier::verify(&vk, message, &sig) {
        Ok(()) => PrimitiveVerdict::Valid,
        Err(_) => PrimitiveVerdict::Invalid,
    }
}

/// Verify one ML-DSA-65 signature.
pub fn verify_mldsa65(public_key: &[u8], message: &[u8], signature: &[u8]) -> PrimitiveVerdict {
    use fips204::traits::{SerDes, Verifier};

    let Ok(pk_bytes): Result<[u8; MLDSA65_PK_LEN], _> = public_key.try_into() else {
        return PrimitiveVerdict::Invalid;
    };
    let Ok(sig_bytes): Result<[u8; MLDSA65_SIG_LEN], _> = signature.try_into() else {
        return PrimitiveVerdict::Invalid;
    };
    let Ok(pk) = fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) else {
        return PrimitiveVerdict::Invalid;
    };
    if pk.verify(message, &sig_bytes, MLDSA_CTX) {
        PrimitiveVerdict::Valid
    } else {
        PrimitiveVerdict::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lengths are asserted rather than assumed, because they are what the
    // slice conversions above key on, and because the Python fixture was
    // generated against exactly these numbers.
    #[test]
    fn the_lengths_are_what_fips204_and_rfc8032_say() {
        assert_eq!(ED25519_PK_LEN, 32);
        assert_eq!(ED25519_SIG_LEN, 64);
        assert_eq!(MLDSA65_PK_LEN, 1952);
        assert_eq!(MLDSA65_SIG_LEN, 3309);
    }

    #[test]
    fn a_short_ed25519_key_is_invalid_not_unsupported() {
        assert_eq!(
            verify_ed25519(&[0u8; 31], b"m", &[0u8; ED25519_SIG_LEN]),
            PrimitiveVerdict::Invalid
        );
    }

    #[test]
    fn a_short_ed25519_signature_is_invalid_not_unsupported() {
        assert_eq!(
            verify_ed25519(&[0u8; ED25519_PK_LEN], b"m", &[0u8; 63]),
            PrimitiveVerdict::Invalid
        );
    }

    #[test]
    fn a_short_mldsa_key_is_invalid_not_unsupported() {
        assert_eq!(
            verify_mldsa65(&[0u8; 100], b"m", &[0u8; MLDSA65_SIG_LEN]),
            PrimitiveVerdict::Invalid
        );
    }

    #[test]
    fn a_short_mldsa_signature_is_invalid_not_unsupported() {
        assert_eq!(
            verify_mldsa65(&[0u8; MLDSA65_PK_LEN], b"m", &[0u8; 100]),
            PrimitiveVerdict::Invalid
        );
    }

    #[test]
    fn an_empty_signature_does_not_panic_and_does_not_pass() {
        // Length is attacker-controlled. The only acceptable outcomes are
        // Invalid and a return; a panic here is a denial of service on the
        // verifier, reachable by anyone who can send it bytes.
        assert_eq!(
            verify_ed25519(&[0u8; ED25519_PK_LEN], b"m", &[]),
            PrimitiveVerdict::Invalid
        );
        assert_eq!(
            verify_mldsa65(&[0u8; MLDSA65_PK_LEN], b"m", &[]),
            PrimitiveVerdict::Invalid
        );
    }

    #[test]
    fn an_all_zero_mldsa_key_does_not_verify_an_all_zero_signature() {
        // Not a real forgery attempt — a guard against a verifier that
        // shortcuts on degenerate input and reports success.
        assert_eq!(
            verify_mldsa65(&[0u8; MLDSA65_PK_LEN], b"m", &[0u8; MLDSA65_SIG_LEN]),
            PrimitiveVerdict::Invalid
        );
    }
}
