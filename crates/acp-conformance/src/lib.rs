//! Runs the shared conformance corpus in `spec/vectors/` against this
//! implementation, so that "50/50" means the same thing in Rust as in Python.
//!
//! **Not started.** `spec/vectors/` is empty; extracting it is step 1 and the
//! classification of which cases are extractable at all is the first task of
//! that step.
//!
//! Two constraints on whatever lands here, recorded now because both are easy
//! to violate later:
//!
//! 1. **Vectors are defined over canonical bytes and declared mutations, never
//!    over signatures** (RES-P5). The Python reference signs with modelled
//!    HMAC; this crate will sign with real Ed25519 and ML-DSA-65. A vector
//!    carrying a signature is not portable between them.
//!
//! 2. **Passing the corpus is a partial claim.** Vectors express
//!    input -> verdict. They do not express the 34 mutants, ordering
//!    properties such as AU-7 anchor-before-release, partition behaviour, or
//!    render-path distinctness. Those are per-implementation obligations,
//!    enumerated in `spec/vectors/OBLIGATIONS.md`. This crate must not report
//!    a green total that implies more than it checked.

/// Placeholder for the corpus runner. Deliberately absent rather than stubbed
/// to return success: a runner that reports "0 failures" over 0 vectors is
/// exactly the misleading green this repository argues against.
pub fn corpus_path() -> &'static str {
    "spec/vectors"
}
