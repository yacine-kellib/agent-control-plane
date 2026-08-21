//! Runs the shared conformance corpus in `spec/vectors/` against this
//! implementation, so that a green conformance total means the same thing in
//! Rust as in Python. The total is not quoted here: no `tools/sync-counts.sh`
//! rule re-derives it in this file, and a number published where nothing
//! re-derives it goes stale in silence. This line said "52/52" while the suite
//! printed 53/53.
//!
//! **Not started.** `spec/vectors/` is empty; extracting it is step 1 and the
//! classification of which cases are extractable at all is the first task of
//! that step.
//!
//! Two constraints on whatever lands here, recorded now because both are easy
//! to violate later:
//!
//! 1. **Vectors are defined over canonical bytes and declared mutations, never
//!    over signatures** (RES-P5). A correction worth recording: this file
//!    justified that rule with "the Python reference signs with modelled HMAC",
//!    which has been false since v1.3.14. Both sides sign for real now, with
//!    RFC 8032 Ed25519 and FIPS 204 ML-DSA-65. The rule survives its dead
//!    reason, for two others: ML-DSA signing is hedged unless a deployment pins
//!    deterministic signing, so an implementation does not reproduce even its
//!    own signature bytes, let alone another's; and a vector carrying a
//!    signature would have to carry key material to be checkable at all.
//!
//! 2. **Passing the corpus is a partial claim.** Vectors express
//!    input -> verdict. They do not express the 37 mutants, ordering
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
