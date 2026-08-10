//! External audit anchoring (AU-6, AU-7, AC-5).
//!
//! AU-7 is an **ordering** property: the anchor must exist before the release,
//! not after it. That is a trace property, which is precisely the kind of thing
//! a conformance vector cannot express — it is a per-implementation obligation
//! listed in `spec/vectors/OBLIGATIONS.md`, and this service owes its own test.
//!
//! This runs outside the trust domain of the components it anchors. An anchor
//! service an attacker can also compromise is a log, not an anchor.
//!
//! Scaffold. See `reference/src/acp_audit.py`.

fn main() -> std::process::ExitCode {
    eprintln!("acp-anchor: scaffold only — not implemented (build order step 6).");
    std::process::ExitCode::FAILURE
}
