//! Policy evaluation: §8.4 order, over values recomputed from the signed bundle.
//!
//! RAD-4: this service must derive the bundle itself and never accept one
//! handed to it by a peer. A service given a bundle over a pipe is trusting the
//! peer that sent it, which is the defect the signature was supposed to close.
//! The Python simulation already demonstrates the property — policy and
//! executor independently compute the same bundle hash in separate processes.
//!
//! Scaffold. See `sim/policy.py` for the evaluation order and the XPROG-1
//! cross-program rule.

fn main() -> std::process::ExitCode {
    eprintln!("acp-policy: scaffold only — not implemented (build order step 6).");
    std::process::ExitCode::FAILURE
}
