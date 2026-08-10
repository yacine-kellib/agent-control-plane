//! The Executor: the §9.3 verification checklist, and the only component that
//! can cause an effect.
//!
//! The controlling discipline when this is implemented (RES-8): every value the
//! Executor acts on is **recomputed** from the signed bundle, never read from
//! the receipt it is verifying. Risk (TR-8), reversibility (RV-3) and program
//! ownership all come from the bundle, because a compromised KMS writes the
//! whole receipt.
//!
//! Scaffold. See `reference/src/acp_executor.py` for the behaviour this must
//! reproduce, and `spec/vectors/` for the corpus it must pass.

fn main() -> std::process::ExitCode {
    eprintln!("acp-executor: scaffold only — not implemented (build order step 6).");
    eprintln!("The reference implementation is reference/src/acp_executor.py.");
    std::process::ExitCode::FAILURE
}
