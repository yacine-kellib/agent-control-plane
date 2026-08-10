//! Single-use nonce ledger with quorum across replicas (CL-1..CL-7).
//!
//! CL-6 is the property that costs something and must not be traded away:
//! on loss of majority the ledger **fails closed**, stopping HIGH actions.
//! Availability is the stated price, and the residual document says so rather
//! than hiding it. An implementation that keeps serving through a partition
//! has replaced a safety property with a convenience one.
//!
//! Scaffold. See `reference/src/acp_ledger.py`.

fn main() -> std::process::ExitCode {
    eprintln!("acp-ledger: scaffold only — not implemented (build order step 6).");
    std::process::ExitCode::FAILURE
}
