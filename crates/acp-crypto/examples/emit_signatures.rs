//! Emit Rust-produced hybrid signatures as JSON, for the Python reference to
//! verify. Run by `tools/check-rust-signatures.py`.
//!
//! **This is the direction that was missing.** `tests/python_interop.rs` proves
//! Rust accepts what Python produced. Until `custody.rs` there was no Rust
//! signer, so the reverse — Python accepting what Rust produced — was an
//! obligation this crate's own module docs named and nothing discharged. Half a
//! differential pair is not a differential pair: it shows the verifier is
//! permissive enough, never that the signer is correct.
//!
//! Nothing is committed. The output is generated and consumed in one run, so
//! there is no fixture here that can quietly stop describing the code — the
//! failure mode `tools/gen-crypto-vectors.py` exists to prevent on the other
//! side, avoided here by not having a fixture at all.
//!
//! JSON is written by hand rather than through serde: every value below is hex
//! or an ASCII identifier chosen in this file, so there is nothing to escape,
//! and an example that pulls in a serialiser to print six fields is a
//! dependency added for typing convenience.

use acp_crypto::{CustodyTier, Environment, KeyMaterial, OfflineSigner, Primitive, Signer, Suite};

/// The seeds the Python suites already use, so a divergence shows up in the
/// same key material the conformance suite signs with.
const SEEDS: [&str; 3] = ["k1", "k2", "kop"];

const MESSAGE: &str = "ACP cross-language primitive vector: the Python verifier must accept what the Rust signer produced.";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let mut entries = Vec::new();

    for seed in SEEDS {
        // T1: the tier that may sign for production, and whose key is wiped
        // afterwards. One signer per seed because a T1 key does not survive its
        // signature — which is the control, not an inconvenience to work
        // around.
        let signer = OfflineSigner::new(
            CustodyTier::T1,
            Suite::HybridEd25519MlDsa65,
            KeyMaterial::from_seed(seed.as_bytes()),
        )
        .expect("T1 is available in a default build");

        let pk = signer.verifying_keys().clone();
        let sig = signer
            .sign(MESSAGE.as_bytes(), Environment::Production)
            .expect("T1 may sign for production");

        entries.push(format!(
            "  {{\n\
             \x20  \"seed_utf8\": \"{}\",\n\
             \x20  \"fingerprint\": \"{}\",\n\
             \x20  \"ed25519_pk_hex\": \"{}\",\n\
             \x20  \"mldsa65_pk_hex\": \"{}\",\n\
             \x20  \"ed25519_sig_hex\": \"{}\",\n\
             \x20  \"mldsa65_sig_hex\": \"{}\"\n\
             \x20 }}",
            seed,
            pk.fingerprint(),
            hex(pk.classical()),
            hex(pk.pq()),
            hex(sig.part(Primitive::Classical).expect("classical leg")),
            hex(sig.part(Primitive::Pq).expect("post-quantum leg")),
        ));
    }

    println!("{{");
    println!(" \"message_utf8\": \"{MESSAGE}\",");
    println!(" \"keys\": [");
    println!("{}", entries.join(",\n"));
    println!(" ]");
    println!("}}");
}
