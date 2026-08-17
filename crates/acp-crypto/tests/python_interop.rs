//! The differential assertion for the primitives: **a signature produced by the
//! Python reference must verify here.**
//!
//! This is the test that decided which ML-DSA crate to depend on. Python signs
//! with `dilithium-py` and `cryptography`; Rust verifies with `fips204` and
//! `ed25519-dalek`. Both sides claim FIPS 204 and RFC 8032, and that claim is
//! either true on the wire or it is decoration — nothing about two crates
//! naming the same standard makes their bytes interchangeable, and the only way
//! to know is to carry bytes across.
//!
//! It matters beyond this crate. `reference/` is the differential partner for
//! Rust, and the first divergence between the two on a shared input is a
//! specification ambiguity rather than a bug to patch around — that is how Z1
//! was found. If the two implementations cannot agree on a signature, they
//! cannot be compared on anything built above one.
//!
//! The fixture is committed rather than generated at test time, so `cargo test`
//! needs no Python. Regenerate it with `tools/gen-crypto-vectors.py` whenever
//! the key derivation or the signed-message construction changes. A committed
//! fixture that nothing regenerates is a fixture that can silently stop
//! describing the code, which is why the generator is checked in beside it.
//!
//! One asymmetry worth stating: this proves Rust accepts what Python produced.
//! It does not prove the reverse, because Rust cannot sign yet — there is no
//! `Signer` in this crate. That is rule-store step 3, and until it lands the
//! Python-verifies-Rust direction is an obligation nobody has discharged.

use acp_crypto::{PrimitiveVerdict, verify_ed25519, verify_mldsa65};

const FIXTURE: &str = include_str!("vectors/python_signatures.json");

struct Vector {
    seed: String,
    fingerprint: String,
    ed_pk: Vec<u8>,
    ed_sig: Vec<u8>,
    ml_pk: Vec<u8>,
    ml_sig: Vec<u8>,
}

fn load() -> (Vec<u8>, Vec<Vector>) {
    let v: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    let message = v["message_utf8"]
        .as_str()
        .expect("message")
        .as_bytes()
        .to_vec();
    let hexf = |k: &serde_json::Value, f: &str| {
        hex::decode(k[f].as_str().unwrap_or_else(|| panic!("missing {f}"))).expect("hex")
    };
    let keys = v["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .map(|k| Vector {
            seed: k["seed_utf8"].as_str().expect("seed").to_string(),
            fingerprint: k["fingerprint"].as_str().expect("fingerprint").to_string(),
            ed_pk: hexf(k, "ed25519_pk_hex"),
            ed_sig: hexf(k, "ed25519_sig_hex"),
            ml_pk: hexf(k, "mldsa65_pk_hex"),
            ml_sig: hexf(k, "mldsa65_sig_hex"),
        })
        .collect();
    (message, keys)
}

#[test]
fn the_fixture_is_not_empty() {
    // A vacuous pass here would make every assertion below trivially true: an
    // empty key list means the loops never run and the file reports success
    // without verifying anything.
    let (message, keys) = load();
    assert!(!message.is_empty(), "fixture carries no message");
    assert!(
        keys.len() >= 3,
        "expected at least 3 keys, got {}",
        keys.len()
    );
}

#[test]
fn python_ed25519_signatures_verify_in_rust() {
    let (message, keys) = load();
    for k in &keys {
        assert_eq!(
            verify_ed25519(&k.ed_pk, &message, &k.ed_sig),
            PrimitiveVerdict::Valid,
            "Ed25519 signature from Python seed {:?} was refused",
            k.seed
        );
    }
}

#[test]
fn python_mldsa65_signatures_verify_in_rust() {
    // The one that was genuinely in doubt. FIPS 204 Algorithm 2 signs
    // `0x00 || len(ctx) || ctx || m`; `dilithium-py` applies that with an empty
    // context by default and `fips204` applies it from the context argument, so
    // the two agree only because both do it and both were passed nothing.
    let (message, keys) = load();
    for k in &keys {
        assert_eq!(
            verify_mldsa65(&k.ml_pk, &message, &k.ml_sig),
            PrimitiveVerdict::Valid,
            "ML-DSA-65 signature from Python seed {:?} was refused",
            k.seed
        );
    }
}

#[test]
fn the_fixture_carries_the_lengths_both_standards_specify() {
    let (_, keys) = load();
    for k in &keys {
        assert_eq!(k.ed_pk.len(), 32, "Ed25519 public key");
        assert_eq!(k.ed_sig.len(), 64, "Ed25519 signature");
        assert_eq!(k.ml_pk.len(), 1952, "ML-DSA-65 public key");
        assert_eq!(k.ml_sig.len(), 3309, "ML-DSA-65 signature");
    }
}

#[test]
fn a_tampered_message_is_refused_by_both_primitives() {
    // Non-vacuity for the two tests above. If the verifiers returned Valid
    // unconditionally — the failure mode that matters, because it is the one
    // that looks like success — those tests would pass and this one would not.
    let (message, keys) = load();
    let mut tampered = message.clone();
    tampered[0] ^= 0xFF;
    for k in &keys {
        assert_eq!(
            verify_ed25519(&k.ed_pk, &tampered, &k.ed_sig),
            PrimitiveVerdict::Invalid,
            "Ed25519 accepted a tampered message for seed {:?}",
            k.seed
        );
        assert_eq!(
            verify_mldsa65(&k.ml_pk, &tampered, &k.ml_sig),
            PrimitiveVerdict::Invalid,
            "ML-DSA-65 accepted a tampered message for seed {:?}",
            k.seed
        );
    }
}

#[test]
fn one_keys_signature_does_not_verify_under_another_keys_public_key() {
    // The forgery that matters operationally: every signature here is genuine,
    // and the question is only whether the verifier binds it to the right
    // identity. An attester registry is a map from a name to a key, so a
    // verifier that does not is a quorum of one wearing several names.
    let (message, keys) = load();
    for (i, k) in keys.iter().enumerate() {
        let other = &keys[(i + 1) % keys.len()];
        assert_eq!(
            verify_ed25519(&other.ed_pk, &message, &k.ed_sig),
            PrimitiveVerdict::Invalid,
            "Ed25519 signature by {:?} verified under {:?}'s key",
            k.seed,
            other.seed
        );
        assert_eq!(
            verify_mldsa65(&other.ml_pk, &message, &k.ml_sig),
            PrimitiveVerdict::Invalid,
            "ML-DSA-65 signature by {:?} verified under {:?}'s key",
            k.seed,
            other.seed
        );
    }
}

#[test]
fn a_truncated_signature_is_refused_rather_than_padded() {
    // A verifier that pads or ignores length turns a partial capture into a
    // valid authorisation.
    let (message, keys) = load();
    for k in &keys {
        assert_eq!(
            verify_ed25519(&k.ed_pk, &message, &k.ed_sig[..63]),
            PrimitiveVerdict::Invalid
        );
        assert_eq!(
            verify_mldsa65(&k.ml_pk, &message, &k.ml_sig[..3308]),
            PrimitiveVerdict::Invalid
        );
    }
}

#[test]
fn the_python_fingerprint_is_recorded_for_the_cross_language_anchor() {
    // The fingerprint covers BOTH public halves, so it is the value that says
    // two implementations derived the same identity from the same seed. Rust
    // cannot compute it yet — that needs the canonical tree encoding from
    // rule-store step 4 — so this asserts only that the anchor is present and
    // well-formed, and names what will consume it. An assertion that a string
    // is non-empty is not evidence of agreement, and is not offered as any.
    let (_, keys) = load();
    for k in &keys {
        assert!(
            k.fingerprint.starts_with("sha256:") && k.fingerprint.len() == 71,
            "malformed fingerprint for seed {:?}: {:?}",
            k.seed,
            k.fingerprint
        );
    }
}
