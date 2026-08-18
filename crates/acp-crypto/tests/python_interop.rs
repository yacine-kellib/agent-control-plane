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
//! One asymmetry worth stating: this proves Rust accepts what Python produced,
//! which shows the Rust verifier is permissive enough to accept a correct
//! signature and nothing about whether the Rust signer makes one. The reverse
//! direction now exists — `acp_crypto::custody` can sign — and is checked by
//! `tools/check-rust-signatures.py`, which `tools/selftest.sh` runs. It lives
//! there rather than here because it needs both toolchains in one process tree.
//!
//! The file also carries the other half of the vector-corpus premise. A vector
//! is meant to declare a **seed** and let each implementation derive its own
//! keypair — `spec/vectors/CLASSIFICATION.md` rests 47 of its 48 extractable
//! cases on that — and it only works if two implementations derive the same one. They
//! do. What is portable, though, is the seed **plus the declared derivation**,
//! not the seed: an implementation that hashes the bare seed, or picks its own
//! domain separators, derives a different identity and refuses every signature
//! in the vector. So the separators are asserted here rather than assumed.

use acp_crypto::{PrimitiveVerdict, verify_ed25519, verify_mldsa65};
use sha2::{Digest, Sha256};

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

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// `reference/src/acp_crypto.py:HybridKey.__init__`, re-executed here.
///
/// Three lines of Python against a different crate stack: SHA-256 with a
/// per-primitive domain separator, then RFC 8032 from the raw scalar and FIPS
/// 204 `KeyGen_internal` from the 32-byte xi.
///
/// The separators `b"ed"` and `b"mldsa"` are wire format, not taste. That is
/// the limit this whole file puts on the seed mechanism: a corpus that names a
/// seed and not the derivation names nothing, because a second implementation
/// hashing the bare seed lands on a different identity and every signature in
/// the vector fails closed against it — indistinguishable, at the verifier,
/// from a forgery.
fn derive_from_seed(seed: &str) -> (Vec<u8>, Vec<u8>) {
    use fips204::traits::{KeyGen, SerDes};

    let ed_pk = ed25519_dalek::SigningKey::from_bytes(&sha256(&[seed.as_bytes(), b"ed"]))
        .verifying_key()
        .to_bytes()
        .to_vec();

    let (ml_pk, _sk) =
        fips204::ml_dsa_65::KG::keygen_from_seed(&sha256(&[seed.as_bytes(), b"mldsa"]));

    (ed_pk, ml_pk.into_bytes().to_vec())
}

#[test]
fn rust_derives_the_public_keys_python_derived_from_the_same_seed() {
    // `spec/vectors/CLASSIFICATION.md` rests the entire extractable corpus on
    // this: a vector declares a seed, each implementation derives locally, and
    // 47 of the 48 cases become shared data. Until this test ran, "in any
    // implementation" had been checked across Python processes only — the same
    // two libraries twice, which cannot detect a disagreement between
    // libraries. `dilithium-py` and `fips204` both cite FIPS 204 Algorithm 6,
    // and citing a standard is not evidence of agreeing on its bytes.
    let (_, keys) = load();
    for k in &keys {
        let (ed_pk, ml_pk) = derive_from_seed(&k.seed);
        assert_eq!(
            hex::encode(&ed_pk),
            hex::encode(&k.ed_pk),
            "Ed25519 public key diverged for seed {:?}: RFC 8032 from a raw scalar is not portable",
            k.seed
        );
        assert_eq!(
            hex::encode(&ml_pk),
            hex::encode(&k.ml_pk),
            "ML-DSA-65 public key diverged for seed {:?}: FIPS 204 KeyGen_internal is not portable",
            k.seed
        );
    }
}

#[test]
fn the_locally_derived_key_verifies_the_signature_python_made_with_it() {
    // Key agreement on its own is a comparison against a fixture, and a fixture
    // is a claim about what Python did once. This closes the loop the corpus
    // will actually walk: derive from the declared seed, then verify a
    // signature nothing in the derivation ever saw.
    let (message, keys) = load();
    for k in &keys {
        let (ed_pk, ml_pk) = derive_from_seed(&k.seed);
        assert_eq!(
            verify_ed25519(&ed_pk, &message, &k.ed_sig),
            PrimitiveVerdict::Valid,
            "locally derived Ed25519 key refused Python's signature for seed {:?}",
            k.seed
        );
        assert_eq!(
            verify_mldsa65(&ml_pk, &message, &k.ml_sig),
            PrimitiveVerdict::Valid,
            "locally derived ML-DSA-65 key refused Python's signature for seed {:?}",
            k.seed
        );
    }
}

#[test]
fn the_fingerprint_is_the_same_on_both_sides() {
    // `HybridPub.fingerprint` covers BOTH halves, so it is the single value
    // that says two implementations derived one identity rather than two that
    // happen to share a leg.
    //
    // WHAT THIS DOES NOT CHECK, because the first version of this comment said
    // it did: `spec/vectors/CLASSIFICATION.md` publishes the `k1` fingerprint in
    // prose, and the claim was that recomputing it here kept the published
    // number and the code from drifting apart. It does not — the comparison is
    // against the committed fixture, not against the prose. Corrupting the
    // published hex left this test and `tools/selftest.sh` green, which is the
    // experiment that found the overclaim. The prose is now covered by
    // selftest's "published key fingerprints match what the code derives"; this
    // test covers Rust against the fixture, which is a different pair.
    let (_, keys) = load();
    for k in &keys {
        let (ed_pk, ml_pk) = derive_from_seed(&k.seed);
        let fp = format!("sha256:{}", hex::encode(sha256(&[&ed_pk, &ml_pk])));
        assert_eq!(
            fp, k.fingerprint,
            "fingerprint diverged for seed {:?}",
            k.seed
        );
    }
}
