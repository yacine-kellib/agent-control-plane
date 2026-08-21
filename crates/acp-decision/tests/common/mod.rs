//! Fixture helpers shared by the integration tests.
//!
//! One definition, imported by both test binaries. A copy per file is two
//! definitions of one object, which is the defect this repository is built
//! around — and a fixture helper is not exempt from it, because a fixture that
//! drifts silently stops testing what its call site says it tests.

use sha2::{Digest, Sha256};

/// A **WE-4 conforming** 128-bit attestation nonce, derived from a fixture seed.
///
/// WE-4 pins the type: `b64:` plus RFC 4648 §4 base64 **with** padding, carried
/// and hashed as that string. These fixtures used bare tokens — `"n1"`, `"n2"`,
/// `"n3"` — so every one of them became non-conformant the moment the clause
/// landed in `acp-decision`, exactly as the reference's did when it landed
/// there. That is the clause having an effect, which is the point: a type
/// nothing can violate is not a type.
///
/// Twenty-two alphabet characters and `==` — a well-formed encoding of *some*
/// sixteen bytes, which is all a fixture needs. Derived from the seed rather
/// than drawn at random so a fixture stays reproducible, and so two distinct
/// seeds stay distinct, which is the only property the call sites rely on.
pub fn b64n(seed: &str) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digest = Sha256::digest(seed.as_bytes());
    let mut out = String::from("b64:");
    out.extend(digest[..22].iter().map(|b| ALPHABET[(*b & 63) as usize] as char));
    out.push_str("==");
    out
}
