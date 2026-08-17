//! Canonical bundle tree: the member index and the hash the signature covers.
//!
//! §8.2 says the SIGNATURE is "Ed25519 over SHA-256 of canonical bundle tree".
//! That sentence leaves two things unstated, and both have to be pinned here or
//! two conformant implementations will disagree on a valid bundle:
//!
//!   1. WHICH FILES are in the tree. Answered by an explicit member index, so
//!      coverage is a signed fact rather than whatever the reader walked. Same
//!      reasoning as `tools/sign-release.sh` halting on an unrecognised file
//!      type instead of silently signing or silently skipping it.
//!   2. IN WHAT ORDER. Answered by a bytewise sort on the path. Bytewise, not
//!      locale-aware: a locale-dependent sort is a defect that only shows up on
//!      someone else's machine.
//!
//! The hash is taken over canonical CBOR, reusing the encoding the repository
//! already has a validating decoder and eight tests for (AT-8a). Writing a
//! second canonicaliser here would be a second definition of one object, which
//! is the encoding-split defect at source level.

use sha2::{Digest, Sha256};

/// One file covered by the bundle signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    path: String,
    sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    /// A path that could escape the bundle root, or is otherwise not a plain
    /// relative path. Rejected at construction: a path traversal in an index
    /// is a file-read primitive handed to whoever wrote the index.
    UnsafePath,
    /// Two members share one path. Refused rather than de-duplicated, because
    /// the two entries carry different digests and picking one is a guess.
    DuplicatePath,
    /// No members. An empty tree hashes to a fixed value that any signer could
    /// produce, so accepting it would make "signed empty bundle" a valid input.
    Empty,
}

impl Member {
    /// Construct a member, validating the path.
    ///
    /// Rejects absolute paths, any `..` component, backslashes, and empty or
    /// `.` components. The check is on components rather than on the raw
    /// string so that `a/../b`, `..`, and `a/..` are all caught by one rule
    /// instead of three string patterns that each miss a case.
    pub fn new(path: impl Into<String>, sha256: [u8; 32]) -> Result<Self, TreeError> {
        let path = path.into();
        if path.is_empty() || path.starts_with('/') || path.contains('\\') {
            return Err(TreeError::UnsafePath);
        }
        for component in path.split('/') {
            if component.is_empty() || component == "." || component == ".." {
                return Err(TreeError::UnsafePath);
            }
        }
        Ok(Member { path, sha256 })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// The signed member index of one bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    members: Vec<Member>,
}

impl Tree {
    /// Build a tree, sorting members into canonical order.
    ///
    /// Sorting here rather than requiring pre-sorted input means a caller
    /// cannot produce a differently-ordered tree by accident. The order is
    /// part of what is hashed, so "the caller should sort first" would be a
    /// correctness requirement expressed as a comment.
    pub fn new(mut members: Vec<Member>) -> Result<Self, TreeError> {
        if members.is_empty() {
            return Err(TreeError::Empty);
        }
        members.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        for pair in members.windows(2) {
            if pair[0].path == pair[1].path {
                return Err(TreeError::DuplicatePath);
            }
        }
        Ok(Tree { members })
    }

    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The canonical CBOR encoding of the tree.
    ///
    /// Encoded by hand rather than through a serde derive, for one reason: the
    /// derive's output depends on struct field order and on the serialiser's
    /// map-key handling, neither of which is visible at the call site. What is
    /// hashed has to be readable in the same file that says what it means.
    ///
    /// Shape: a definite-length array of definite-length 2-element arrays,
    /// `[[path, digest], ...]`. Arrays rather than maps because RFC 8949
    /// canonical form orders map keys by encoded bytes, and relying on that
    /// ordering is one more thing an implementation can get subtly wrong when
    /// positional pairs express the same information with no ordering rule at
    /// all.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_array_header(&mut out, self.members.len() as u64);
        for m in &self.members {
            write_array_header(&mut out, 2);
            write_text(&mut out, &m.path);
            write_bytes(&mut out, &m.sha256);
        }
        out
    }

    /// SHA-256 over the canonical encoding. This is what gets signed.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------- CBOR bits
//
// Canonical CBOR requires the SHORTEST argument encoding for every head
// (RFC 8949 §4.2.1). A non-shortest form is a different byte string for the
// same value, which is two encodings of one object — the defect this whole
// repository keeps rediscovering. `cbor_suite.py` tests the decoder's refusal
// of non-shortest arguments; this is the encoder side of the same rule.

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let major = major << 5;
    match arg {
        0..=23 => out.push(major | arg as u8),
        24..=0xFF => {
            out.push(major | 24);
            out.push(arg as u8);
        }
        0x100..=0xFFFF => {
            out.push(major | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(major | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

fn write_array_header(out: &mut Vec<u8>, n: u64) {
    write_head(out, 4, n);
}

fn write_text(out: &mut Vec<u8>, s: &str) {
    write_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn member(path: &str, seed: u8) -> Member {
        Member::new(path, digest(seed)).expect("test path should be valid")
    }

    #[test]
    fn member_order_does_not_change_the_hash() {
        let a = Tree::new(vec![
            member("floors.json", 1),
            member("manifest.json", 2),
            member("attesters/alice.json", 3),
        ])
        .unwrap();
        let b = Tree::new(vec![
            member("attesters/alice.json", 3),
            member("floors.json", 1),
            member("manifest.json", 2),
        ])
        .unwrap();
        assert_eq!(a.hash(), b.hash(), "canonical order is not being applied");
    }

    #[test]
    fn changing_one_digest_changes_the_hash() {
        let before = Tree::new(vec![member("floors.json", 1)]).unwrap();
        let after = Tree::new(vec![member("floors.json", 2)]).unwrap();
        assert_ne!(
            before.hash(),
            after.hash(),
            "a tampered floors.json produced an identical tree hash"
        );
    }

    #[test]
    fn adding_a_file_changes_the_hash() {
        // An unsigned file smuggled into a signed bundle must not be free.
        let one = Tree::new(vec![member("manifest.json", 1)]).unwrap();
        let two = Tree::new(vec![member("manifest.json", 1), member("extra.json", 9)]).unwrap();
        assert_ne!(one.hash(), two.hash());
    }

    #[test]
    fn path_traversal_is_refused() {
        for bad in [
            "../secrets.json",
            "a/../../etc/passwd",
            "/etc/passwd",
            "a\\b.json",
            "",
            "./x.json",
            "a//b.json",
            "..",
        ] {
            assert_eq!(
                Member::new(bad, digest(0)),
                Err(TreeError::UnsafePath),
                "accepted unsafe path {bad:?}"
            );
        }
    }

    #[test]
    fn ordinary_nested_paths_still_work() {
        // The traversal check must not be so broad it rejects the real layout:
        // §8.2 has attesters/, schemas/ and templates/ as directories.
        assert!(Member::new("attesters/alice.json", digest(0)).is_ok());
        assert!(Member::new("schemas/order_synthesis.v1.json", digest(0)).is_ok());
    }

    #[test]
    fn duplicate_paths_are_refused_not_deduplicated() {
        let e = Tree::new(vec![member("floors.json", 1), member("floors.json", 2)]);
        assert_eq!(e, Err(TreeError::DuplicatePath));
    }

    #[test]
    fn empty_tree_is_refused() {
        assert_eq!(Tree::new(vec![]), Err(TreeError::Empty));
    }

    #[test]
    fn cbor_heads_use_the_shortest_argument() {
        // 23 fits in the head byte; 24 needs one extra byte. A non-shortest
        // encoding would be a second valid encoding of one tree.
        let mut small = Vec::new();
        write_array_header(&mut small, 23);
        assert_eq!(small, vec![0x80 | 23]);

        let mut boundary = Vec::new();
        write_array_header(&mut boundary, 24);
        assert_eq!(boundary, vec![0x80 | 24, 24]);

        let mut wide = Vec::new();
        write_array_header(&mut wide, 0x1234);
        assert_eq!(wide, vec![0x80 | 25, 0x12, 0x34]);
    }

    #[test]
    fn agrees_byte_for_byte_with_the_python_reference() {
        // THE DIFFERENTIAL ASSERTION. This crate hand-rolls a CBOR encoder;
        // `reference/src/acp_crypto.py` has an independent one with a
        // validating decoder and eight tests. Two implementations of one
        // encoding is exactly the situation that produced Z1, so the agreement
        // is pinned here as bytes rather than left to be true by luck.
        //
        // Regenerate with:
        //   cd reference/src && python3 -c "import acp_crypto as C; \
        //     print(C.canon_cbor([['manifest.json', bytes([0xAB]*32)]]).hex())"
        //
        // If this test fails, ONE OF THE TWO ENCODERS IS WRONG. Find out which
        // before changing the constant — a divergence here is a specification
        // ambiguity, and patching the expected value hides it.
        const PYTHON_CANON_CBOR: &str = "81826d6d616e69666573742e6a736f6e5820\
                                         abababababababababababababababababababababababababababababababab";
        const PYTHON_SHA256: &str =
            "c7a02a88ac1e3265a3df0fd77a0c75f4621a7a638843f2fcdd493450f1b063a8";

        let t = Tree::new(vec![member("manifest.json", 0xAB)]).unwrap();
        assert_eq!(
            hex(&t.canonical_bytes()),
            PYTHON_CANON_CBOR.replace(char::is_whitespace, ""),
            "Rust and Python canonical encodings diverge"
        );
        assert_eq!(hex(&t.hash()), PYTHON_SHA256, "tree hashes diverge");
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn digest_is_encoded_as_bytes_not_text() {
        // A hex *string* and a byte string are different CBOR values. Fixing
        // this later would silently invalidate every signature already issued.
        let t = Tree::new(vec![member("a.json", 0xAB)]).unwrap();
        let bytes = t.canonical_bytes();
        // major type 2 (byte string), 32 bytes -> 0x40 | 24, then length 32.
        assert!(
            bytes.windows(2).any(|w| w == [0x58, 32]),
            "32-byte digest is not encoded as a CBOR byte string"
        );
    }
}
