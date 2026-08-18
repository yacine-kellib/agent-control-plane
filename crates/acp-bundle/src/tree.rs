//! Canonical bundle tree: the member index and the hash the signature covers.
//!
//! §8.2 says the SIGNATURE is "Ed25519 over SHA-256 of canonical bundle tree".
//! That sentence leaves three things unstated, and all three have to be pinned
//! here or two conformant implementations will disagree on a valid bundle:
//!
//!   1. WHICH FILES are in the tree. Answered by an explicit member index, so
//!      coverage is a signed fact rather than whatever the reader walked. Same
//!      reasoning as `tools/sign-release.sh` halting on an unrecognised file
//!      type instead of silently signing or silently skipping it.
//!   2. IN WHAT ORDER. Answered by a bytewise sort on the path. Bytewise, not
//!      locale-aware: a locale-dependent sort is a defect that only shows up on
//!      someone else's machine.
//!   3. WHETHER THE INDEX'S OWN HEADER IS COVERED. Answered yes, and this was
//!      wrong in the first cut of this file — see below.
//!
//! **A CORRECTION WORTH RECORDING.** The first version of this module hashed
//! `members` and nothing else, which left `signature.suite` — the field naming
//! *which primitives a verifier must require* — outside the signature that
//! field is part of. An attacker who can rewrite the index in flight relabels a
//! `hybrid-ed25519-mldsa65` bundle as `ed25519`, the verifier obligingly checks
//! one primitive, and the post-quantum leg is gone without a single byte of the
//! member list changing. That is CR-3 downgrade, reintroduced by the very code
//! written to prevent it, and it is the RES-8 class again: the verifier was
//! reading a security-determining value from the artifact under verification.
//! The header is now inside the hash. `schema_version` went in with it for the
//! same reason one version further out — a v2 that reinterprets `members` must
//! not be reachable by relabelling a v1.
//!
//! The hash is taken over canonical CBOR, reusing the encoding the repository
//! already has a validating decoder and eight tests for (AT-8a). Writing a
//! second canonicaliser here would be a second definition of one object, which
//! is the encoding-split defect at source level.

use acp_crypto::Suite;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The only bundle index version this build understands.
///
/// A constant rather than a field: a different version is a different reading
/// of `members`, so a build that hashes "1" and parses v2 semantics is the bug
/// this value exists to make unrepresentable. A loader meeting a foreign
/// `schema_version` must refuse the bundle, not construct a `Tree` for it.
pub const SCHEMA_VERSION: &str = "1";

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

/// The signed member index of one bundle, header included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    suite: Suite,
    members: Vec<Member>,
}

impl Tree {
    /// Build a tree, sorting members into canonical order.
    ///
    /// Sorting here rather than requiring pre-sorted input means a caller
    /// cannot produce a differently-ordered tree by accident. The order is
    /// part of what is hashed, so "the caller should sort first" would be a
    /// correctness requirement expressed as a comment.
    ///
    /// `suite` is the suite the bundle signature is issued under. It is taken
    /// as a [`Suite`] rather than a string so that the value the hash covers
    /// has exactly one spelling — see the module note on the header.
    pub fn new(suite: Suite, mut members: Vec<Member>) -> Result<Self, TreeError> {
        if members.is_empty() {
            return Err(TreeError::Empty);
        }
        members.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        for pair in members.windows(2) {
            if pair[0].path == pair[1].path {
                return Err(TreeError::DuplicatePath);
            }
        }
        Ok(Tree { suite, members })
    }

    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The suite this tree's signature is issued under, and which a verifier
    /// must therefore require in full (CR-3, conjunctive).
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The canonical CBOR encoding of the tree.
    ///
    /// Encoded by hand rather than through a serde derive, for one reason: the
    /// derive's output depends on struct field order and on the serialiser's
    /// map-key handling, neither of which is visible at the call site. What is
    /// hashed has to be readable in the same file that says what it means.
    ///
    /// Shape: `[schema_version, suite, [[path, digest], ...]]` — a
    /// definite-length 3-element array whose last element is a definite-length
    /// array of definite-length 2-element arrays. Arrays rather than maps
    /// because RFC 8949 canonical form orders map keys by encoded bytes, and
    /// relying on that ordering is one more thing an implementation can get
    /// subtly wrong when positional pairs express the same information with no
    /// ordering rule at all.
    ///
    /// The header comes first so that a truncated read cannot be mistaken for
    /// a shorter valid tree: the version and suite are decided before any
    /// member is.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_array_header(&mut out, 3);
        write_text(&mut out, SCHEMA_VERSION);
        write_text(&mut out, self.suite.as_wire());
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

// ---------------------------------------------------------------- the walk
//
// Turning a DIRECTORY into a member list. Everything above this line works on
// a list someone already had; this is where the list comes from, and it is the
// part an attacker can influence by putting a file somewhere.

/// Extensions a bundle member may have.
///
/// An allowlist, mirroring `tools/sign-release.sh`, and for the reason that
/// script records: its halt-on-unknown assertion is what surfaced a file the
/// previous allowlist would have skipped **while the manifest still looked
/// complete**. A skipped file in a signed tree is an unsigned file inside a
/// signed bundle, which is precisely the thing the signature is supposed to
/// deny. Adding a type here is a deliberate act, not a convenience.
const BUNDLE_EXTS: &[&str] = &["json", "md", "txt", "cddl"];

/// The detached signature. **Excluded from the tree**, and it must be: a
/// signature cannot cover itself, and if it were a member the file's digest
/// would have to be known before the file existed.
///
/// Excluded by NAME rather than by extension, so a `SIGNATURE.json` — which is
/// a different file — is still covered.
pub const SIGNATURE_FILE: &str = "SIGNATURE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// The filesystem refused. Carried as a string because the walk is offline
    /// tooling and the operator needs the path, not a typed taxonomy.
    Io(String),
    /// A file whose type is not on the allowlist. **Halts the walk.** Not
    /// skipped: a silently skipped file is unsigned content inside a signed
    /// bundle. Not signed either: a bundle is not a place to discover that a
    /// new file type exists.
    UnrecognisedFileType(String),
    /// A symlink anywhere in the bundle. Refused rather than followed or
    /// skipped — following one makes the tree hash depend on state outside the
    /// bundle (so two hosts with identical bundles disagree, or one reads
    /// `/etc/shadow` into a member), and skipping one hides a file the author
    /// believes is covered.
    Symlink(String),
    /// The resulting member list was not a valid tree.
    Tree(TreeError),
}

impl From<TreeError> for WalkError {
    fn from(e: TreeError) -> Self {
        WalkError::Tree(e)
    }
}

/// Build the canonical tree for the bundle rooted at `root`.
///
/// `suite` is the suite the bundle is signed under. It is a parameter rather
/// than something read out of `manifest.json`, and that is the RES-8 shape:
/// the value that decides *which primitives a verifier must require* cannot be
/// taken from the artifact under verification. It is hashed (see the module
/// note), so a relabel invalidates the signature; and a verifier additionally
/// checks it against a floor it was configured with out-of-band (CR-4).
///
/// **The attester registry is inside the resulting hash**, because `attesters/`
/// is walked like everything else. That is PB-KEY, and it was a real defect in
/// the reference: with the registry outside the hash, two Executors trusting
/// *different* attesters agree they hold the same bundle, `policy_bundle_hash`
/// stops determining who was allowed to approve, and P-3 — decisions replayable
/// bit-for-bit from the audit record — does not hold. `quorum_k` rides along in
/// the same file (PB-6), which is why it is authoritative.
pub fn walk_bundle(root: &Path, suite: Suite) -> Result<Tree, WalkError> {
    let mut members = Vec::new();
    collect(root, root, &mut members)?;
    Ok(Tree::new(suite, members)?)
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<Member>) -> Result<(), WalkError> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| WalkError::Io(format!("{}: {e}", dir.display())))?;

    for entry in entries {
        let entry = entry.map_err(|e| WalkError::Io(format!("{}: {e}", dir.display())))?;
        let path = entry.path();

        // symlink_metadata, not metadata: the latter follows the link and would
        // report the TARGET's type, so a symlink to a directory would be walked
        // as a directory and this check would never fire.
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| WalkError::Io(format!("{}: {e}", path.display())))?;
        if meta.is_symlink() {
            return Err(WalkError::Symlink(rel(root, &path)));
        }

        if meta.is_dir() {
            collect(root, &path, out)?;
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if name == SIGNATURE_FILE && path.parent() == Some(root) {
            continue;
        }

        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !BUNDLE_EXTS.contains(&ext.as_str()) {
            return Err(WalkError::UnrecognisedFileType(rel(root, &path)));
        }

        let bytes =
            std::fs::read(&path).map_err(|e| WalkError::Io(format!("{}: {e}", path.display())))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        out.push(Member::new(rel(root, &path), digest)?);
    }
    Ok(())
}

/// The member path: relative to the bundle root, with `/` separators on every
/// platform.
///
/// Hard-coded rather than taken from `std::path::MAIN_SEPARATOR`, because the
/// separator is inside the hash: a bundle walked on Windows must produce the
/// same tree hash as the same bundle walked on Linux, and `\` would silently
/// make it a different bundle. It would also be rejected by `Member::new`,
/// which is the second line of defence rather than the first.
fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
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

    const HYBRID: Suite = Suite::HybridEd25519MlDsa65;

    #[test]
    fn member_order_does_not_change_the_hash() {
        let a = Tree::new(
            HYBRID,
            vec![
                member("floors.json", 1),
                member("manifest.json", 2),
                member("attesters/alice.json", 3),
            ],
        )
        .unwrap();
        let b = Tree::new(
            HYBRID,
            vec![
                member("attesters/alice.json", 3),
                member("floors.json", 1),
                member("manifest.json", 2),
            ],
        )
        .unwrap();
        assert_eq!(a.hash(), b.hash(), "canonical order is not being applied");
    }

    #[test]
    fn changing_one_digest_changes_the_hash() {
        let before = Tree::new(HYBRID, vec![member("floors.json", 1)]).unwrap();
        let after = Tree::new(HYBRID, vec![member("floors.json", 2)]).unwrap();
        assert_ne!(
            before.hash(),
            after.hash(),
            "a tampered floors.json produced an identical tree hash"
        );
    }

    #[test]
    fn adding_a_file_changes_the_hash() {
        // An unsigned file smuggled into a signed bundle must not be free.
        let one = Tree::new(HYBRID, vec![member("manifest.json", 1)]).unwrap();
        let two = Tree::new(
            HYBRID,
            vec![member("manifest.json", 1), member("extra.json", 9)],
        )
        .unwrap();
        assert_ne!(one.hash(), two.hash());
    }

    #[test]
    fn downgrading_the_suite_changes_the_hash() {
        // THE CR-3 DOWNGRADE, at the index rather than at the verifier. The
        // member list is byte-identical; only the declared suite moves. If
        // these hashes matched, an attacker could relabel a hybrid bundle as
        // classical-only and the original signature would still verify over
        // it, so the verifier would require one primitive where the signer
        // required two.
        let members = || vec![member("manifest.json", 1), member("floors.json", 2)];
        let hybrid = Tree::new(HYBRID, members()).unwrap();
        let classical = Tree::new(Suite::Ed25519, members()).unwrap();
        assert_eq!(
            hybrid.members(),
            classical.members(),
            "the two trees must differ ONLY in the suite for this test to mean anything"
        );
        assert_ne!(
            hybrid.hash(),
            classical.hash(),
            "signature.suite is outside the tree hash — CR-3 downgrade is free"
        );
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
        let e = Tree::new(
            HYBRID,
            vec![member("floors.json", 1), member("floors.json", 2)],
        );
        assert_eq!(e, Err(TreeError::DuplicatePath));
    }

    #[test]
    fn empty_tree_is_refused() {
        assert_eq!(Tree::new(HYBRID, vec![]), Err(TreeError::Empty));
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
        //   cd reference/src && python3 -c "import acp_crypto as C, hashlib; \
        //     v = ['1', 'hybrid-ed25519-mldsa65', \
        //          [['manifest.json', bytes([0xAB]*32)]]]; \
        //     b = C.canon_cbor(v); print(b.hex()); \
        //     print(hashlib.sha256(b).hexdigest())"
        //
        // The constant MOVED when the header came inside the hash (see the
        // module note). That is a deliberate break of a value nothing has
        // signed yet, not a divergence: it was regenerated from Python after
        // the shape changed, not edited until Rust agreed with itself.
        //
        // If this test fails, ONE OF THE TWO ENCODERS IS WRONG. Find out which
        // before changing the constant — a divergence here is a specification
        // ambiguity, and patching the expected value hides it.
        const PYTHON_CANON_CBOR: &str = "836131766879627269642d656432353531392d6d6c6473613635\
                                         81826d6d616e69666573742e6a736f6e5820abababababababab\
                                         abababababababababababababababababababababababab";
        const PYTHON_SHA256: &str =
            "992660054cc117175d9037f853a5609341873442d79e155c11210427177e2904";

        let t = Tree::new(HYBRID, vec![member("manifest.json", 0xAB)]).unwrap();
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

    // ------------------------------------------------------------- the walk

    /// A bundle shaped like §8.2: manifest, policy tables, and an attester
    /// registry in its own directory.
    fn bundle(dir: &Path, attester_key: &str) {
        use std::fs;
        fs::write(dir.join("manifest.json"), br#"{"bundle_epoch":7}"#).unwrap();
        fs::write(dir.join("floors.json"), br#"{"payments":"T3"}"#).unwrap();
        fs::create_dir_all(dir.join("attesters")).unwrap();
        fs::write(
            dir.join("attesters/registry.json"),
            format!(r#"{{"quorum_k":2,"keys":["{attester_key}"]}}"#),
        )
        .unwrap();
    }

    #[test]
    fn the_attester_registry_is_inside_the_hash() {
        // PB-KEY, and a real defect in the reference before it was fixed. With
        // the registry outside the hash, two Executors trusting DIFFERENT
        // attesters agree they hold the same bundle: `policy_bundle_hash` stops
        // determining who was allowed to approve, and P-3 — decisions
        // replayable bit-for-bit from the audit record — does not hold. Nothing
        // else in the bundle has moved between these two.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        bundle(a.path(), "sha256:aaaa");
        bundle(b.path(), "sha256:bbbb");

        let ta = walk_bundle(a.path(), HYBRID).unwrap();
        let tb = walk_bundle(b.path(), HYBRID).unwrap();
        assert_eq!(
            ta.members().len(),
            tb.members().len(),
            "the two bundles must differ ONLY in the registry for this to mean anything"
        );
        assert_ne!(
            ta.hash(),
            tb.hash(),
            "swapping an attester key left the tree hash unchanged"
        );
    }

    #[test]
    fn quorum_k_is_inside_the_hash_too() {
        // PB-6 names the attester registry as the ONLY authoritative source of
        // the approval threshold. Authoritative means signed: if k could move
        // without moving the hash, a floor-HIGH action needing two approvals
        // could be relabelled to need one, under a signature that still checks.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        bundle(a.path(), "sha256:aaaa");
        bundle(b.path(), "sha256:aaaa");
        std::fs::write(
            b.path().join("attesters/registry.json"),
            br#"{"quorum_k":1,"keys":["sha256:aaaa"]}"#,
        )
        .unwrap();

        assert_ne!(
            walk_bundle(a.path(), HYBRID).unwrap().hash(),
            walk_bundle(b.path(), HYBRID).unwrap().hash(),
            "quorum_k moved from 2 to 1 without moving the tree hash"
        );
    }

    #[test]
    fn the_signature_is_not_a_member_of_the_tree_it_signs() {
        // A signature cannot cover itself: if SIGNATURE were a member, its
        // digest would have to be known before the file existed. So the two
        // bundles below — identical but for a SIGNATURE that only one has —
        // must hash the same, which is what makes "sign, then write SIGNATURE"
        // a coherent order of operations.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        bundle(a.path(), "sha256:aaaa");
        bundle(b.path(), "sha256:aaaa");
        std::fs::write(b.path().join(SIGNATURE_FILE), b"not-a-real-signature").unwrap();

        assert_eq!(
            walk_bundle(a.path(), HYBRID).unwrap().hash(),
            walk_bundle(b.path(), HYBRID).unwrap().hash(),
            "SIGNATURE is being hashed as a member"
        );
    }

    #[test]
    fn a_signature_named_file_deeper_in_the_tree_is_not_silently_excluded() {
        // The property under test is that `attesters/SIGNATURE` cannot become a
        // hole to park uncovered content in — the root exclusion must not
        // generalise by name alone.
        //
        // It is upheld by HALTING, not by covering, and the first version of
        // this test asserted the wrong mechanism: an extensionless file is not
        // on the allowlist, so the walk refuses it before the name is ever
        // considered. That is strictly stronger than including it — the author
        // is told the file exists and must decide, rather than having it
        // absorbed into a hash nobody reads. Recording which check fires
        // matters, because if the allowlist ever grew an extensionless entry
        // this test would be the one that notices the exclusion has become
        // reachable.
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path(), "sha256:aaaa");
        std::fs::write(dir.path().join("attesters/SIGNATURE"), b"smuggled").unwrap();
        assert_eq!(
            walk_bundle(dir.path(), HYBRID),
            Err(WalkError::UnrecognisedFileType(
                "attesters/SIGNATURE".into()
            )),
            "a nested file named SIGNATURE was silently excluded from the tree"
        );
    }

    #[test]
    fn an_unrecognised_file_type_halts_the_walk() {
        // Mirrors `tools/sign-release.sh`, whose halt-assertion surfaced a file
        // the previous allowlist would have skipped while the manifest still
        // looked complete. Skipping is the dangerous option: an unsigned file
        // inside a signed bundle is exactly what the signature should deny.
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path(), "sha256:aaaa");
        std::fs::write(dir.path().join("helper.sh"), b"#!/bin/sh\nrm -rf /\n").unwrap();

        assert_eq!(
            walk_bundle(dir.path(), HYBRID),
            Err(WalkError::UnrecognisedFileType("helper.sh".into()))
        );
    }

    #[test]
    fn a_symlink_is_refused_rather_than_followed_or_skipped() {
        // Following one makes the tree hash depend on state outside the bundle,
        // so two hosts holding identical bundles disagree — or one of them
        // reads a file it was never given. Skipping one hides content the
        // author believes is covered. Both are worse than refusing.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            bundle(dir.path(), "sha256:aaaa");
            std::os::unix::fs::symlink("/etc/hosts", dir.path().join("outside.json")).unwrap();
            assert_eq!(
                walk_bundle(dir.path(), HYBRID),
                Err(WalkError::Symlink("outside.json".into()))
            );
        }
    }

    #[test]
    fn nested_directories_are_walked_with_forward_slash_paths() {
        // The separator is inside the hash, so a bundle walked on Windows must
        // produce the same tree hash as the same bundle walked on Linux.
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path(), "sha256:aaaa");
        let t = walk_bundle(dir.path(), HYBRID).unwrap();
        let paths: Vec<_> = t.members().iter().map(|m| m.path()).collect();
        assert_eq!(
            paths,
            vec!["attesters/registry.json", "floors.json", "manifest.json"],
            "members are not in bytewise path order, or the separator is wrong"
        );
    }

    #[test]
    fn a_walked_bundle_hashes_to_what_python_computes() {
        // ACP-38's acceptance: the Python signer and the Rust verifier must
        // agree on the tree hash for the same bundle. The single-member vector
        // above pins the ENCODING; this pins the WALK — nested paths, bytewise
        // ordering across a directory boundary, and content digests taken from
        // real bytes rather than from a fixture's `[seed; 32]`.
        //
        // Regenerate with:
        //   cd reference/src && python3 -c "import acp_crypto as C, hashlib; \
        //     files = {'attesters/registry.json': b'...', \
        //              'floors.json': b'...', 'manifest.json': b'...'}; \
        //     m = [[p, hashlib.sha256(b).digest()] for p, b in sorted(files.items())]; \
        //     print(hashlib.sha256(C.canon_cbor(['1','hybrid-ed25519-mldsa65',m])).hexdigest())"
        //
        // A divergence here is a SPECIFICATION AMBIGUITY, not a constant to
        // update — that is how Z1 was found. Note that `sorted()` in Python and
        // the bytewise sort in `Tree::new` agree only because both order by the
        // encoded path bytes; if they ever disagree this is where it surfaces,
        // and the answer is to pin the rule in the spec, not to re-sort one
        // side until it matches the other.
        const PYTHON_SHA256: &str =
            "e279d1bdc00bbd7c8092db3f178f0e8eb1a92c21f94d5f8b1f16e7b9b6592af5";

        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path(), "sha256:aaaa");
        let t = walk_bundle(dir.path(), HYBRID).unwrap();
        assert_eq!(
            hex(&t.hash()),
            PYTHON_SHA256,
            "the Rust walk and the Python reference disagree on the tree hash"
        );
    }

    #[test]
    fn an_empty_directory_is_refused_rather_than_signed() {
        // An empty tree hashes to a fixed value any signer could produce, so
        // "signed empty bundle" would be a valid input. A bundle directory that
        // is empty is a mistake somewhere upstream, not a policy of no rules.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            walk_bundle(dir.path(), HYBRID),
            Err(WalkError::Tree(TreeError::Empty))
        );
    }

    #[test]
    fn editing_any_covered_file_moves_the_hash() {
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path(), "sha256:aaaa");
        let before = walk_bundle(dir.path(), HYBRID).unwrap().hash();
        std::fs::write(dir.path().join("floors.json"), br#"{"payments":"T1"}"#).unwrap();
        assert_ne!(
            walk_bundle(dir.path(), HYBRID).unwrap().hash(),
            before,
            "a resource floor was downgraded T3 -> T1 without moving the hash"
        );
    }

    #[test]
    fn digest_is_encoded_as_bytes_not_text() {
        // A hex *string* and a byte string are different CBOR values. Fixing
        // this later would silently invalidate every signature already issued.
        let t = Tree::new(HYBRID, vec![member("a.json", 0xAB)]).unwrap();
        let bytes = t.canonical_bytes();
        // major type 2 (byte string), 32 bytes -> 0x40 | 24, then length 32.
        assert!(
            bytes.windows(2).any(|w| w == [0x58, 32]),
            "32-byte digest is not encoded as a CBOR byte string"
        );
    }
}
