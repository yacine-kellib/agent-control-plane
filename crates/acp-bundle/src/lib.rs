//! The policy bundle: the rule store the whole control plane reads from.
//!
//! The bundle is the only place authorisation rules exist. PB-4 states the
//! property that matters: runtime components — *including a fully compromised
//! Policy Engine* — hold no key capable of producing a valid bundle signature.
//! Policy is read-only to the runtime **by cryptography**, not by file
//! permissions.
//!
//! Scope of this crate, and what is deliberately not here yet:
//!
//! - [`tree`] — the index and the hash the signature covers: the member list,
//!   the header that says how to read it (including the declared suite), and
//!   [`walk_bundle`], which turns a directory into that member list. The
//!   suite's inclusion is a correction; see the module note.
//! - `model`  — the typed bundle contents. **Not written by hand.** The
//!   schemas in `spec/schemas/bundle/` are the normative source, and a
//!   hand-written Rust struct would be a second definition of one object,
//!   which is the encoding-split defect at source level. These types come from
//!   `tools/codegen.sh`, which does not exist yet — that is the next step, not
//!   an oversight.
//!
//! The walk is where an attacker's influence lands, because it is the part
//! decided by what is on disk rather than by what a caller passed. So it halts
//! on an unrecognised file type rather than skipping it (an unsigned file
//! inside a signed bundle is what the signature exists to deny), refuses
//! symlinks rather than following them (a tree hash must not depend on state
//! outside the bundle), and excludes `SIGNATURE` at the root only — a
//! signature cannot cover itself.

pub mod tree;
pub mod verify;

pub use tree::{Member, SIGNATURE_FILE, Tree, TreeError, WalkError, walk_bundle};
pub use verify::{
    BundleHost, BundleSignature, Reading, Refusal, Serving, Timestamp, VerifierConfig,
};
