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
//! - [`tree`] — the index and the hash the signature covers: the member list
//!   AND the header that says how to read it, including the declared suite.
//!   Complete. The suite's inclusion is a correction; see the module note.
//! - `model`  — the typed bundle contents. **Not written by hand.** The
//!   schemas in `spec/schemas/bundle/` are the normative source, and a
//!   hand-written Rust struct would be a second definition of one object,
//!   which is the encoding-split defect at source level. These types come from
//!   `tools/codegen.sh`, which does not exist yet — that is the next step, not
//!   an oversight.
//! - `verify` — verify-on-read. Blocked on `model` and on real primitives in
//!   `acp-crypto`, which currently implements the CR-3 composition but neither
//!   underlying signature scheme.
//!
//! Nothing here can verify a signature yet, and nothing here pretends to.

pub mod tree;

pub use tree::{Member, Tree, TreeError};
