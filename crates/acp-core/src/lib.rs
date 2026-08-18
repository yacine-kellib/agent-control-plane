//! Core ACP types.
//!
//! Two kinds of thing live here and the split is deliberate.
//!
//! [`generated`] holds the **wire types**, emitted by `tools/codegen.sh` from
//! `spec/schemas/bundle/`. `spec/` is the only normative source, so a
//! hand-written wire type is a second definition of an object the
//! specification already defines — and two definitions of one object is the
//! encoding-split defect at the source level. Do not edit that file;
//! `./tools/codegen.sh --check` runs from `tools/selftest.sh` and will fail.
//!
//! This file holds what the schemas cannot express: **behaviour**.
//! [`BundleEpoch`] is here because PB-5's rule is a comparison, not a shape,
//! and a schema constrains what a document contains rather than how two
//! documents relate.
//!
//! # What moved out of here, and why it was wrong (ACP-51)
//!
//! There used to be one hand-written `RiskTier { Low, Medium, High }` whose doc
//! comment read *"a resource absent from `floors.json` is **T3**"*. The enum it
//! annotated had no T3. `@acp/types` carried the same defect one step worse, as
//! a value: `UNCLASSIFIED_RESOURCE_TIER: RiskTier = 'HIGH'`.
//!
//! The schemas define **two ordered domains over different subjects**:
//! [`generated::Tier`] (`T0 < T1 < T2 < T3`, how sensitive a resource is) and
//! [`generated::Risk`] (`LOW < MEDIUM < HIGH`, how dangerous an action is).
//! §8.4 composes both with `max`, which is exactly why one enum served for both
//! until someone read the schema as a producer of types: every wrong
//! composition typechecked. Nothing consumed either value yet, so the defect
//! was latent — and phase 9 puts the decision path in Rust, which is where a
//! floors lookup returning `High` would have started being read.
//!
//! Both are now generated, separately, and the fail-safe *pattern* is
//! unchanged: the default is a named function, never an `Option` a caller
//! unwraps. Only its domain was corrected.

pub mod generated;

pub use generated::{Reversibility, Risk, Tier};

impl Tier {
    /// The tier for a resource with no entry in the signed floors table.
    ///
    /// RK-1: absent means unknown, and unknown is the **highest** tier, not the
    /// lowest. Returning `T0` or `T1` here is the whole class of defect this
    /// specification exists to prevent (P-4: unknown is never LOW).
    ///
    /// The value comes from `x-acp-absent` on `floors.schema.json`, through
    /// [`generated::Floors::get`], which is what this delegates to. It is
    /// stated here as well because the name is the one callers reach for, and a
    /// second spelling of one constant is what this whole module is about — so
    /// the test below asserts the two agree rather than trusting them to.
    pub const fn for_unclassified() -> Self {
        Tier::T3
    }
}

/// A policy bundle epoch (PB-5).
///
/// Strictly increasing, never reused, never decreased. The Executor keeps a
/// high-water mark **indefinitely** (CL-4) — an expiring epoch mark would
/// reopen rollback, which is why retention here differs from nonces.
///
/// Hand-written rather than generated, and that is the line between this file
/// and [`generated`]: the schema can say `bundle_epoch` is a non-negative
/// integer, and it cannot say that one bundle's epoch must exceed another's.
///
/// The monotonicity check lives on the type rather than at each call site.
/// [`BundleEpoch::accepts`] is the only way to ask the question, and it is
/// deliberately not `PartialOrd`: `>=` would silently accept a replay of the
/// *current* epoch, and that is the shape of the bug rather than an edge case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleEpoch(u64);

impl BundleEpoch {
    pub const fn new(n: u64) -> Self {
        BundleEpoch(n)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether `candidate` may replace `self` as the active epoch.
    ///
    /// Strictly greater. Equal is refused: re-serving the current epoch is how
    /// a rollback is dressed up as a no-op, and a bundle whose content changed
    /// under an unchanged epoch is exactly what PB-5 forbids.
    pub const fn accepts(self, candidate: BundleEpoch) -> bool {
        candidate.0 > self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generated::{Floors, ReversibilityTable};

    /// The four tests below are the only automated check that the
    /// `x-acp-absent` annotations still agree with the clauses they cite.
    ///
    /// Codegen reads the annotation and emits whatever it says. Edit
    /// `floors.schema.json` to claim `"value": "T1"` and the generator will
    /// cheerfully produce it, `--check` will pass because the output matches
    /// the schema, and every gate stays green. These assertions are what goes
    /// red. Nothing else covers annotation-versus-clause agreement until phase
    /// 9's decision path gives Python something to differ from.
    #[test]
    fn unclassified_resources_are_t3_not_t1() {
        assert_eq!(Tier::for_unclassified(), Tier::T3);
    }

    #[test]
    fn a_floors_table_returns_t3_for_a_resource_it_does_not_name() {
        // Through the generated accessor, which is the path a caller takes.
        // Asserting only on `for_unclassified()` would leave the accessor
        // itself — the thing with the `unwrap_or` in it — unchecked.
        let floors: Floors =
            serde_json::from_str(r#"{"schema_version":"1","floors":{"cache":"T0"}}"#).unwrap();
        assert_eq!(floors.get("cache"), Tier::T0);
        assert_eq!(floors.get("production-database"), Tier::for_unclassified());
        assert_eq!(floors.get("production-database"), Tier::T3);
    }

    #[test]
    fn unclassified_actions_are_irreversible() {
        let table: ReversibilityTable = serde_json::from_str(
            r#"{"schema_version":"1","reversibility":{"read_file":"REVERSIBLE"}}"#,
        )
        .unwrap();
        assert_eq!(table.get("read_file"), Reversibility::Reversible);
        assert_eq!(table.get("send_email"), Reversibility::Irreversible);
    }

    #[test]
    fn tiers_and_risks_are_separate_ladders_that_both_compose_with_max() {
        // The two domains ACP-51 found collapsed into one. They are ordered
        // independently and there is no conversion between them, which is what
        // makes a floor-versus-risk mix-up fail to compile rather than fail to
        // matter.
        assert!(Tier::T3 > Tier::T0);
        assert_eq!(Tier::T0.max(Tier::T3), Tier::T3);
        assert!(Risk::High > Risk::Low);
        assert_eq!(Risk::Low.max(Risk::High), Risk::High);
    }

    #[test]
    fn a_suite_has_no_ordering_because_cr4_is_containment_not_rank() {
        // Asserted against the GENERATED SOURCE, because Rust has no way to
        // say "this type does not implement Ord" — every generic bound trick
        // for it either fails coherence or accepts everything, and a test that
        // accepts everything is worse here than no test.
        //
        // CR-4's floor is satisfied by CONTAINMENT of primitives, never by
        // rank: `ed25519` and `slhdsa128s` are incomparable, not adjacent. A
        // derived `Ord` would make `declared >= floor` compile, and that
        // comparison is the downgrade. So `suite_id` deliberately carries no
        // `x-acp-ordered`, and this is what notices if it gains one.
        let src = include_str!("generated.rs");
        let decl = src
            .split("pub enum SuiteId")
            .next()
            .expect("generated.rs declares SuiteId");
        let derive = decl
            .rsplit_once("#[derive(")
            .expect("SuiteId has a derive attribute")
            .1;
        let derive = &derive[..derive.find(')').expect("derive closes")];
        assert!(
            !derive.contains("Ord"),
            "SuiteId derives an ordering: {derive}. CR-4 is containment, not rank."
        );

        // The ordered ladders keep theirs, so the assertion above is about the
        // annotation rather than about the generator having stopped emitting
        // orderings at all.
        let tier = src.split("pub enum Tier").next().unwrap();
        assert!(
            tier.rsplit_once("#[derive(").unwrap().1.contains("Ord"),
            "Tier lost its ordering; §8.4 composes tiers with max"
        );

        assert!(generated::SuiteId::from_wire("ed25519").is_some());
        assert!(
            generated::SuiteId::from_wire("ed25519-but-longer").is_none(),
            "an unknown suite must be None so the caller refuses it (CR-1)"
        );
    }

    #[test]
    fn epoch_must_strictly_increase() {
        let active = BundleEpoch::new(7);
        assert!(active.accepts(BundleEpoch::new(8)));
        assert!(!active.accepts(BundleEpoch::new(6)), "rollback accepted");
        assert!(
            !active.accepts(BundleEpoch::new(7)),
            "replay of the current epoch accepted — PB-5 requires strictly increasing"
        );
    }
}
