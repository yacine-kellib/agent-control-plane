//! Core ACP types.
//!
//! Everything here is generated from or derived by hand against
//! `spec/ACP-SPEC-001.md`. Once `spec/schemas/` exists, the wire types move to
//! codegen (`tools/codegen.sh`) and stop being hand-written: two definitions of
//! one object is the encoding-split defect at the source level.
//!
//! Scaffold status: only the fail-safe defaults are implemented, because they
//! are the part that is unambiguous without the schemas. Policy evaluation
//! lives in `services/policy` and is not started.

/// Risk tier. Ordered so that `max` composes the way §8.4 requires.
///
/// A resource absent from `floors.json` is **T3**, never T1 (P-4: unknown is
/// never LOW). That default is expressed by [`RiskTier::for_unclassified`]
/// rather than by an `Option` the caller may unwrap carelessly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

impl RiskTier {
    /// The tier for a resource with no entry in the signed floors table.
    ///
    /// RK-1: absent means unknown, and unknown is the highest tier, not the
    /// lowest. Returning `Low` here would be the whole class of defect this
    /// specification exists to prevent.
    pub const fn for_unclassified() -> Self {
        RiskTier::High
    }
}

/// Whether an action can be undone.
///
/// RV-1: an action with no entry in `reversibility.json` is IRREVERSIBLE. The
/// `Default` impl encodes it so that a struct update or a deserialisation gap
/// cannot silently produce the permissive value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reversibility {
    Reversible,
    Irreversible,
}

// clippy suggests `#[derive(Default)]` with `#[default]` on the variant. It is
// equivalent today, and the manual impl is kept anyway: this default is a
// control (RV-1), not a convenience, and a derive attribute on a variant is
// easy to move while editing an enum. Spelling it out puts the fail-safe
// direction next to the sentence explaining why it points that way.
#[allow(clippy::derivable_impls)]
impl Default for Reversibility {
    fn default() -> Self {
        Reversibility::Irreversible
    }
}

/// A policy bundle epoch (PB-5).
///
/// Strictly increasing, never reused, never decreased. The Executor keeps a
/// high-water mark **indefinitely** (CL-4) — an expiring epoch mark would
/// reopen rollback, which is why retention here differs from nonces.
///
/// The monotonicity check lives on the type rather than at each call site.
/// [`accepts`] is the only way to ask the question, and it is deliberately
/// not `PartialOrd`: `>=` would silently accept a replay of the *current*
/// epoch, and that is the shape of the bug rather than an edge case.
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

    #[test]
    fn unclassified_resources_are_high_not_low() {
        assert_eq!(RiskTier::for_unclassified(), RiskTier::High);
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

    #[test]
    fn unclassified_actions_are_irreversible() {
        assert_eq!(Reversibility::default(), Reversibility::Irreversible);
    }

    #[test]
    fn tiers_order_so_that_max_escalates() {
        assert!(RiskTier::High > RiskTier::Low);
        assert_eq!(RiskTier::Low.max(RiskTier::High), RiskTier::High);
    }
}
