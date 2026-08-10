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

impl Default for Reversibility {
    fn default() -> Self {
        Reversibility::Irreversible
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
    fn unclassified_actions_are_irreversible() {
        assert_eq!(Reversibility::default(), Reversibility::Irreversible);
    }

    #[test]
    fn tiers_order_so_that_max_escalates() {
        assert!(RiskTier::High > RiskTier::Low);
        assert_eq!(RiskTier::Low.max(RiskTier::High), RiskTier::High);
    }
}
