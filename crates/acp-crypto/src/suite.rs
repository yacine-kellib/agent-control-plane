//! The signature suite table (CR-1, CR-4).
//!
//! Mirrors `SUITES` / `SUITE_RANK` / `_PRIMS_IMPLEMENTED` in
//! `reference/src/acp_executor.py`. The two tables must agree, and the
//! differential tests are what keep them agreeing — this is a second
//! implementation of one specification, which is the point (it is how Z1 was
//! found) and also the risk.
//!
//! `pq-slh` (SLH-DSA, FIPS 205) is DECLARED AND NOT IMPLEMENTED. It carries its
//! own primitive name rather than sharing `pq` with ML-DSA. Sharing would mean
//! a receipt claiming suite `slhdsa128s` had in fact been verified against an
//! ML-DSA key — the suite label naming one algorithm and the bytes another,
//! which is the encoding-split defect wearing a cryptographic hat. **Do not
//! alias it to `pq` to make a test pass.**

/// One cryptographic primitive within a suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Primitive {
    /// Ed25519, RFC 8032.
    Classical,
    /// ML-DSA-65, FIPS 204.
    Pq,
    /// SLH-DSA, FIPS 205. Declared, not implemented, fails closed.
    PqSlh,
}

impl Primitive {
    /// Whether this build can actually verify the primitive.
    ///
    /// An unimplemented primitive is never a pass. It resolves to
    /// [`crate::PrimitiveVerdict::Unsupported`], which `verify_hybrid` refuses
    /// — CR-1: an unknown suite is refused rather than ignored.
    pub const fn is_implemented(self) -> bool {
        matches!(self, Primitive::Classical | Primitive::Pq)
    }
}

/// A named signature suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    Ed25519,
    HybridEd25519MlDsa65,
    SlhDsa128s,
}

impl Suite {
    /// Parse a wire suite name. Unknown names are `None` and MUST be refused
    /// by the caller, never defaulted to a known suite.
    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "ed25519" => Some(Suite::Ed25519),
            "hybrid-ed25519-mldsa65" => Some(Suite::HybridEd25519MlDsa65),
            "slhdsa128s" => Some(Suite::SlhDsa128s),
            _ => None,
        }
    }

    pub const fn as_wire(self) -> &'static str {
        match self {
            Suite::Ed25519 => "ed25519",
            Suite::HybridEd25519MlDsa65 => "hybrid-ed25519-mldsa65",
            Suite::SlhDsa128s => "slhdsa128s",
        }
    }

    /// Every primitive this suite requires. Verification is conjunctive over
    /// all of them (CR-3).
    pub const fn primitives(self) -> &'static [Primitive] {
        match self {
            Suite::Ed25519 => &[Primitive::Classical],
            Suite::HybridEd25519MlDsa65 => &[Primitive::Classical, Primitive::Pq],
            Suite::SlhDsa128s => &[Primitive::PqSlh],
        }
    }

    /// Whether this suite satisfies a signed floor.
    ///
    /// CR-4: the floor lives in the signed bundle precisely so that a
    /// downgrade cannot be negotiated at runtime.
    ///
    /// **CONTAINMENT, NOT RANK, and this is a correction.** The first cut of
    /// this file mirrored the reference's `SUITE_RANK` — `{ed25519: 0,
    /// slhdsa128s: 1, hybrid: 2}` — and asked `self.rank() >= floor.rank()`.
    /// That is a total order over sets that are not comparable. `hybrid` is
    /// `{classical, pq}` and does not contain `pq-slh`, yet it outranked
    /// `slhdsa128s`: a deployment whose signed floor said "hash-based
    /// post-quantum, no lattice assumption" accepted a signature whose
    /// post-quantum leg was ML-DSA. That is not a stronger suite being
    /// accepted, it is a different hardness assumption substituted, with the
    /// floor check reporting satisfaction.
    ///
    /// The floor is satisfied iff every primitive it names is present. Extra
    /// primitives are fine; a missing one never is, whatever is offered in its
    /// place.
    pub fn satisfies_floor(self, floor: Suite) -> bool {
        floor
            .primitives()
            .iter()
            .all(|needed| self.primitives().contains(needed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_requires_both_primitives() {
        assert_eq!(
            Suite::HybridEd25519MlDsa65.primitives(),
            &[Primitive::Classical, Primitive::Pq]
        );
    }

    #[test]
    fn slh_dsa_is_declared_but_not_implemented() {
        // It must parse — a deployment can name it — and it must fail closed,
        // because naming is not implementing.
        let s = Suite::from_wire("slhdsa128s").expect("declared suite should parse");
        assert!(!s.primitives()[0].is_implemented());
    }

    #[test]
    fn slh_dsa_does_not_share_the_ml_dsa_primitive() {
        // If these were equal, a receipt claiming slhdsa128s would be verified
        // against an ML-DSA key: the label naming one algorithm and the bytes
        // another.
        assert_ne!(Primitive::PqSlh, Primitive::Pq);
    }

    #[test]
    fn unknown_suite_does_not_default_to_a_known_one() {
        assert_eq!(Suite::from_wire("ed25519-but-trust-me"), None);
        assert_eq!(Suite::from_wire(""), None);
        assert_eq!(Suite::from_wire("HYBRID-ED25519-MLDSA65"), None);
    }

    #[test]
    fn classical_alone_does_not_satisfy_a_hybrid_floor() {
        // The CR-4 downgrade: a signer offering Ed25519 against a bundle whose
        // signed floor is hybrid must be refused.
        assert!(!Suite::Ed25519.satisfies_floor(Suite::HybridEd25519MlDsa65));
        assert!(Suite::HybridEd25519MlDsa65.satisfies_floor(Suite::HybridEd25519MlDsa65));
        // Still accepted, and now for the right reason: hybrid CONTAINS
        // classical. Not because it scores higher on a scale.
        assert!(Suite::HybridEd25519MlDsa65.satisfies_floor(Suite::Ed25519));
    }

    #[test]
    fn hybrid_does_not_satisfy_an_slh_dsa_floor() {
        // THE INCOMPARABILITY. Under the rank table this passed, because
        // hybrid scored 2 and slhdsa128s scored 1. It carries no SLH-DSA at
        // all: a deployment that chose hash-based post-quantum specifically
        // would have been served a lattice signature and told its floor was
        // met.
        assert!(!Suite::HybridEd25519MlDsa65.satisfies_floor(Suite::SlhDsa128s));
        // And the converse, which the rank table also got wrong in the other
        // direction: SLH-DSA alone carries no classical leg.
        assert!(!Suite::SlhDsa128s.satisfies_floor(Suite::Ed25519));
        assert!(!Suite::SlhDsa128s.satisfies_floor(Suite::HybridEd25519MlDsa65));
        // A suite always satisfies its own floor.
        assert!(Suite::SlhDsa128s.satisfies_floor(Suite::SlhDsa128s));
    }

    #[test]
    fn wire_names_round_trip() {
        for s in [
            Suite::Ed25519,
            Suite::HybridEd25519MlDsa65,
            Suite::SlhDsa128s,
        ] {
            assert_eq!(Suite::from_wire(s.as_wire()), Some(s));
        }
    }

    #[test]
    fn primitive_sets_match_the_python_reference() {
        // acp_executor.py: SUITES = {
        //   "ed25519":                ("classical",),
        //   "hybrid-ed25519-mldsa65": ("classical", "pq"),
        //   "slhdsa128s":             ("pq-slh",)}
        //
        // This replaced a test pinning the old SUITE_RANK values. The ranks
        // agreed across the two implementations and were wrong in both, which
        // is worth remembering about differential tests: agreement is evidence
        // about consistency, never about correctness. The sets are what CR-4
        // actually decides on now, so the sets are what gets pinned.
        assert_eq!(Suite::Ed25519.primitives(), &[Primitive::Classical]);
        assert_eq!(
            Suite::HybridEd25519MlDsa65.primitives(),
            &[Primitive::Classical, Primitive::Pq]
        );
        assert_eq!(Suite::SlhDsa128s.primitives(), &[Primitive::PqSlh]);
    }
}
