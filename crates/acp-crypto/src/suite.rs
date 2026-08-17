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

    /// CR-4 ordering, for comparing against the bundle's signed `min_suite`
    /// floor. Higher rank is stronger.
    pub const fn rank(self) -> u8 {
        match self {
            Suite::Ed25519 => 0,
            Suite::SlhDsa128s => 1,
            Suite::HybridEd25519MlDsa65 => 2,
        }
    }

    /// Whether this suite satisfies a signed floor.
    ///
    /// CR-4: the floor lives in the signed bundle precisely so that a
    /// downgrade cannot be negotiated at runtime. A suite at or above the
    /// floor passes; anything below is refused.
    pub const fn satisfies_floor(self, floor: Suite) -> bool {
        self.rank() >= floor.rank()
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
        assert!(Suite::HybridEd25519MlDsa65.satisfies_floor(Suite::Ed25519));
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
    fn ranks_match_the_python_reference() {
        // acp_executor.py: SUITE_RANK = {"ed25519": 0, "slhdsa128s": 1,
        //                                "hybrid-ed25519-mldsa65": 2}
        assert_eq!(Suite::Ed25519.rank(), 0);
        assert_eq!(Suite::SlhDsa128s.rank(), 1);
        assert_eq!(Suite::HybridEd25519MlDsa65.rank(), 2);
    }
}
