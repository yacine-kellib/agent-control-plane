//! The §8.4 grading fold: floors, risk functions, RV-1 reversibility, DR-13.
//!
//! This is the half of the decision path that turns a Proposal plus signed
//! policy into a **recomputed** risk grade. It holds no crypto and no ledger;
//! ACP-45's later slices add those. What it does hold is every place a grade
//! can come out lower than the policy author wrote, which is the only
//! direction that matters.
//!
//! # TR-8, and why every input here is recomputed
//!
//! Nothing in this module reads a risk value, a reversibility class or a
//! fidelity from a receipt. All three are derived from the **canonical
//! Proposal the verifier itself received** and the **signed bundle**. That is
//! TR-8, and it is the standing answer to the RES-8 family: a verifier must
//! never accept a derived security value from the party it is verifying.
//!
//! X1 is the concrete reason. A compromised issuer asserting `risk: LOW`
//! suppressed attestation entirely, because the Executor read the field
//! instead of computing it. RV-3 is the same defect one field over: an
//! asserted `REVERSIBLE` obtains Silent mode.
//!
//! # The three absent-rules are three DIFFERENT rules
//!
//! It is tempting to read them as one "fail safe" habit. They are not, and the
//! generated accessors keep them apart on purpose:
//!
//! | table | absent means | why not the others |
//! | --- | --- | --- |
//! | `floors` | **`T3`** (RK-1) | a value exists; the safe one is the highest |
//! | `reversibility` | **`IRREVERSIBLE`** (RV-1) | likewise, and it selects the acknowledgement regime |
//! | `risk_functions` | **REFUSE** (8.4-3) | grading HIGH would route an unknown action into the human quorum, teaching approvers to rubber-stamp what the author never considered (T-26, AT-7) |
//! | `notice_targets` | **REFUSE** (DR-13) | there is no fail-safe recipient to fall back to, so the fail-safe outcome is that the action does not run |
//!
//! P-4 says unknown is never LOW. It does not say unknown is always HIGH, and
//! two of the four rules above are refusals precisely because "conservative"
//! and "safe" come apart once a human is in the loop.

use std::collections::BTreeMap;

use acp_core::generated::{Floors, NoticeTargets, Reversibility, Risk, RiskFunctions, Tier};
use acp_el1::{Env, Value};

mod grade;
pub mod quorum;
pub mod receipt;

pub use grade::{grade_floor_risk, notice_recipients, recompute_reversibility};

/// A refusal, carrying the clause that governs it.
///
/// The clause id is the payload, not decoration: the Python↔Rust differential
/// compares **which rule fired**, and two implementations refusing one input
/// for different stated reasons have not been shown to agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub clause: &'static str,
    pub message: String,
}

impl Refusal {
    pub(crate) fn new(clause: &'static str, message: impl Into<String>) -> Self {
        Refusal { clause, message: message.into() }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.clause, self.message)
    }
}

impl std::error::Error for Refusal {}

/// The clause that governs the Proposal parameter domain.
///
/// §8.3.1: "Numeric literals are integers", and every FieldRef "MUST resolve to
/// a field declared in a typing environment derived from the Proposal schema".
/// Exported so a caller that wraps a deserialisation failure can name the rule
/// that fired instead of forwarding "data did not match any variant" — the
/// cross-language differential compares **which rule refused**, and a refusal
/// with no name has not been shown to agree with anything.
pub const PARAM_DOMAIN_CLAUSE: &str = "8.3.1";

/// The message every domain refusal below carries. Begins with the clause, and
/// `the_domain_refusal_names_its_clause` asserts that it still does.
const PARAM_DOMAIN_MSG: &str =
    "8.3.1: a Proposal parameter must be an integer or a string";

/// One Proposal parameter.
///
/// Integers and strings only. Nothing else has a type in the §8.3.1
/// environment, and the deserialiser below is where that is enforced — by
/// construction, so there is no second door and no check a caller can forget.
///
/// # Why this is hand-written rather than `#[serde(untagged)]` (ACP-74)
///
/// It used to be untagged, which refused a float for the right reason and with
/// the wrong error: serde reported "data did not match any variant", carrying
/// no clause. That is fine until the differential asks *which rule refused*.
///
/// The reference had the same domain and no refusal at all. `isinstance(v, int)`
/// is false for a float, so `port: 22.0` fell through to the STRING arm, a
/// string never compares equal to a number, and every numeric clause mentioning
/// that parameter silently stopped firing — the permissive direction, since a
/// clause that cannot fire cannot raise. Against the reference bundle,
/// `port: 22` graded HIGH and was refused for want of a quorum while
/// `port: 22.0` **executed with no attestations at all**. RFC 8259 has one
/// number type; `22` and `22.0` are the same number, and the Proposal is
/// written by the party under verification.
///
/// # bool is refused, and that is not tidiness
///
/// `isinstance(True, int)` is `True` in Python, so a JSON `true` bound as
/// `("num", True)` there and compared equal to `1`. This enum has no `Bool`
/// arm. Accepting it as a string instead would let `flag == 1` mean one thing
/// in each language, which is an accident of one type system deciding a control
/// outcome. Both sides refuse now, so both sides read the same.
///
/// # An integer too large for `i64` is refused, not narrowed
///
/// serde_json parses an integer beyond `u64` as an `f64`, so it arrives at
/// `visit_f64` and is refused with everything else outside the domain. Same
/// decision as the EL-1 literal in `acp-el1`, and for the same reason: a value
/// this implementation cannot represent must never take the permissive branch.
/// Python compares the real value, so the divergence is disclosed rather than
/// hidden — it is pinned in `tools/check-el1-differential.py`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    Num(i64),
    Str(String),
}

impl<'de> serde::Deserialize<'de> for ParamValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Domain;

        impl<'de> serde::de::Visitor<'de> for Domain {
            type Value = ParamValue;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(PARAM_DOMAIN_MSG)
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<ParamValue, E> {
                Ok(ParamValue::Num(v))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<ParamValue, E> {
                // Above `i64::MAX` this is out of range, not merely large.
                // Refused rather than wrapped: a wrapped threshold compares
                // SMALLER than the policy author wrote, which is permissive.
                i64::try_from(v)
                    .map(ParamValue::Num)
                    .map_err(|_| E::custom(PARAM_DOMAIN_MSG))
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ParamValue, E> {
                Ok(ParamValue::Str(v.to_owned()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<ParamValue, E> {
                Ok(ParamValue::Str(v))
            }

            // Everything below is a REFUSAL, spelled out one arm at a time.
            //
            // serde's default arms already error, but with a message about
            // types rather than about the clause, and the clause is the payload
            // the differential compares. They are also the arms an attacker
            // chooses, so leaving them implicit means the interesting half of
            // this type is the half nobody wrote down.
            //
            // (8.3.1-param-domain mutation target: make visit_f64 return
            // `Ok(ParamValue::Str(v.to_string()))` and the reference's defect is
            // back exactly as it was — the float becomes a string and every
            // numeric clause mentioning it stops firing.)
            fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<ParamValue, E> {
                Err(E::custom(PARAM_DOMAIN_MSG))
            }

            fn visit_bool<E: serde::de::Error>(self, _v: bool) -> Result<ParamValue, E> {
                Err(E::custom(PARAM_DOMAIN_MSG))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<ParamValue, E> {
                Err(E::custom(PARAM_DOMAIN_MSG))
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<ParamValue, E> {
                Err(E::custom(PARAM_DOMAIN_MSG))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                _: A,
            ) -> Result<ParamValue, A::Error> {
                Err(serde::de::Error::custom(PARAM_DOMAIN_MSG))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                _: A,
            ) -> Result<ParamValue, A::Error> {
                Err(serde::de::Error::custom(PARAM_DOMAIN_MSG))
            }
        }

        d.deserialize_any(Domain)
    }
}

/// The Proposal, as the verifier independently received it.
///
/// Deliberately NOT `deny_unknown_fields`: a Proposal carries fields this
/// module does not grade on, and refusing them here would turn every unrelated
/// schema addition into a grading failure. The fields below are the ones read.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Proposal {
    pub task_type: String,
    #[serde(default)]
    pub params: BTreeMap<String, ParamValue>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub cidrs: BTreeMap<String, u8>,
    #[serde(default)]
    pub schema_id: Option<String>,
}

/// The signed policy this module reads.
///
/// Borrowed, never owned, and never cached across a decision. §1250 names
/// caching as a way to manufacture a `T`: "an implementation can introduce a T
/// the specification does not have, for example by caching a bundle rather
/// than re-reading it".
pub struct Policy<'a> {
    pub floors: &'a Floors,
    pub risk_functions: &'a RiskFunctions,
    pub reversibility: &'a acp_core::generated::ReversibilityTable,
    pub notice_targets: &'a NoticeTargets,
    /// `schema_id` -> fidelity class.
    ///
    /// **A plain map, and that is a disclosed gap (ACP-73).** Every other
    /// table here is a generated type whose absent-rule comes from the
    /// schema's `x-acp-absent` annotation. `adapters` has **no schema** in
    /// `spec/schemas/bundle/`, so `tools/codegen.sh` emits no type and no
    /// accessor for it, and the TR-8 refusal below is hand-written in this
    /// crate exactly as it is hand-written in `acp_executor.py`.
    ///
    /// Hand-writing an `Adapters` wire type instead would be worse: CLAUDE.md
    /// is explicit that a hand-written type is a second definition of an
    /// object the specification defines. So this stays a bare map, visibly
    /// unlike its neighbours, until the schema exists.
    pub adapters: &'a BTreeMap<String, String>,
}

/// Build the EL-1 environment for a Proposal under a Policy.
///
/// This function is where a grade can quietly come out too low, so each
/// binding says what it is and what it must not become.
pub(crate) fn build_env(p: &Proposal, pol: &Policy<'_>) -> Result<Env, Refusal> {
    let mut env = Env::new();

    for (k, v) in &p.params {
        env.insert(
            k.clone(),
            match v {
                ParamValue::Num(n) => Value::Num(*n),
                ParamValue::Str(s) => Value::Str(s.clone()),
            },
        );
    }

    // Per-target effective tier. FLOOR ONLY (TR-5): Context-Store raises are
    // deliberately ignored on this path. The floor is signed policy; a raise is
    // a value the Context Store supplies, and TR-8's whole point is that the
    // recomputation uses only what the verifier already trusts.
    for res in &p.targets {
        env.insert(format!("{res}.effective_tier"), Value::Tier(tier_ord(pol.floors.get(res))));
    }

    // The aggregate `resource.effective_tier`: the MAX floor over the targets.
    //
    // THE EMPTY CASE IS T3, NOT "no binding" AND NOT T0.
    //
    // Python spells it `max(..., default=TIER["T3"])`. Rust's `.max()` over an
    // empty iterator is `None`, and the two obvious ways to handle that are
    // both wrong: `unwrap_or(Tier::T0)` grades a target-less proposal as the
    // least sensitive thing in the deployment, and omitting the binding makes
    // every clause mentioning it `false` under §8.3.1 totality — which is the
    // permissive direction for a `raise_to`, since a clause that cannot fire
    // cannot raise.
    //
    // (empty-targets-T3 mutation target: replace T3 with T0, or drop the
    // binding, and the empty-targets grading test starts passing at LOW.)
    let aggregate = p
        .targets
        .iter()
        .map(|r| tier_ord(pol.floors.get(r)))
        .max()
        .unwrap_or_else(|| tier_ord(Tier::T3));
    env.insert("resource.effective_tier".into(), Value::Tier(aggregate));

    for (k, v) in &p.cidrs {
        env.insert(k.clone(), Value::Cidr(*v));
    }

    // TR-8: an unregistered schema_id is REFUSED, not defaulted. `fidelity` is
    // readable by any raise_to clause, so a default would be a policy value
    // this code invented. See ACP-73 -- the absent-rule is hand-written here
    // because `adapters` has no schema to generate it from.
    let sid = p.schema_id.as_deref().unwrap_or("");
    let Some(fidelity) = pol.adapters.get(sid) else {
        return Err(Refusal::new("TR-8", "schema_id not bound to a registered adapter"));
    };
    env.insert("fidelity".into(), Value::Str(fidelity.clone()));

    Ok(env)
}

/// A tier as its ordinal, for EL-1's ordered comparison.
///
/// `Tier` is generated with `Ord` because `floors.schema.json` declares the
/// domain ordered. This maps it onto the same small integers `acp-el1` and
/// `acp_executor.py` both use, in one place, so the two spellings of "T2 is 2"
/// cannot drift.
pub(crate) fn tier_ord(t: Tier) -> u8 {
    match t {
        Tier::T0 => 0,
        Tier::T1 => 1,
        Tier::T2 => 2,
        Tier::T3 => 3,
    }
}

pub(crate) fn risk_ord(r: Risk) -> u8 {
    match r {
        Risk::Low => 0,
        Risk::Medium => 1,
        Risk::High => 2,
    }
}

pub(crate) fn risk_of(ord: u8) -> Risk {
    match ord {
        0 => Risk::Low,
        1 => Risk::Medium,
        _ => Risk::High,
    }
}

/// Re-exported so callers need not depend on `acp-core` to name a verdict.
pub use acp_core::generated::{Reversibility as Rev, Risk as RiskLevel};

#[allow(unused_imports)]
use Reversibility as _;
