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

/// One Proposal parameter.
///
/// Integers and strings only, matching `acp_executor.py`'s
/// `("num", v) if isinstance(v, int) else ("str", v)`.
///
/// **`isinstance(v, int)` is `True` for `bool` in Python**, so a JSON `true`
/// becomes `("num", True)` there and compares equal to `1`. This enum has no
/// `Bool`, so a boolean parameter is a divergence rather than a silent
/// coercion — surfaced by [`ParamValue`]'s deserialiser refusing it. That is
/// deliberate: reproducing Python's bool-is-an-int would import an accident of
/// its type system into a security decision, and silently accepting it as a
/// string would let `flag == 1` mean something different in each language.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(untagged)]
pub enum ParamValue {
    Num(i64),
    Str(String),
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
