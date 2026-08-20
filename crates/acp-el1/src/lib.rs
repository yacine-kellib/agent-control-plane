//! EL-1 — the §8.3.1 expression language, parsed and evaluated.
//!
//! `RaiseClause::if` in a signed bundle is an EL-1 source string. Grading an
//! action means evaluating it, so this is the first thing the Rust decision
//! path needs and the thing most exposed to divergence from the Python
//! reference.
//!
//! # Why this crate exists at all, rather than a parser dependency
//!
//! Z1. Through v1.3.3 the §8.3.1 production placed `&&` and `||` at one level
//! with no precedence and no associativity rule, so "the" meaning of a mixed
//! expression was not a property of the specification — it was a property of
//! whichever parser read it. Two evaluators written independently from the
//! prose disagreed on **493 of 10,000** generated cases, minimal witness:
//!
//! ```text
//! action != 'deny' || action == 'allow' && action == 'allow'
//! ```
//!
//! A literal left-to-right fold of the flat production yields `((a || b) && c)`
//! and evaluates it `false`; the C-family reading yields `(a || (b && c))` and
//! evaluates it `true`. EL-1 closed that by making the C-family reading
//! normative: **`&&` binds tighter than `||`, both left-associative.**
//!
//! Where it hid is the part worth keeping. Annex B proves eight theorems about
//! **parsed** `Expr` values, and the differential harness generated **ASTs** —
//! so the entire assurance apparatus sat downstream of the ambiguity and could
//! not see it. RES-10 states the general lesson: *every proof has a boundary,
//! and the defect will be found immediately outside it.*
//!
//! That is why §1246 makes the parser a separate conformance obligation, to be
//! exercised on **source text** and run against the deployment's own parser
//! rather than only its evaluator, and why this crate takes no dependencies:
//! a precedence rule implemented inside someone else's combinator library is
//! a rule this deployment cannot answer for.
//!
//! # Totality
//!
//! Evaluation is **total**: every well-formed expression yields `true` or
//! `false` and there is no error path at evaluation time, therefore no error
//! path to fall open through. Absent field, type mismatch, `.prefixlen` on a
//! non-CIDR value — each is `false`, never a raise and never a skip.
//!
//! Parsing is the only fallible half, and it fails **closed** with the clause
//! id `8.3.1`, matching `reference/src/acp_executor.py`'s `FailClosed`.
//!
//! # Monotonicity, and what this crate deliberately does not do
//!
//! §8.4 folds `raise_to` clauses with `max` (RK-3), so grading is monotone in
//! the set of satisfied clauses. That fold lives in the decision path, not
//! here. This crate answers one question — *does this expression hold in this
//! environment* — and holds no policy opinion, which is what makes it
//! differentially testable against Python in isolation.

mod eval;
mod parse;

pub use eval::{eval, Env};
pub use parse::{parse, CmpOp, Expr, Operand};

/// A parse failure, carrying the clause id that governs it.
///
/// The id is part of the value rather than a log line because the Python↔Rust
/// differential compares **which rule fired**, not merely that both sides
/// refused. Two implementations that refuse the same input for different
/// stated reasons have not been shown to agree; that is the check
/// `tools/check-bundle-differential.py` already applies to bundle verdicts,
/// and it applies here for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct El1Error {
    /// Always `"8.3.1"` today. Kept as a field, not a constant, so that a
    /// future clause split shows up in the differential rather than silently
    /// widening one id to cover two rules.
    pub clause: &'static str,
    pub message: String,
}

impl El1Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        El1Error { clause: "8.3.1", message: message.into() }
    }
}

impl std::fmt::Display for El1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.clause, self.message)
    }
}

impl std::error::Error for El1Error {}

/// A value in the evaluation environment, or in the expression source.
///
/// The tag is load-bearing, not a convenience. §8.3.1's evaluation rules make
/// **type mismatch ⇒ false**, so comparing a string to a number must be `false`
/// rather than a coercion or a panic — and the only way to say that is to
/// carry the type at runtime. Python spells the same thing as a `(tag, value)`
/// tuple; this is that tuple with the tags checked at compile time.
///
/// [`Value::Absent`] is a real inhabitant rather than an `Option` wrapper
/// because absence is a *value-level* rule here (absent ⇒ false, totality),
/// not an error to be propagated. An `Option` invites a caller to `unwrap_or`
/// a default, and the fail-safe-default discipline in `acp-core` exists
/// precisely because that pattern once produced the permissive answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    /// `T0`–`T3` as an ordinal. Ordered, and comparable only with other tiers.
    Tier(u8),
    Num(i64),
    /// A CIDR prefix length. Only `.prefixlen <= n` reads it.
    Cidr(u8),
    /// No such field in the environment. Every comparison against it is
    /// `false` (§8.3.1 field resolution: absent path ⇒ false, totality).
    Absent,
}

/// `T0`–`T3` to its ordinal, or `None` if the token is not a tier literal.
///
/// Shared by the lexer and by callers building an [`Env`], so the two cannot
/// drift into disagreeing about what `T2` means — a second spelling of one
/// constant being the defect `acp-core`'s module docs are about.
pub fn tier_ordinal(token: &str) -> Option<u8> {
    match token {
        "T0" => Some(0),
        "T1" => Some(1),
        "T2" => Some(2),
        "T3" => Some(3),
        _ => None,
    }
}

/// Parse and evaluate in one call.
///
/// The convenience form. Callers grading a bundle should [`parse`] once and
/// evaluate many times instead — but note that caching a parsed tree **across
/// a trust boundary** is exactly the T that §1250 warns about: "accepting a
/// pre-parsed expression tree from a shared library instead of parsing under
/// EL-1 itself" turns a recomputed value into a transmitted one.
pub fn evaluate(src: &str, env: &Env) -> Result<bool, El1Error> {
    Ok(eval::eval(&parse(src)?, env))
}
