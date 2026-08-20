//! Evaluation of a parsed EL-1 tree.
//!
//! # This is not a dynamic `eval`
//!
//! Stated plainly because the name invites the wrong reading. Nothing here
//! executes host-language code, resolves callables, or reaches outside the
//! environment it is handed. EL-1 has no functions, no assignment, no
//! indirection and no escape hatch: the whole language is comparisons, set
//! membership, one CIDR predicate, and two boolean connectives. This *is* the
//! "safe expression parser" that the advice against `eval` recommends
//! reaching for. The only inputs are a tree parsed from a **signed** bundle
//! and an environment the caller builds from a canonical proposal.
//!
//! # Totality (§8.3.1)
//!
//! Every function here returns `bool`. There is no `Result`, deliberately:
//! an error path at evaluation time is a path that can fall open, and the
//! specification closes that by defining every awkward case as `false`.
//!
//! - absent field ⇒ `false`
//! - type mismatch ⇒ `false`
//! - `.prefixlen` on a non-CIDR value ⇒ `false`
//!
//! **Evaluation order MUST NOT affect the result** (§8.3.1). Short-circuit is
//! permitted and used below; it is safe precisely because no operand can have
//! an effect or raise.

use crate::parse::{CmpOp, Expr, Operand};
use crate::Value;
use std::collections::HashMap;

/// The evaluation environment: field name to value.
///
/// Built by the caller from the canonical proposal and the **signed** bundle —
/// never from a receipt. TR-8: the recomputed grade is what every downstream
/// attestation requirement keys on, so an environment populated from a
/// transmitted risk value would reintroduce X1 (a forged risk suppressing
/// attestation) one layer down.
pub type Env = HashMap<String, Value>;

/// Resolve an operand against the environment.
///
/// A `Ref` naming no field yields [`Value::Absent`] rather than an error —
/// §8.3.1 field resolution, and the reason evaluation is total.
fn resolve(op: &Operand, env: &Env) -> Value {
    match op {
        Operand::Lit(v) => v.clone(),
        Operand::Ref(name) => env.get(name).cloned().unwrap_or(Value::Absent),
    }
}

/// Order two values of the *same* type.
///
/// Returns `None` for a type mismatch or an absent side, which every caller
/// turns into `false`. Tiers order as ordinals (`T0 < T1 < T2 < T3`), which is
/// the ordering the schema declares via `x-acp-ordered`; strings order
/// lexicographically, matching Python's `<` on `str`.
///
/// `Cidr` is deliberately absent from this match. A prefix length is not a
/// magnitude to compare with `<`; the only thing §8.3.1 permits on it is
/// `.prefixlen <= n`, handled separately. Admitting it here would let
/// `net < 24` mean something, and it means nothing.
fn compare(l: &Value, r: &Value) -> Option<std::cmp::Ordering> {
    match (l, r) {
        (Value::Str(a), Value::Str(b)) => Some(a.cmp(b)),
        (Value::Num(a), Value::Num(b)) => Some(a.cmp(b)),
        (Value::Tier(a), Value::Tier(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

pub fn eval(e: &Expr, env: &Env) -> bool {
    match e {
        Expr::And(a, b) => eval(a, env) && eval(b, env),
        Expr::Or(a, b) => eval(a, env) || eval(b, env),

        Expr::In(lhs, items) => {
            let a = resolve(lhs, env);
            // An absent left-hand side is false BEFORE the membership test, not
            // via it. Without this, `Absent` would be compared against each
            // element and could match another absent reference in the set --
            // "this unknown field equals that unknown field" reading as true.
            // (in-absent-lhs mutation target: delete this line and the
            // absent-vs-absent membership case starts passing.)
            if a == Value::Absent {
                return false;
            }
            // Membership is equality BY VALUE, which for tagged values means
            // the tags must match too: 'T2' (a string) is not T2 (a tier).
            items.iter().any(|x| resolve(x, env) == a)
        }

        Expr::PrefixLen(field, rhs) => {
            // Only a CIDR-typed environment value answers this. Anything else
            // -- a string, a number, an absent field -- is false. §8.3.1's
            // static constraint says `.prefixlen` is valid only on CIDR fields;
            // at run time an ill-typed bundle must fail closed rather than
            // find some other interpretation.
            let Some(Value::Cidr(len)) = env.get(field) else {
                return false;
            };
            match resolve(rhs, env) {
                Value::Num(n) => i64::from(*len) <= n,
                _ => false,
            }
        }

        Expr::Cmp(op, l, r) => {
            let (l, r) = (resolve(l, env), resolve(r, env));
            // Equality and inequality go through the same ordering as the
            // relational operators rather than using `==` on Value directly.
            // The distinction shows on a type mismatch: `Value::Str("1") ==
            // Value::Num(1)` is false, so `!=` on it would be TRUE if derived
            // from `==`. §8.3.1 says type mismatch ⇒ false for the comparison,
            // and that must hold for `!=` as well -- otherwise a mistyped rule
            // silently satisfies every `!=` clause in a bundle, which raises
            // risk on a policy the author never wrote.
            // (cmp-mismatch-false mutation target: return `l != r` here and the
            // type-mismatch `!=` case starts passing.)
            let Some(ord) = compare(&l, &r) else {
                return false;
            };
            match op {
                CmpOp::Eq => ord.is_eq(),
                CmpOp::Ne => ord.is_ne(),
                CmpOp::Lt => ord.is_lt(),
                CmpOp::Le => ord.is_le(),
                CmpOp::Gt => ord.is_gt(),
                CmpOp::Ge => ord.is_ge(),
            }
        }
    }
}
