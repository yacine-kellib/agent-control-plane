//! EL-1 conformance: precedence on SOURCE TEXT, and totality.
//!
//! §1246 makes this its own obligation, separate from evaluation: *"Because
//! Annex B quantifies over parsed `Expr` values, the parser is outside the
//! proof TCB and MUST be tested separately: the suite MUST include
//! mixed-connective **source-text** vectors asserting EL-1 precedence and
//! associativity, and MUST be run against the deployment's own parser, not
//! only its evaluator. A deployment whose parser disagrees with EL-1 on any
//! vector is non-conformant."*
//!
//! So the precedence tests below assert the **tree**, not just the truth
//! value. Asserting only the value would let a wrong tree pass whenever the
//! two readings happen to agree — and they agree on 95.1% of mixed
//! expressions, which is exactly how Z1 survived to v1.3.3.

use acp_el1::{evaluate, parse, Env, Value};

fn env(pairs: &[(&str, Value)]) -> Env {
    pairs.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect()
}

fn s(v: &str) -> Value {
    Value::Str(v.to_string())
}

// ---------------------------------------------------------------- Z1 itself

/// The minimal witness from the v1.3.4 alert, on source text.
///
/// ```text
/// action != 'deny' || action == 'allow' && action == 'allow'
/// ```
///
/// Writing `a = action != 'deny'` and `b = c = action == 'allow'`:
///
/// | `action`  | flat `((a||b) && c)` | EL-1 `(a || (b && c))` |
/// | --------- | -------------------- | ---------------------- |
/// | `'allow'` | true                 | true                   |
/// | `'deny'`  | false                | false                  |
/// | `'read'`  | **false**            | **true**               |
///
/// **Only the third row detects Z1**, and getting that wrong is the lesson.
/// The first version of this test used `'allow'`, asserted `true`, passed, and
/// read as a Z1 regression detector -- while SURVIVING a mutant that collapsed
/// the parser back to the flat v1.3.3 production. It was caught by running
/// that mutant, not by review.
///
/// This is the 4.9% in miniature: two of the three assignments agree, so a
/// witness chosen without checking which one separates the readings usually
/// lands on "passes for the wrong reason".
#[test]
fn z1_minimal_witness_evaluates_under_el1_precedence() {
    let src = "action != 'deny' || action == 'allow' && action == 'allow'";

    // The distinguishing assignment: neither 'deny' nor 'allow'.
    let e = env(&[("action", s("read"))]);
    assert_eq!(
        evaluate(src, &e),
        Ok(true),
        "EL-1 requires (a || (b && c)) = true here; the flat v1.3.3 fold yields false"
    );

    // The assignments where both readings AGREE. Controls, not evidence: they
    // must hold, and they prove nothing about precedence.
    for (action, expected) in [("allow", true), ("deny", false)] {
        let e = env(&[("action", s(action))]);
        assert_eq!(evaluate(src, &e), Ok(expected), "control case {action:?}");
    }
}

// ------------------------------------------------- precedence, as TREE shape

/// `&&` binds tighter than `||`, asserted structurally.
#[test]
fn and_binds_tighter_than_or_in_the_parse_tree() {
    let mixed = parse("a == 'x' || b == 'y' && c == 'z'").unwrap();
    let explicit = parse("a == 'x' || (b == 'y' && c == 'z')").unwrap();
    let wrong = parse("(a == 'x' || b == 'y') && c == 'z'").unwrap();

    assert_eq!(mixed, explicit, "&& must bind tighter than ||");
    assert_ne!(
        mixed, wrong,
        "the flat v1.3.3 reading must NOT be what this parser produces"
    );
}

/// Both connectives are left-associative, asserted structurally.
///
/// `||` and `&&` are associative, so no truth value can distinguish these
/// trees. Only the tree can — which is why §1246 puts the obligation on the
/// parser rather than on evaluation results.
#[test]
fn both_connectives_are_left_associative_in_the_parse_tree() {
    assert_eq!(
        parse("a == '1' || b == '2' || c == '3'").unwrap(),
        parse("(a == '1' || b == '2') || c == '3'").unwrap(),
        "|| is left-associative"
    );
    assert_ne!(
        parse("a == '1' || b == '2' || c == '3'").unwrap(),
        parse("a == '1' || (b == '2' || c == '3')").unwrap(),
        "|| must not be RIGHT-associative"
    );
    assert_eq!(
        parse("a == '1' && b == '2' && c == '3'").unwrap(),
        parse("(a == '1' && b == '2') && c == '3'").unwrap(),
        "&& is left-associative"
    );
}

// ------------------------------------------------------------------ totality

/// Absent field ⇒ false, for every comparison operator.
///
/// Including `!=`, which is the one that would read "true" under a naive
/// implementation: an absent field is not equal to `'x'`, so `!=` looks like
/// it should hold. §8.3.1 says otherwise, and it matters — a `raise_to` clause
/// keyed on `!=` would fire for every proposal that omits the field, raising
/// risk on a policy nobody wrote.
#[test]
fn an_absent_field_is_false_under_every_operator() {
    let e = env(&[]);
    for op in ["==", "!=", "<", "<=", ">", ">="] {
        let src = format!("missing {op} 'x'");
        assert_eq!(evaluate(&src, &e), Ok(false), "absent must be false for {op}");
    }
}

/// Type mismatch ⇒ false, `!=` included.
#[test]
fn a_type_mismatch_is_false_including_for_ne() {
    let e = env(&[("n", Value::Num(1)), ("t", Value::Tier(2))]);
    assert_eq!(evaluate("n == '1'", &e), Ok(false));
    assert_eq!(
        evaluate("n != '1'", &e),
        Ok(false),
        "a mistyped != must not silently satisfy every clause in a bundle"
    );
    assert_eq!(evaluate("t == 'T2'", &e), Ok(false), "'T2' is a string, T2 is a tier");
    assert_eq!(evaluate("t == T2", &e), Ok(true));
}

/// Tiers order as ordinals, and only against other tiers.
#[test]
fn tiers_are_ordered_and_only_comparable_with_tiers() {
    let e = env(&[("r", Value::Tier(2))]);
    assert_eq!(evaluate("r >= T2", &e), Ok(true));
    assert_eq!(evaluate("r > T1", &e), Ok(true));
    assert_eq!(evaluate("r > T3", &e), Ok(false));
    assert_eq!(evaluate("r >= 2", &e), Ok(false), "a tier is not a number");
}

// -------------------------------------------------------- set membership, CIDR

#[test]
fn set_membership_is_equality_by_value_and_tag() {
    let e = env(&[("a", s("read")), ("t", Value::Tier(1))]);
    assert_eq!(evaluate("a in ['read', 'write']", &e), Ok(true));
    assert_eq!(evaluate("a in ['write']", &e), Ok(false));
    assert_eq!(evaluate("t in [T1, T2]", &e), Ok(true));
    assert_eq!(evaluate("t in ['T1']", &e), Ok(false), "tag must match, not just spelling");
}

/// An absent left-hand side is false BEFORE the membership test.
///
/// The in-absent-lhs mutation target. Without the early return, `Absent` would
/// be compared against each element, and a set containing another unresolved
/// reference would match — "this unknown field equals that unknown field"
/// reading as true.
#[test]
fn absent_lhs_is_false_even_when_the_set_holds_absent_references() {
    let e = env(&[]);
    assert_eq!(evaluate("missing in [alsomissing]", &e), Ok(false));
}

#[test]
fn prefixlen_reads_only_cidr_values() {
    let e = env(&[("net", Value::Cidr(24)), ("name", s("x"))]);
    assert_eq!(evaluate("net.prefixlen <= 24", &e), Ok(true));
    assert_eq!(evaluate("net.prefixlen <= 23", &e), Ok(false));
    assert_eq!(evaluate("name.prefixlen <= 24", &e), Ok(false), "not a CIDR");
    assert_eq!(evaluate("gone.prefixlen <= 24", &e), Ok(false), "absent");
}

// ------------------------------------------------------------- fail closed

/// Parsing fails closed, and every refusal names clause 8.3.1.
#[test]
fn malformed_source_is_refused_under_clause_8_3_1() {
    for src in [
        "a == ",            // truncated
        "a == 'x' garbage", // trailing tokens
        "(a == 'x'",        // unbalanced
        "a ~ 'x'",          // illegal character
        "a === 'x'",        // unknown operator
        "a in 'x'",         // set literal expected
        "a == 'unterminated",
    ] {
        let err = parse(src).expect_err(&format!("{src:?} must be refused"));
        assert_eq!(err.clause, "8.3.1", "refusal must name the governing clause");
    }
}

/// Evaluation itself is total: a parsed expression always answers.
///
/// The assertion is carried by the SIGNATURE -- `eval` returns `bool`, not
/// `Result<bool, _>` -- so this test is really a compile-time claim with a
/// runtime witness. It is written out because a future change to a `Result`
/// would be a silent widening of the interface into one that has an error
/// path, and §8.3.1's totality is the reason there must not be one.
#[test]
fn evaluation_has_no_error_path() {
    let e = env(&[]);
    let parsed = parse("x == 'y' && z.prefixlen <= 8 || w in ['q']").unwrap();
    let answer: bool = acp_el1::eval(&parsed, &e);
    assert!(!answer, "every atom is absent, so every branch is false");
}

/// An integer literal beyond `i64` fails CLOSED, rather than becoming a field.
///
/// Found by `tools/check-el1-differential.py` probing the boundary. The token
/// used to fall through to `Operand::Ref`, resolve absent, and evaluate
/// `false` -- so `count < <huge>` did not fire here while it did in Python,
/// making the recomputed grade LOWER in Rust. Silent, and in the permissive
/// direction, inside the fold that decides whether a human is needed.
///
/// The boundary is asserted on both sides of itself: `i64::MAX` must still
/// parse. Without that row this test is satisfied by a parser that refuses
/// every large number, which passes by being uniformly broken.
#[test]
fn an_integer_literal_beyond_i64_is_refused_not_treated_as_a_field() {
    let e = env(&[("count", Value::Num(5))]);

    assert_eq!(
        evaluate("count < 9223372036854775807", &e),
        Ok(true),
        "i64::MAX must still parse as a number"
    );

    for lit in ["9223372036854775808", "99999999999999999999"] {
        let err = parse(&format!("count < {lit}"))
            .expect_err("an out-of-range integer literal must be refused");
        assert_eq!(err.clause, "8.3.1");
        assert!(
            err.message.contains("representable range"),
            "the refusal must say why, got {:?}",
            err.message
        );
    }
}
