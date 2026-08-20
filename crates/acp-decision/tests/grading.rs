//! §8.4 grading: the four absent-rules, RK-3 monotonicity, and DR-13.
//!
//! Every test here pairs a rule with a case that **reads** it. A test that
//! only asserts a lookup returns `T3` proves the accessor, not the control —
//! and this repository has already published a fail-safe default that set a
//! value nothing on its path read (RV-1 before DR-13 gave it effect in
//! v1.3.15). The question a test must answer is *which outcome changes*.

use std::collections::BTreeMap;

use acp_core::generated::{
    Floors, NoticeTargets, Reversibility, Risk, RiskFunctions, ReversibilityTable,
};
use acp_decision::{grade_floor_risk, notice_recipients, recompute_reversibility, Policy, Proposal};

// ------------------------------------------------------------------ fixtures

fn floors(json: &str) -> Floors {
    serde_json::from_str(json).expect("floors fixture")
}
fn risks(json: &str) -> RiskFunctions {
    serde_json::from_str(json).expect("risk_functions fixture")
}
fn revs(json: &str) -> ReversibilityTable {
    serde_json::from_str(json).expect("reversibility fixture")
}
fn notices(json: &str) -> NoticeTargets {
    serde_json::from_str(json).expect("notice_targets fixture")
}
fn adapters() -> BTreeMap<String, String> {
    BTreeMap::from([("sch-1".to_string(), "STRUCTURED".to_string())])
}

fn proposal(json: &str) -> Proposal {
    serde_json::from_str(json).expect("proposal fixture")
}

/// A policy whose only risk function raises to HIGH when the aggregate target
/// tier is at least T2. Everything in this file turns on that one clause, so
/// the grade is a direct readout of what the floors lookup returned.
fn default_risks() -> RiskFunctions {
    risks(
        r#"{"schema_version":"1","risk_functions":[
            {"applies_to":"send_mail","base":"LOW","raise_to":[
                {"if":"resource.effective_tier >= T2","then":"HIGH"}]}]}"#,
    )
}

// ------------------------------------------------------- RK-1, actually read

/// RK-1: a resource absent from `floors` is `T3`, and the grade shows it.
///
/// The two proposals differ only in whether the target is listed. If the
/// absent rule returned `T0`, both would grade LOW and this test would still
/// pass on the listed one — which is why both are asserted.
#[test]
fn rk1_an_unlisted_resource_is_t3_and_that_raises_the_grade() {
    let f = floors(r#"{"schema_version":"1","floors":{"inbox":"T0"}}"#);
    let rf = default_risks();
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{}}"#);
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };

    let listed = proposal(r#"{"task_type":"send_mail","targets":["inbox"],"schema_id":"sch-1"}"#);
    assert_eq!(
        grade_floor_risk(&listed, &pol),
        Ok(Risk::Low),
        "a T0 target must not trip the >= T2 clause"
    );

    let unlisted =
        proposal(r#"{"task_type":"send_mail","targets":["nowhere"],"schema_id":"sch-1"}"#);
    assert_eq!(
        grade_floor_risk(&unlisted, &pol),
        Ok(Risk::High),
        "an unlisted resource is T3 (RK-1), which trips the clause"
    );
}

/// The empty-targets case: the aggregate tier defaults to **T3**.
///
/// Python spells it `max(..., default=TIER["T3"])`. Rust's `.max()` on an
/// empty iterator is `None`, and both obvious repairs are wrong:
/// `unwrap_or(T0)` grades a target-less proposal as the least sensitive thing
/// in the deployment, and omitting the binding makes every clause mentioning
/// it `false` under totality — which for a `raise_to` is the permissive
/// direction, because a clause that cannot fire cannot raise.
#[test]
fn an_empty_target_list_aggregates_to_t3_not_t0_and_not_absent() {
    let f = floors(r#"{"schema_version":"1","floors":{"inbox":"T0"}}"#);
    let rf = default_risks();
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{}}"#);
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };

    let none = proposal(r#"{"task_type":"send_mail","targets":[],"schema_id":"sch-1"}"#);
    assert_eq!(
        grade_floor_risk(&none, &pol),
        Ok(Risk::High),
        "no targets must aggregate to T3, so the >= T2 clause fires"
    );
}

// ------------------------------------------------------------------- 8.4-3

/// An action with no risk function is REFUSED, not graded HIGH.
///
/// The assertion is on the **clause id**, not merely on "it failed". Refusing
/// for the wrong stated reason is what the Python↔Rust differential is built
/// to catch, and a test that accepts any error cannot see it.
#[test]
fn an_action_with_no_risk_function_is_refused_under_8_4_3_not_graded_high() {
    let f = floors(r#"{"schema_version":"1","floors":{}}"#);
    let rf = default_risks();
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{}}"#);
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };

    let p = proposal(r#"{"task_type":"delete_everything","schema_id":"sch-1"}"#);
    let err = grade_floor_risk(&p, &pol).expect_err("must refuse");
    assert_eq!(err.clause, "8.4-3");
    assert_ne!(
        grade_floor_risk(&p, &pol).ok(),
        Some(Risk::High),
        "grading HIGH would route an unknown action into the human quorum (T-26, AT-7)"
    );
}

// --------------------------------------------------------------------- RK-3

/// The fold is a monotone `max`: a later, lower clause cannot lower the grade.
///
/// Without `max`, the second clause below would overwrite HIGH with LOW and a
/// policy author could walk a grade down by appending — the "lowering clause"
/// the generated `RiskFunction` doc says the type deliberately cannot express.
#[test]
fn rk3_a_later_lower_clause_cannot_lower_the_grade() {
    let f = floors(r#"{"schema_version":"1","floors":{"inbox":"T3"}}"#);
    let rf = risks(
        r#"{"schema_version":"1","risk_functions":[
            {"applies_to":"send_mail","base":"LOW","raise_to":[
                {"if":"resource.effective_tier >= T2","then":"HIGH"},
                {"if":"resource.effective_tier >= T0","then":"LOW"}]}]}"#,
    );
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{}}"#);
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };

    let p = proposal(r#"{"task_type":"send_mail","targets":["inbox"],"schema_id":"sch-1"}"#);
    assert_eq!(
        grade_floor_risk(&p, &pol),
        Ok(Risk::High),
        "the second clause fires too, and must not lower HIGH to LOW"
    );
}

/// A `raise_to` clause that does not parse REFUSES; it is never skipped.
///
/// Skipping is the permissive direction: a malformed `if` in signed policy
/// would silently stop being able to raise, and the grade would settle at
/// whatever the remaining clauses allow.
#[test]
fn a_malformed_raise_clause_refuses_rather_than_being_skipped() {
    let f = floors(r#"{"schema_version":"1","floors":{}}"#);
    let rf = risks(
        r#"{"schema_version":"1","risk_functions":[
            {"applies_to":"send_mail","base":"LOW","raise_to":[
                {"if":"resource.effective_tier ~~ T2","then":"HIGH"}]}]}"#,
    );
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{}}"#);
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };

    let p = proposal(r#"{"task_type":"send_mail","schema_id":"sch-1"}"#);
    let err = grade_floor_risk(&p, &pol).expect_err("a malformed clause must refuse");
    assert_eq!(err.clause, "8.3.1", "the EL-1 clause id is surfaced unchanged");
}

// --------------------------------------------------------------------- TR-8

#[test]
fn an_unregistered_schema_id_is_refused_under_tr8() {
    let f = floors(r#"{"schema_version":"1","floors":{}}"#);
    let rf = default_risks();
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{}}"#);
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };

    let p = proposal(r#"{"task_type":"send_mail","schema_id":"unregistered"}"#);
    assert_eq!(grade_floor_risk(&p, &pol).unwrap_err().clause, "TR-8");

    let missing = proposal(r#"{"task_type":"send_mail"}"#);
    assert_eq!(
        grade_floor_risk(&missing, &pol).unwrap_err().clause,
        "TR-8",
        "an absent schema_id is not a registered one"
    );
}

// --------------------------------------------------------------- RV-1, DR-13

#[test]
fn rv1_an_unclassified_action_is_irreversible() {
    let f = floors(r#"{"schema_version":"1","floors":{}}"#);
    let rf = default_risks();
    let rv = revs(r#"{"schema_version":"1","reversibility":{"archive":"REVERSIBLE"}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{}}"#);
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };

    assert_eq!(
        recompute_reversibility(&proposal(r#"{"task_type":"archive"}"#), &pol),
        Reversibility::Reversible
    );
    assert_eq!(
        recompute_reversibility(&proposal(r#"{"task_type":"unheard_of"}"#), &pol),
        Reversibility::Irreversible,
        "RV-1: an action nobody classified is one nobody thought about"
    );
}

/// DR-13, all four arms — including the two that must NOT demand a notice.
///
/// The `HIGH` and `REVERSIBLE` arms are what stop this from being a test that
/// passes by refusing everything.
#[test]
fn dr13_demands_a_named_recipient_below_high_and_only_there() {
    let f = floors(r#"{"schema_version":"1","floors":{}}"#);
    let rf = default_risks();
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(
        r#"{"schema_version":"1","notice_targets":{"send_mail":["secops@example.test"]}}"#,
    );
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };
    let p = proposal(r#"{"task_type":"send_mail","schema_id":"sch-1"}"#);

    // Owed, and named.
    let got = notice_recipients(&p, &pol, Risk::Low, Reversibility::Irreversible)
        .expect("recipients are named");
    assert_eq!(got.map(|v| v.len()), Some(1));

    // Not owed at floor-HIGH: DR-1's gate already applies there.
    assert_eq!(
        notice_recipients(&p, &pol, Risk::High, Reversibility::Irreversible),
        Ok(None)
    );

    // Not owed for a REVERSIBLE action.
    assert_eq!(
        notice_recipients(&p, &pol, Risk::Low, Reversibility::Reversible),
        Ok(None)
    );

    // Owed, and nobody named: refuse.
    let unnamed = proposal(r#"{"task_type":"wire_transfer","schema_id":"sch-1"}"#);
    let err = notice_recipients(&unnamed, &pol, Risk::Low, Reversibility::Irreversible)
        .expect_err("a notice with no addressee is not a detection channel");
    assert_eq!(err.clause, "DR-13");
}

/// An entry that exists but is EMPTY refuses too.
///
/// The generated accessor only refuses on an absent key, so this arm is the
/// one a Rust implementation can get wrong while looking correct: `Ok(&[])`
/// is a successful lookup returning nobody. Python spells both as
/// `.get(...) or []` followed by `if not targets`.
#[test]
fn dr13_an_empty_recipient_list_refuses_as_surely_as_an_absent_one() {
    let f = floors(r#"{"schema_version":"1","floors":{}}"#);
    let rf = default_risks();
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{"send_mail":[]}}"#);
    let ad = adapters();
    let pol = Policy {
        floors: &f,
        risk_functions: &rf,
        reversibility: &rv,
        notice_targets: &nt,
        adapters: &ad,
    };

    let p = proposal(r#"{"task_type":"send_mail","schema_id":"sch-1"}"#);
    let err = notice_recipients(&p, &pol, Risk::Low, Reversibility::Irreversible)
        .expect_err("an empty recipient list is not a detection channel either");
    assert_eq!(err.clause, "DR-13");
    assert!(err.message.contains("empty"), "the refusal must distinguish empty from absent");
}
