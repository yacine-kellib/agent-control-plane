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

// ------------------------------------------- §8.3.1 parameter domain (ACP-74)

/// A policy whose only clause turns on a NUMERIC parameter, so the grade is a
/// direct readout of how that parameter was typed.
fn port_risks() -> RiskFunctions {
    risks(
        r#"{"schema_version":"1","risk_functions":[
            {"applies_to":"modify_firewall_rule","base":"MEDIUM","raise_to":[
                {"if":"port >= 22","then":"HIGH"}]}]}"#,
    )
}

fn port_policy<'a>(
    f: &'a Floors,
    rf: &'a RiskFunctions,
    rv: &'a ReversibilityTable,
    nt: &'a NoticeTargets,
    ad: &'a BTreeMap<String, String>,
) -> Policy<'a> {
    Policy { floors: f, risk_functions: rf, reversibility: rv, notice_targets: nt, adapters: ad }
}

/// ACP-74: the same number, spelled as a float, must not buy a lower grade.
///
/// The integer arm is a **control**, not decoration. The whole content of this
/// test is the difference between two spellings of one number, so if `22` ever
/// stops grading HIGH the test must fail loudly rather than pass on the float
/// alone — which is exactly what the first Z1 witness did by choosing an
/// assignment under which both readings agree.
///
/// In the reference this was an executed action with no attestations: `22`
/// graded HIGH and was refused for want of a two-person quorum, `22.0` graded
/// MEDIUM and ran. Here the float never becomes a `ParamValue` at all.
#[test]
fn acp74_a_float_parameter_is_refused_and_the_integer_spelling_grades_high() {
    let f = floors(r#"{"schema_version":"1","floors":{"fw":"T0"}}"#);
    let rf = port_risks();
    let rv = revs(r#"{"schema_version":"1","reversibility":{}}"#);
    let nt = notices(r#"{"schema_version":"1","notice_targets":{}}"#);
    let ad = adapters();
    let pol = port_policy(&f, &rf, &rv, &nt, &ad);

    // CONTROL: the integer spelling reaches the clause and raises the grade.
    let as_int = proposal(
        r#"{"task_type":"modify_firewall_rule","targets":["fw"],
            "schema_id":"sch-1","params":{"port":22}}"#,
    );
    assert_eq!(
        grade_floor_risk(&as_int, &pol),
        Ok(Risk::High),
        "control failed: the integer spelling no longer reaches the clause, so \
         this test is not measuring the float"
    );

    // THE DEFECT: the same number, written the other way.
    let as_float = serde_json::from_str::<Proposal>(
        r#"{"task_type":"modify_firewall_rule","targets":["fw"],
            "schema_id":"sch-1","params":{"port":22.0}}"#,
    );
    assert!(
        as_float.is_err(),
        "22.0 is the same number as 22 and must never be accepted as a \
         differently-typed value that no numeric clause can compare against"
    );
}

/// The refusal must NAME the clause, because the differential compares which
/// rule fired and "data did not match any variant" names nothing.
#[test]
fn the_domain_refusal_names_its_clause() {
    let err = serde_json::from_str::<Proposal>(
        r#"{"task_type":"t","schema_id":"sch-1","params":{"x":1.5}}"#,
    )
    .expect_err("1.5 is outside the domain");
    assert!(
        err.to_string().contains(acp_decision::PARAM_DOMAIN_CLAUSE),
        "the refusal must carry §8.3.1, got: {err}"
    );
}

/// Every other shape outside the domain, one arm at a time.
///
/// `true` is the one worth naming: `isinstance(True, int)` is `True` in Python,
/// so a JSON `true` used to bind as a number there and compare equal to `1`.
/// Accepting it here as a string instead would give `flag == 1` two meanings.
#[test]
fn bool_null_array_and_object_parameters_are_all_refused() {
    for bad in [
        r#"{"port":true}"#,
        r#"{"port":null}"#,
        r#"{"port":[22]}"#,
        r#"{"port":{"n":22}}"#,
    ] {
        let doc = format!(r#"{{"task_type":"t","schema_id":"sch-1","params":{bad}}}"#);
        assert!(
            serde_json::from_str::<Proposal>(&doc).is_err(),
            "accepted a parameter outside the §8.3.1 domain: {bad}"
        );
    }
}

/// The width boundary, both sides of it.
///
/// Without the lower row this test is satisfied by an implementation that
/// refuses every large integer and passes by being uniformly broken — the same
/// control the EL-1 differential's pinned `i64::MAX` row exists to supply.
#[test]
fn i64_max_parses_and_one_past_it_is_refused() {
    let ok = serde_json::from_str::<Proposal>(
        r#"{"task_type":"t","schema_id":"sch-1","params":{"n":9223372036854775807}}"#,
    );
    assert!(ok.is_ok(), "i64::MAX is representable and must parse");

    let over = serde_json::from_str::<Proposal>(
        r#"{"task_type":"t","schema_id":"sch-1","params":{"n":9223372036854775808}}"#,
    );
    assert!(
        over.is_err(),
        "an integer past i64::MAX must refuse, never wrap: a wrapped threshold \
         compares SMALLER than the policy author wrote"
    );
}
