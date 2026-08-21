//! §9.3 composed — the stateless checklist, driven with REAL hybrid signatures.
//!
//! `tools/check-decision-differential.py` proves this module agrees with the
//! reference on 34 conformance cases. It cannot run in `cargo test` (it needs
//! Python), and **the mutants run under `cargo test`** — so a check whose only
//! evidence is the differential is a check no mutant can kill. These tests are
//! that evidence, and each one names the mutant it exists to kill.
//!
//! Every test signs. Slice 4's lesson, applied from the start: every check past
//! step 2 sits behind signature verification, so a test that never produces a
//! valid signature can only assert the refusal it stops at first.
//!
//! **The control is [`a_well_formed_receipt_passes_the_checklist`].** Without
//! it every refusal assertion below is satisfied by a `decide` that refuses
//! everything — the uniformly-broken trap the EL-1 differential already had to
//! guard against.

use std::collections::BTreeMap;

use acp_core::generated::{Floors, NoticeTargets, ReversibilityTable, RiskFunctions, SuiteId};
use acp_crypto::{CustodyTier, Environment, KeyMaterial, OfflineSigner, Signer, Suite};
use acp_decision::decide::{decide, BundleView};
use acp_decision::quorum::{attestation_id, AttesterKey};
use acp_decision::receipt::ReceiptKey;
use acp_decision::{Policy, Proposal, Refusal};
use serde_json::{json, Value};

const OP: &str = "op_8842";
const A1: &str = "op_1121";
const A2: &str = "op_3307";
const KMS: &str = "kms";
const BUNDLE_HASH: &str = "sha256:bundle";
const EPOCH: u64 = 47;
const NOW: f64 = 1000.0;

/// Distinct seeds. PB-7 makes a shared seed an INVALID bundle, so the fixtures
/// have to respect a rule enforced in a different crate — see tests/quorum.rs.
fn seed_of(who: &str) -> &'static [u8] {
    match who {
        A1 => b"acp-45-slice6-attester-1",
        A2 => b"acp-45-slice6-attester-2",
        OP => b"acp-45-slice6-operator",
        KMS => b"acp-45-slice6-kms",
        _ => panic!("no seed for {who}"),
    }
}

fn signer_for(who: &str) -> OfflineSigner {
    OfflineSigner::new(
        CustodyTier::T1,
        Suite::HybridEd25519MlDsa65,
        KeyMaterial::from_seed(seed_of(who)),
    )
    .unwrap()
}

/// Sign `payload` and render it the way the wire carries it: a map from
/// primitive name to hex. This is the shape `parse_sig` must accept, and the
/// shape the three CR-2/CR-3 format attacks perturb.
fn sig_of(who: &str, payload: &[u8]) -> Value {
    let sig = signer_for(who).sign(payload, Environment::Production).unwrap();
    let mut m = serde_json::Map::new();
    for (primitive, bytes) in sig.parts() {
        let name = match primitive {
            acp_crypto::Primitive::Classical => "classical",
            acp_crypto::Primitive::Pq => "pq",
            acp_crypto::Primitive::PqSlh => "pq-slh",
        };
        m.insert(name.to_string(), Value::String(hex(bytes)));
    }
    Value::Object(m)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn wire_key(who: &str) -> AttesterKey {
    let k = KeyMaterial::from_seed(seed_of(who));
    AttesterKey { classical: k.public().classical().to_vec(), pq: k.public().pq().to_vec() }
}

fn registry() -> BTreeMap<String, AttesterKey> {
    [A1, A2, OP].into_iter().map(|w| (w.to_string(), wire_key(w))).collect()
}

fn receipt_key() -> ReceiptKey {
    let k = KeyMaterial::from_seed(seed_of(KMS));
    let mut classical = [0u8; 32];
    classical.copy_from_slice(k.public().classical());
    ReceiptKey { classical, pq: k.public().pq().to_vec() }
}

// ------------------------------------------------------------------ policy
//
// One resource at T3 and one risk function that raises on it, so the grade is
// a direct readout: `prod-db` grades HIGH and needs a quorum, `sandbox` grades
// LOW and does not. Both paths are exercised, because a checklist tested only
// at floor-HIGH leaves step 7b's `else` branch unread.

fn floors() -> Floors {
    serde_json::from_str(r#"{"schema_version":"1","floors":{"prod-db":"T3","sandbox":"T0"}}"#)
        .unwrap()
}

fn risks() -> RiskFunctions {
    serde_json::from_str(
        r#"{"schema_version":"1","risk_functions":[
            {"applies_to":"modify_firewall_rule","base":"MEDIUM","raise_to":[
                {"if":"resource.effective_tier == T3","then":"HIGH"}]}]}"#,
    )
    .unwrap()
}

fn revs() -> ReversibilityTable {
    serde_json::from_str(
        r#"{"schema_version":"1","reversibility":{"modify_firewall_rule":"IRREVERSIBLE"}}"#,
    )
    .unwrap()
}

fn notices() -> NoticeTargets {
    serde_json::from_str(
        r#"{"schema_version":"1","notice_targets":{"modify_firewall_rule":["secops_oncall"]}}"#,
    )
    .unwrap()
}

fn adapters() -> BTreeMap<String, String> {
    [("fw.v1".to_string(), "F-HIGH".to_string())].into_iter().collect()
}

fn proposal(target: &str) -> Value {
    json!({
        "task_type": "modify_firewall_rule",
        "schema_id": "fw.v1",
        "tenant_id": "t1",
        "targets": [target],
        "params": {"action": "allow", "port": 22},
        "cidrs": {"source_cidr": 24}
    })
}

/// An AT-1 object bound to `phash`. Eleven fields exactly (AT-8b).
fn att_obj(phash: &str, nonce: &str) -> Value {
    json!({
        "alg": "hybrid-ed25519-mldsa65",
        "att_nonce": nonce,
        "bundle_epoch": EPOCH,
        "context_snapshot_hash": "sha256:ctx",
        "expires_at": NOW + 600.0,
        "floor_only_risk": "HIGH",
        "operator": OP,
        "policy_bundle_hash": BUNDLE_HASH,
        "proposal_hash": phash,
        "required_count": 2,
        "required_roles": ["net_approver"]
    })
}

fn att_entry(who: &str, obj: Value, kind: &str) -> Value {
    // The reference signs the DERIVED id, not the object bytes. Signing the
    // bytes would verify here and diverge from Python on every case.
    let aid = attestation_id(&obj).unwrap();
    json!({"obj": obj, "kind": kind, "attester": who, "sig": sig_of(who, aid.as_bytes())})
}

fn quorum_for(phash: &str) -> Value {
    json!([
        att_entry(A1, att_obj(phash, "n1"), "approval"),
        att_entry(A2, att_obj(phash, "n2"), "approval"),
        att_entry(OP, att_obj(phash, "n3"), "confirmation"),
    ])
}

/// A well-formed receipt over `proposal`, with `over` applied to the body
/// BEFORE signing — so a perturbed field is genuinely signed and the test is
/// exercising the check rather than an accidental signature failure.
fn receipt(proposal: &Value, over: Value) -> Value {
    let phash = attestation_id(proposal).unwrap();
    let high = proposal["targets"][0] == "prod-db";
    let mut body = json!({
        "alg": "hybrid-ed25519-mldsa65",
        "decision": "ALLOW",
        "proposal_hash": phash,
        "policy_bundle_hash": BUNDLE_HASH,
        "bundle_epoch": EPOCH,
        "issued_at": NOW,
        "expires_at": NOW + 60.0,
        "nonce": "nonce-1",
        "tenant_id": "t1",
        "operator": OP,
        "attestations": if high { quorum_for(&phash) } else { json!([]) }
    });
    for (k, v) in over.as_object().unwrap() {
        if v.is_null() {
            body.as_object_mut().unwrap().remove(k);
        } else {
            body[k] = v.clone();
        }
    }
    let bytes = acp_decision::receipt::canon(&body).unwrap();
    let sig = sig_of(KMS, &bytes);
    body["sig"] = sig;
    body
}

struct Held {
    floors: Floors,
    risks: RiskFunctions,
    revs: ReversibilityTable,
    notices: NoticeTargets,
    adapters: BTreeMap<String, String>,
    attesters: BTreeMap<String, AttesterKey>,
    receipt_key: ReceiptKey,
}

fn held() -> Held {
    Held {
        floors: floors(),
        risks: risks(),
        revs: revs(),
        notices: notices(),
        adapters: adapters(),
        attesters: registry(),
        receipt_key: receipt_key(),
    }
}

/// Run the checklist. `bundle_hash` is a parameter so step 4 can be exercised
/// against a verifier holding a DIFFERENT bundle, which is the only honest way
/// to test that comparison — perturbing the receipt's copy would test the
/// receipt, not the binding.
fn run_with(h: &Held, receipt: &Value, proposal: &Value, bundle_hash: &str) -> Result<acp_decision::Outcome, Refusal> {
    let policy = Policy {
        floors: &h.floors,
        risk_functions: &h.risks,
        reversibility: &h.revs,
        notice_targets: &h.notices,
        adapters: &h.adapters,
    };
    let view = BundleView {
        epoch: EPOCH,
        quorum_k: 2,
        min_suite: SuiteId::HybridEd25519Mldsa65,
        policy_bundle_hash: bundle_hash,
        policy: &policy,
        attesters: &h.attesters,
        receipt_key: &h.receipt_key,
    };
    let typed: Proposal = serde_json::from_value(proposal.clone()).expect("proposal fixture");
    decide(receipt, proposal, &typed, &view, NOW)
}

fn run(h: &Held, receipt: &Value, proposal: &Value) -> Result<acp_decision::Outcome, Refusal> {
    run_with(h, receipt, proposal, BUNDLE_HASH)
}

// ================================================================= CONTROLS

/// THE CONTROL. Without it every refusal below is satisfied by a checklist
/// that refuses everything.
#[test]
fn a_well_formed_receipt_passes_the_checklist() {
    let h = held();
    let p = proposal("prod-db");
    let out = run(&h, &receipt(&p, json!({})), &p).expect("the honest floor-HIGH path must pass");
    assert_eq!(out.risk, acp_core::generated::Risk::High);
    // The operator comes from the VERIFIED attestations at floor-HIGH (Y4),
    // not from the receipt body. Asserted, because the two agree on this input
    // and only this assertion says which one was read.
    assert_eq!(out.operator, OP);
    assert!(out.deferred, "DR-1 scopes the gate to floor-HIGH");
}

/// The second control: the below-HIGH path must also pass, or step 7b's `else`
/// branch and the DR-13 notice are never reached by any test here.
#[test]
fn a_well_formed_below_high_receipt_passes_and_owes_a_notice() {
    let h = held();
    let p = proposal("sandbox");
    let out = run(&h, &receipt(&p, json!({})), &p).expect("the honest below-HIGH path must pass");
    assert_eq!(out.risk, acp_core::generated::Risk::Medium);
    assert!(!out.deferred);
    // DR-13: IRREVERSIBLE below floor-HIGH owes a notice, and the recipients
    // come from the signed bundle rather than from a notifier's own config.
    assert_eq!(
        out.notice_recipients.as_deref(),
        Some(&["secops_oncall".to_string()][..]),
        "an IRREVERSIBLE action below floor-HIGH must owe a notice"
    );
}

// ============================================================= step 3, B-1a

/// (kills `9.3-3-proposal-binding`)
///
/// The receipt is genuinely signed over proposal A; the verifier is handed
/// proposal B. Nothing about the receipt is malformed — the signature verifies
/// — so only the recomputed comparison stops it. That is B-1a.
#[test]
fn step3_refuses_a_receipt_bound_to_a_different_proposal() {
    let h = held();
    let signed_over = proposal("prod-db");
    let r = receipt(&signed_over, json!({}));

    let mut received = signed_over.clone();
    received["params"]["port"] = json!(3389); // a different proposal entirely

    let e = run(&h, &r, &received).unwrap_err();
    assert_eq!(e.clause, "9.3-3", "{e}");
}

// ======================================================== step 4, the basis

/// (kills `9.3-4-policy-basis`)
///
/// PB-KEY in miniature: the verifier holds a bundle whose hash differs. The
/// registry is inside that hash, so this is the comparison that stops a receipt
/// issued under a bundle trusting DIFFERENT attester keys.
#[test]
fn step4_refuses_a_receipt_issued_against_another_bundle() {
    let h = held();
    let p = proposal("prod-db");
    let r = receipt(&p, json!({}));
    let e = run_with(&h, &r, &p, "sha256:a-different-bundle").unwrap_err();
    assert_eq!(e.clause, "9.3-4", "{e}");
}

/// The epoch half of step 4, refusing under the SAME clause. Asserted
/// separately because the two are different comparisons and a mutant deleting
/// only one would otherwise be caught by the other's test.
#[test]
fn step4_refuses_a_receipt_from_another_epoch() {
    let h = held();
    let p = proposal("prod-db");
    let r = receipt(&p, json!({"bundle_epoch": EPOCH + 1}));
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "9.3-4", "{e}");
}

// ==================================================== step 5, and L-14 (Y2)

/// (kills `l14-window-ceiling`)
///
/// **This test asserts the CLAUSE, and that is the whole point.** The receipt
/// is inside its window, so deleting the L-14 ceiling does not make it
/// *refused-for-some-other-reason* — it makes it PASS. But a sloppier version
/// of this test, asserting only "refused", would be satisfied by an
/// implementation that reported `9.3-5`, telling an operator the receipt had
/// expired when the truth is that its validity window was ten times too long.
/// Y2 is an attacker widening the interval in which a stolen receipt is usable;
/// "expired" is the wrong remediation.
#[test]
fn l14_refuses_an_over_long_validity_window_under_its_own_clause() {
    let h = held();
    let p = proposal("prod-db");
    let r = receipt(&p, json!({"expires_at": NOW + 3600.0}));
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "L-14", "{e}");

    // The boundary must still pass, or this check is satisfied by an
    // implementation that refuses every window — uniformly broken, and green.
    let ok = receipt(&p, json!({"expires_at": NOW + 120.0}));
    assert!(run(&h, &ok, &p).is_ok(), "a 120s window is exactly at the ceiling and must pass");
}

#[test]
fn step5_refuses_an_expired_receipt() {
    let h = held();
    let p = proposal("prod-db");
    let r = receipt(&p, json!({"issued_at": NOW - 200.0, "expires_at": NOW - 100.0}));
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "9.3-5", "{e}");
}

// ======================================================= step 8, the tenant

/// (kills `9.3-8-tenant-scoping`)
///
/// Both sides of the comparison are things the verifier holds separately: the
/// receipt (signed by the KMS) and the Proposal (received independently). A
/// receipt minted for tenant A must not consume tenant B's Proposal.
#[test]
fn step8_refuses_a_cross_tenant_receipt() {
    let h = held();
    let p = proposal("prod-db");
    let r = receipt(&p, json!({"tenant_id": "t2"}));
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "9.3-8", "{e}");
}

// ============================================ the signature key set (CR-2/3)

/// (kills `cr3-sig-key-set`)
///
/// The suite's two primitives are GENUINE; an unexpected third is added. A
/// verifier that only checks "every declared primitive verifies" accepts this,
/// and an accepted extra primitive is an undeclared code path the attacker
/// chose (CR-3, §1123: the supplied set must EXACTLY match).
#[test]
fn cr3_refuses_an_extra_undeclared_primitive() {
    let h = held();
    let p = proposal("prod-db");
    let mut r = receipt(&p, json!({}));
    r["sig"]["experimental"] = json!("00".repeat(32));
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "9.3-1", "{e}");
}

/// CR-2: a bare scalar signature. Format leniency is a downgrade in disguise,
/// so this must refuse rather than be coerced into a single-primitive map.
#[test]
fn cr2_refuses_a_legacy_scalar_signature() {
    let h = held();
    let p = proposal("prod-db");
    let mut r = receipt(&p, json!({}));
    let classical = r["sig"]["classical"].clone();
    r["sig"] = classical;
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "9.3-1", "{e}");
}

/// CR-3 conjunctive: the post-quantum leg removed, the classical one genuine.
/// A verifier composing with OR accepts this.
#[test]
fn cr3_refuses_a_stripped_post_quantum_leg() {
    let h = held();
    let p = proposal("prod-db");
    let mut r = receipt(&p, json!({}));
    r["sig"].as_object_mut().unwrap().remove("pq");
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "9.3-1", "{e}");
}

// ================================================== TR-8 / RV-3, step 7

/// X1: a compromised issuer asserting a lower risk suppressed attestation
/// entirely. The value is recomputed and the claim COMPARED.
#[test]
fn tr8_refuses_a_receipt_claiming_a_lower_risk_than_recomputed() {
    let h = held();
    let p = proposal("prod-db");
    let r = receipt(&p, json!({"risk_level_floor_only": "LOW"}));
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "TR-8", "{e}");
}

/// RV-3 is X1 one field over: an asserted `REVERSIBLE` otherwise obtains
/// Silent mode.
#[test]
fn rv3_refuses_a_receipt_asserting_a_different_reversibility() {
    let h = held();
    let p = proposal("prod-db");
    let r = receipt(&p, json!({"reversibility": "REVERSIBLE"}));
    let e = run(&h, &r, &p).unwrap_err();
    assert_eq!(e.clause, "RV-3", "{e}");
}

// =========================================== the gaps, asserted as gaps

/// The unimplemented steps are DECLARED, and the declaration is asserted.
///
/// A gap named only in a doc comment is a gap nothing can check. This test does
/// not prove the steps are absent — it proves the list a reader is handed is
/// non-empty and names an owner for every entry, so `UNIMPLEMENTED_STEPS`
/// cannot decay into an empty tuple while the module docs still promise it.
#[test]
fn every_unimplemented_step_names_a_clause_and_an_owner() {
    let steps = acp_decision::decide::UNIMPLEMENTED_STEPS;
    assert!(!steps.is_empty(), "the module claims steps are missing; the list must say which");
    for (step, clause, why) in steps {
        assert!(!step.is_empty() && !clause.is_empty(), "{step}/{clause}");
        assert!(
            why.contains("ACP-") || why.contains("§"),
            "{step}: an unimplemented step must name the ticket or clause that owns it, got {why:?}"
        );
    }
}
