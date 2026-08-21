//! §9.3 step 7b — the AT-* quorum, driven with REAL hybrid signatures.
//!
//! Nothing here uses a stub signer. Every check past 7b(i) sits *behind*
//! signature verification, so a test that never produces a valid signature can
//! only ever assert the refusal it stops at first — the trap slice 4 hit, where
//! three mutants were unreachable until the tests started signing.
//!
//! **One seed per attester, and that is load-bearing.** PB-7 requires attester
//! verification keys to be pairwise distinct over the full hybrid identity, so
//! a fixture sharing a seed builds a registry that a conformant loader must
//! REFUSE. The distinctness rule is enforced in `acp_bundle::verify`, not here,
//! and these fixtures have to respect it or they are testing an invalid bundle.

use std::collections::BTreeMap;

use acp_core::generated::{Risk, SuiteId};
use acp_crypto::{CustodyTier, Environment, KeyMaterial, OfflineSigner, Signer, Suite};
use acp_decision::quorum::{
    attestation_id, verify_quorum, AttestationEntry, AttesterKey, DecisionBasis, QuorumPolicy,
    CLAUSE_ATTESTATION_SUITE, CLAUSE_ATTESTER_SIG, CLAUSE_BINDING, CLAUSE_CONSENT,
    CLAUSE_DERIVED_ID, CLAUSE_NO_ATTESTATIONS, CLAUSE_OBJECT_SCHEMA, CLAUSE_OPERATOR_SELF,
    CLAUSE_NONCE_SIZE, CLAUSE_POLICY_BASIS, CLAUSE_QUORUM, CLAUSE_WIRE_TYPE,
};
use acp_decision::quorum::{is_we4_b64, AT1_NONCE_LEN};
use acp_decision::receipt::SignaturePart;
use serde_json::{json, Value};

mod common;

const OP: &str = "op_8842";
const A1: &str = "op_1121";
const A2: &str = "op_3307";

/// Distinct seeds, per the module note. `from_seed` derives BOTH halves, which
/// is why `sign_as` can rebuild the same identity without carrying the signer
/// around: an unseeded ML-DSA keygen would give a different key per call for
/// the same name, and that was a real defect in this repository once.
fn seed_of(who: &str) -> &'static [u8] {
    match who {
        A1 => b"acp-45-slice5-attester-1",
        A2 => b"acp-45-slice5-attester-2",
        OP => b"acp-45-slice5-operator",
        _ => panic!("no seed for {who}"),
    }
}

fn registry() -> BTreeMap<String, AttesterKey> {
    [A1, A2, OP]
        .into_iter()
        .map(|who| {
            let k = KeyMaterial::from_seed(seed_of(who));
            (
                who.to_string(),
                AttesterKey {
                    classical: k.public().classical().to_vec(),
                    pq: k.public().pq().to_vec(),
                },
            )
        })
        .collect()
}

/// A well-formed AT-1 object: exactly the eleven fields, no more (AT-8b).
fn att_obj(nonce: &str) -> Value {
    json!({
        "alg": "hybrid-ed25519-mldsa65",
        "att_nonce": common::b64n(nonce),
        "bundle_epoch": 47,
        "context_snapshot_hash": "sha256:ctx",
        "expires_at": 1600.0,
        "floor_only_risk": "HIGH",
        "operator": OP,
        "policy_bundle_hash": "sha256:bundle",
        "proposal_hash": "sha256:proposal",
        "required_count": 2,
        "required_roles": ["net_approver"]
    })
}

/// Sign the DERIVED id, which is what the reference signs: `sig_ok(key, aid, …)`
/// where `aid = h(obj)`. Signing the object bytes directly would verify here and
/// fail every cross-language check in slice 6.
fn sign_as(who: &str, obj: &Value) -> Vec<SignaturePart> {
    let k = KeyMaterial::from_seed(seed_of(who));
    let signer = OfflineSigner::new(CustodyTier::T1, Suite::HybridEd25519MlDsa65, k).unwrap();
    let aid = attestation_id(obj).unwrap();
    let sig = signer.sign(aid.as_bytes(), Environment::Production).unwrap();
    sig.parts()
        .iter()
        .map(|(primitive, bytes)| SignaturePart { primitive: *primitive, bytes: bytes.clone() })
        .collect()
}

fn entry(who: &str, obj: Value, kind: &str) -> AttestationEntry {
    AttestationEntry {
        sig: sign_as(who, &obj),
        obj,
        kind: kind.to_string(),
        attester: who.to_string(),
        attestation_id: None,
    }
}

fn basis() -> DecisionBasis<'static> {
    DecisionBasis {
        proposal_hash: "sha256:proposal",
        policy_bundle_hash: "sha256:bundle",
        bundle_epoch: 47,
        risk: Risk::High,
        receipt_issued_at: 1000.0,
    }
}

fn check(reg: &BTreeMap<String, AttesterKey>, entries: &[AttestationEntry]) -> Result<String, acp_decision::Refusal> {
    let policy = QuorumPolicy { quorum_k: 2, attesters: reg, floor: SuiteId::Ed25519 };
    verify_quorum(&policy, &basis(), entries)
}

/// A legitimate k=2 quorum: two distinct approvers, plus a confirmation.
fn good_quorum() -> Vec<AttestationEntry> {
    vec![
        entry(A1, att_obj("n1"), "approval"),
        entry(A2, att_obj("n2"), "approval"),
        entry(OP, att_obj("n3"), "confirmation"),
    ]
}

// ---------------------------------------------------------------- the control

#[test]
fn a_well_formed_quorum_of_two_is_accepted() {
    // THE CONTROL. Without it every refusal assertion below is satisfied by a
    // verifier that refuses everything — the uniformly-broken trap, which the
    // EL-1 differential already had to guard against and which slice 4 named.
    let reg = registry();
    let operator = check(&reg, &good_quorum()).expect("a valid k=2 quorum was refused");
    // And the operator is established from the VERIFIED objects (Y4), never
    // from a receipt body that could disagree with them.
    assert_eq!(operator, OP);
}

// ------------------------------------------------- AT-9's two requirements

#[test]
fn at3_a_single_approval_does_not_satisfy_a_quorum_of_two() {
    // Kills `at3-quorum-comparison`. This is the INV-1-HIGH control proper:
    // the threshold is met or the action does not run.
    let reg = registry();
    let entries = vec![
        entry(A1, att_obj("n1"), "approval"),
        entry(OP, att_obj("n3"), "confirmation"),
    ];
    let e = check(&reg, &entries).unwrap_err();
    assert_eq!(e.clause, CLAUSE_QUORUM, "a quorum of one satisfied k=2: {e}");
}

#[test]
fn at9_attesters_who_signed_for_a_larger_quorum_are_refused() {
    // Kills `at9-consent`. THE INVARIANT HOLDS THROUGHOUT — two distinct
    // approvals against a bundle requiring two. What fails is consent: both
    // objects say `required_count: 3`, so both humans signed for an action
    // three people would review, and the third reviewer never existed.
    //
    // Note WHICH clause is asserted. Delete the consent check and this input is
    // ACCEPTED, not refused under some other rule — so unlike CR-4 in slice 4,
    // the mutant is caught by the outcome. Asserting the clause anyway keeps
    // the reason honest and is what slice 6's differential compares.
    let reg = registry();
    let obj = |n: &str| {
        let mut o = att_obj(n);
        o["required_count"] = json!(3);
        o
    };
    let entries = vec![
        entry(A1, obj("n1"), "approval"),
        entry(A2, obj("n2"), "approval"),
    ];
    let e = check(&reg, &entries).unwrap_err();
    assert_eq!(e.clause, CLAUSE_CONSENT, "stated-vs-applied quorum passed: {e}");
}

#[test]
fn at9s_two_requirements_are_not_redundant() {
    // The property the clause exists for, asserted directly rather than left
    // implicit in two separate tests: each requirement ACCEPTS the input the
    // other refuses, so neither can substitute for the other.
    let reg = registry();

    // Refused by AT-3 (too few approvals); the consent check sees nothing
    // wrong, because every stated count equals the bundle's.
    let too_few = vec![
        entry(A1, att_obj("n1"), "approval"),
        entry(OP, att_obj("n3"), "confirmation"),
    ];
    assert_eq!(check(&reg, &too_few).unwrap_err().clause, CLAUSE_QUORUM);

    // Refused by AT-9 (stated basis diverges); the threshold comparison sees
    // nothing wrong, because two distinct approvals are present for k=2.
    let wrong_basis = {
        let obj = |n: &str| {
            let mut o = att_obj(n);
            o["required_count"] = json!(3);
            o
        };
        vec![entry(A1, obj("n1"), "approval"), entry(A2, obj("n2"), "approval")]
    };
    assert_eq!(check(&reg, &wrong_basis).unwrap_err().clause, CLAUSE_CONSENT);
}

#[test]
fn at2_the_operator_never_counts_toward_their_own_quorum() {
    // Kills `at2-self-approval`. Two distinct approvals are present and the
    // threshold IS met — `approvals` is {op_8842, op_1121} — so this input
    // passes AT-3 and is stopped only by distinctness. DR-9 restates the same
    // bar for confirmations at release time.
    let reg = registry();
    let entries = vec![
        entry(OP, att_obj("n1"), "approval"),
        entry(A1, att_obj("n2"), "approval"),
    ];
    let e = check(&reg, &entries).unwrap_err();
    assert_eq!(e.clause, CLAUSE_OPERATOR_SELF, "the proposer approved themselves: {e}");
}

// ------------------------------------------------------ the surrounding gate

#[test]
fn inv1_high_refuses_a_floor_high_action_with_no_attestations() {
    let reg = registry();
    let e = check(&reg, &[]).unwrap_err();
    assert_eq!(e.clause, CLAUSE_NO_ATTESTATIONS);
}

#[test]
fn at8b_the_object_schema_is_closed_in_both_directions() {
    let reg = registry();

    // An EXTRA field is refused rather than ignored: an issuer must not be able
    // to add a field a future verifier reads without invalidating the object.
    let mut extra = att_obj("n1");
    extra["surprise"] = json!("hello");
    let entries = vec![entry(A1, extra, "approval")];
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_OBJECT_SCHEMA);

    // A MISSING field is refused rather than defaulted (Z4).
    let mut missing = att_obj("n2");
    missing.as_object_mut().unwrap().remove("context_snapshot_hash");
    let entries = vec![entry(A1, missing, "approval")];
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_OBJECT_SCHEMA);
}

#[test]
fn we4_the_b64_prefix_is_part_of_the_value() {
    // ACP-87, recorded as the reference records it. The prefix stripped, and
    // nothing else touched: signed correctly, exact field set, honest binding.
    // `attestation_id` is over the canonical bytes of the whole object, so this
    // is a second id for one attestation and a second ledger slot.
    let reg = registry();
    let mut o = att_obj("n1");
    let bare = o["att_nonce"].as_str().unwrap().strip_prefix("b64:").unwrap().to_string();
    o["att_nonce"] = json!(bare);
    let entries = vec![entry(A1, o, "approval")];
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_WIRE_TYPE);
}

#[test]
fn we4_stripped_padding_is_rejected_and_not_normalized() {
    // WE-4 says omitting the padding MUST be rejected rather than normalized.
    // The reference's first pattern accepted it — `[A-Za-z0-9+/]+={0,2}` also
    // matches `b64:A` and `b64:AAA`, lengths that are not base64 at all — so
    // the clause said one thing and the control enforced a weaker thing.
    let reg = registry();
    let mut o = att_obj("n1");
    let unpadded = o["att_nonce"].as_str().unwrap().trim_end_matches('=').to_string();
    o["att_nonce"] = json!(unpadded);
    let entries = vec![entry(A1, o, "approval")];
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_WIRE_TYPE);
}

#[test]
fn we4_the_url_safe_alphabet_is_a_different_value_not_a_spelling() {
    // THE ONE SHAPE ONLY WE-4 CATCHES, and the reference's mutation harness is
    // what established that. Stripping the prefix or the padding also changes
    // the LENGTH, so AT-1 below refuses those even with the type check gone —
    // against them WE-4 is redundant. Swapping RFC 4648 §4's `+` and `/` for
    // §5's `-` and `_` preserves the length and the decoded bytes and changes
    // only the string, so every other step passes it.
    let reg = registry();
    let mut o = att_obj("url-safe");
    let std = o["att_nonce"].as_str().unwrap().to_string();
    assert!(
        std.contains('+') || std.contains('/'),
        "fixture seed produces no alphabet difference, so this tests nothing"
    );
    o["att_nonce"] = json!(std.replace('+', "-").replace('/', "_"));
    let entries = vec![entry(A1, o, "approval")];
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_WIRE_TYPE);
}

#[test]
fn at1_a_well_formed_64_bit_nonce_refuses_under_at1_and_not_we4() {
    // The refusal NAME is the assertion. This value is exactly what WE-4
    // demands; what is wrong with it is that AT-1 says 128-bit and this is
    // half that. A check that folded the size into the type would answer
    // `WE-4` here, and the cross-language differential compares names.
    let reg = registry();
    let mut o = att_obj("n1");
    // Ten alphabet characters and `==` — a well-formed encoding of eight bytes.
    let short = format!("b64:{}==", &o["att_nonce"].as_str().unwrap()[4..14]);
    assert!(is_we4_b64(&short), "the fixture must SATISFY WE-4, or it tests WE-4");
    o["att_nonce"] = json!(short);
    let entries = vec![entry(A1, o, "approval")];
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_NONCE_SIZE);
}

#[test]
fn we4_and_at1_agree_with_the_reference_on_the_shared_corpus() {
    // The two definitions of this type — `attestation_object.schema.json` and
    // the reference — diverged silently for a whole release: the schema pinned
    // `{22}==` and the reference accepted any length, and no fixture fed a
    // wrong-length nonce so both stayed green. The corpus is now ONE file with
    // three consumers; `tools/check-nonce-type.py` holds the other two.
    let raw = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/nonce-type-vectors.json"),
    )
    .expect("the shared corpus must be readable — a vector file nothing reads is not a control");
    let corpus: Value = serde_json::from_str(&raw).unwrap();
    let mut checked = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let value = case["value"].as_str().unwrap();
        let want = case["clause"].as_str(); // None => conforming
        let got = if !is_we4_b64(value) {
            Some(CLAUSE_WIRE_TYPE)
        } else if value.len() != AT1_NONCE_LEN {
            Some(CLAUSE_NONCE_SIZE)
        } else {
            None
        };
        assert_eq!(got, want, "corpus case {:?}: {}", value, case["why"].as_str().unwrap());
        checked += 1;
    }
    assert!(checked >= 10, "corpus shrank to {checked} cases — a smaller corpus is a weaker claim");
}

#[test]
fn y1_an_attestation_bound_to_a_different_proposal_is_refused() {
    // The signature is genuine. It attests to something else, which is exactly
    // why a transmitted binding must be checked against the recomputed hash.
    let reg = registry();
    let mut o = att_obj("n1");
    o["proposal_hash"] = json!("sha256:some-other-proposal");
    let entries = vec![entry(A1, o, "approval")];
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_BINDING);
}

#[test]
fn y1b_a_transmitted_attestation_id_that_disagrees_is_refused() {
    let reg = registry();
    let mut entries = good_quorum();
    entries[0].attestation_id = Some("sha256:deadbeef".to_string());
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_DERIVED_ID);

    // The control: the DERIVED id, transmitted honestly, is accepted. Without
    // this the check above is satisfied by refusing every transmitted id.
    let mut ok = good_quorum();
    ok[0].attestation_id = Some(attestation_id(&ok[0].obj).unwrap());
    assert!(check(&reg, &ok).is_ok(), "an honestly transmitted id was refused");
}

#[test]
fn tr8_the_risk_compared_is_the_recomputed_one() {
    // X1 in miniature: an object asserting a risk the verifier did not compute
    // is refused. The basis says HIGH; the object claims LOW.
    let reg = registry();
    let mut o = att_obj("n1");
    o["floor_only_risk"] = json!("LOW");
    let entries = vec![entry(A1, o, "approval")];
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_POLICY_BASIS);
}

#[test]
fn ack4_an_identity_absent_from_the_registry_is_not_an_attester() {
    // The signature is cryptographically perfect. The key is not in the signed
    // bundle, which is the only reason that should matter.
    let reg = registry();
    let mut entries = good_quorum();
    entries[0].attester = "op_9999_not_enrolled".to_string();
    assert_eq!(check(&reg, &entries).unwrap_err().clause, CLAUSE_ATTESTER_SIG);
}

#[test]
fn cr4_an_unknown_attestation_suite_refuses_under_cr4_not_cr1() {
    // A PINNED DIVERGENCE FROM THE RECEIPT PATH, and it is deliberate.
    // `Bundle.suite_ok` returns False for a suite it does not know, so the
    // reference raises CR-4 here while `verify_receipt` raises CR-1 for the
    // same shape. Slice 6's differential compares refusal NAMES, so matching
    // the reference beats internal symmetry. If this ever becomes CR-1, the
    // change must be made on both sides at once and this assertion is the one
    // that says so.
    let reg = registry();
    let mut o = att_obj("n1");
    o["alg"] = json!("ed25519-but-not-really");
    let entries = vec![entry(A1, o, "approval")];
    let e = check(&reg, &entries).unwrap_err();
    assert_eq!(e.clause, CLAUSE_ATTESTATION_SUITE, "unknown suite took the wrong clause: {e}");
}

// ------------------------------------------------------- the `kind` disclosure

#[test]
fn kind_is_an_unsigned_input_that_decides_quorum_membership() {
    // THE DISCLOSURE, ASSERTED FROM BOTH SIDES so it cannot change silently —
    // the ACP-75 pattern.
    //
    // The two runs below differ in ONE byte of unsigned wire data. The objects
    // are identical, the signatures are identical and genuine in both, and the
    // outcome flips from refused to accepted. `kind` is absent from AT1_FIELDS,
    // so no attester signs it, and the object carries nothing else saying
    // whether its signer meant to approve or to confirm.
    //
    // The schema declares a signed per-attester `role` that would settle it.
    // Nothing reads it — `AttesterRole` is generated with no consumer anywhere,
    // and the Python reference has no role field at all, so it cannot check
    // one. Matched bug for bug on purpose; the fix belongs in the spec first.
    //
    // When that lands, the ACCEPTING assertion is the one that must change,
    // deliberately rather than by discovery.
    let reg = registry();
    let obj_a1 = att_obj("n1");
    let obj_a2 = att_obj("n2");

    let as_confirmation = vec![
        entry(A1, obj_a1.clone(), "approval"),
        entry(A2, obj_a2.clone(), "confirmation"),
    ];
    assert_eq!(
        check(&reg, &as_confirmation).unwrap_err().clause,
        CLAUSE_QUORUM,
        "a confirmation counted toward the quorum"
    );

    let relabelled = vec![
        entry(A1, obj_a1, "approval"),
        entry(A2, obj_a2, "approval"),
    ];
    assert!(
        check(&reg, &relabelled).is_ok(),
        "the relabelled entry was refused -- if a role check landed, update the disclosure"
    );
}
