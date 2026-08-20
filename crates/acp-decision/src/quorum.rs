//! §9.3 step 7b — the AT-\* quorum, and AT-9's two requirements.
//!
//! `grade.rs` decides what an action needs; `receipt.rs` decides whether the
//! substrate issued the thing claiming that need. This module decides whether
//! the **humans** the policy requires actually agreed, which is the control
//! INV-1-HIGH names and the one a compromised Executor most wants to skip.
//!
//! # AT-9 is TWO requirements, and they fail closed on disjoint inputs
//!
//! This is the whole reason the clause exists, and an implementation keeping
//! only one of them looks correct:
//!
//! 1. **The threshold is recomputed** from the signed bundle's `quorum_k`
//!    (PB-6) and never read from an attestation. Through v1.3.14 the reference
//!    read `entries[0].required_count` — asking the party under verification
//!    how many signatures to demand — and one compromised attester key signing
//!    one object carrying `required_count: 1` executed a floor-HIGH action.
//!    Sixth recurrence of the RES-8 class (C2 → X1 → Y1 → Z3 → W1 → this).
//! 2. **Every entry's `required_count` must equal `quorum_k`** — a *consent*
//!    check, not a threshold one. It catches attesters who signed under a
//!    stated threshold different from the one applied. Both objects saying
//!    `required_count: 3` while the bundle says 2 means two humans approved an
//!    action believing a third reviewer existed. The invariant holds
//!    throughout; what fails is AT-3 consent.
//!
//! Deleting (2) cannot lower a quorum. Deleting (1) cannot detect an attester
//! who signed under a different stated threshold. Keeping only (1) satisfies
//! INV-1-HIGH while silently executing actions no attester agreed to.
//!
//! # `quorum_k` is read here, and that line is NOT a control
//!
//! Reading the threshold from [`QuorumPolicy::quorum_k`] rather than from an
//! entry raises nothing, so no mutant can score it — and this is settled
//! ground rather than an excuse. `reference/suites/mutate_executor.py` records
//! the threshold-from-object mutant being **written, run, and removed**: AT-9's
//! consent check forces every entry's `required_count` to equal `quorum_k`, so
//! substituting `entries[0]` yields the bundle's own number and the mutant
//! survives. The masking is real, not a test defect.
//!
//! The honest reading, taken verbatim from that note: the recomputation "is not
//! a CHECK at all: it is the choice of which variable a number is read from".
//! The two branches that *can* refuse are AT-9's equality and AT-3's
//! comparison, and both carry mutants. This line stays because it makes the
//! property local instead of dependent on a check elsewhere in the loop, and it
//! is labelled **defence in depth** rather than dressed up as a control.
//!
//! # Keys arrive as raw bytes, and the reason is a disclosed gap
//!
//! [`QuorumPolicy`] takes decoded verification keys, exactly as
//! [`crate::receipt::verify_receipt`] takes a `ReceiptKey` and a floor. Both
//! are documented as coming from the signed bundle; neither reads the bundle
//! itself, because wiring the decision path to a live `BundleHost` is step 5.
//!
//! What is worth naming rather than leaving implicit: the generated
//! `AttesterRegistry` stores `classical` and `pq` as **base64 strings**, and
//! **nothing in this workspace decodes base64**. `acp-bundle`'s PB-7 compares
//! those strings without decoding them, which is correct for a distinctness
//! test and insufficient for a verification. So the decision path cannot today
//! be driven from a real bundle's registry, and that is an integration gap, not
//! a design choice.
//!
//! # PB-7 is NOT restated here
//!
//! Attester key distinctness is enforced at bundle load in
//! `acp_bundle::verify`, where the schema says the loader owns it: a registry
//! that cannot support its own quorum is malformed everywhere it is used, not
//! only on this path. A second copy here would be two definitions of one rule —
//! the encoding-split defect this repository names at the source level — so
//! this module *depends* on that check having run and says so instead.
//!
//! # Suite 12 classification — R / B / T, written with the code
//!
//! Every control input this module reads, classified **R** (recomputed), **B**
//! (bound to signed bytes) or **T** (trusted as transmitted). An unlisted `T`
//! is a conformance failure, so the point of the table is the last row.
//!
//! | input | class | why |
//! | --- | :---: | --- |
//! | `quorum_k` | **R** | from the signed bundle, never an attestation (AT-9) |
//! | attester keys | **B** | the registry is inside `policy_bundle_hash` (PB-KEY) |
//! | `floor` | **R** | from the signed manifest (CR-4) |
//! | the eleven AT-1 fields | **B** | the signature covers the derived id, which covers the whole object |
//! | `obj.proposal_hash` | **B** | and compared against the recomputed hash (Y1) |
//! | `obj.floor_only_risk` | **B** | and compared against the recomputed grade (TR-8/X1) |
//! | `obj.required_count` | **B** | and compared against `quorum_k` (AT-9) |
//! | `entry.attester` | **B** | a name selects a key; the signature establishes identity (ACK-4) |
//! | `entry.attestation_id` | **R** | derived; a transmitted value is compared, never used (Y1b) |
//! | `entry.sig` | **B** | verified under a registry key |
//! | `basis.*` | **R** | recomputed by the caller before this function is reached |
//! | **`entry.kind`** | **T** | **DISCLOSED RESIDUAL.** It decides quorum membership and no signature covers it. See [`verify_quorum`]. |
//!
//! # Two divergences from the reference, both deliberate and both pinned
//!
//! **An unknown `alg` on an attestation refuses under `CR-4`, not `CR-1`.**
//! That is not a slip. `Bundle.suite_ok` returns `False` for a suite it does
//! not know, so the reference raises CR-4 on the attestation path while the
//! receipt path raises CR-1. The cross-language differential compares refusal
//! *names*, so matching the reference matters more than internal symmetry.
//!
//! **`kind` decides quorum membership and is not signature-covered.** See
//! [`verify_quorum`]. Matched bug for bug, asserted from both sides, disclosed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use acp_core::generated::{Risk, SuiteId};
use acp_crypto::{verify_ed25519, verify_mldsa65, Primitive, PrimitiveVerdict};
use sha2::{Digest, Sha256};

use crate::receipt::{canon, parse_suite, suite_of, SignaturePart};
use crate::Refusal;

/// INV-1-HIGH — a floor-HIGH action presented with no attestations at all.
pub const CLAUSE_NO_ATTESTATIONS: &str = "INV-1-HIGH";
/// AT-8 — an entry carrying no Attestation Object (the pre-v1.3.3 form).
pub const CLAUSE_NO_OBJECT: &str = "AT-8";
/// AT-8b — the object's field set is not exactly AT-1's.
pub const CLAUSE_OBJECT_SCHEMA: &str = "AT-8b";
/// CR-4 — the attestation's suite does not contain every primitive of the floor.
pub const CLAUSE_ATTESTATION_SUITE: &str = "CR-4";
/// §9.3 step 7b(i) — the attester signature did not verify under a registry key.
pub const CLAUSE_ATTESTER_SIG: &str = "9.3-7b-i";
/// §9.3 step 7b(ii) — the object binds a different proposal.
pub const CLAUSE_BINDING: &str = "9.3-7b-ii";
/// §9.3 step 7b(iii) — policy basis, recomputed risk, or object freshness.
pub const CLAUSE_POLICY_BASIS: &str = "9.3-7b-iii";
/// §9.3 step 7b(iii-a) — the objects disagree on who the operator is (Y4).
pub const CLAUSE_OPERATOR_DISAGREE: &str = "9.3-7b-iii-a";
/// AT-9 — an attester signed for a quorum other than the bundle's.
pub const CLAUSE_CONSENT: &str = "AT-9";
/// Y1b — a transmitted `attestation_id` differing from the derived one.
pub const CLAUSE_DERIVED_ID: &str = "Y1b";
/// AT-3 — fewer distinct approvals than the recomputed threshold.
pub const CLAUSE_QUORUM: &str = "AT-3";
/// AT-2 — the operator counted toward their own quorum.
pub const CLAUSE_OPERATOR_SELF: &str = "AT-2";

/// AT-8b: the Attestation Object schema is **CLOSED**. Exact field set, no
/// more and no less.
///
/// An unknown field is refused rather than ignored and a missing one is never
/// defaulted (Z4). Normalizing either would let an issuer add a field a future
/// verifier reads, or drop one this verifier checks, without invalidating a
/// signature that covers only what is present.
pub const AT1_FIELDS: [&str; 11] = [
    "alg",
    "att_nonce",
    "bundle_epoch",
    "context_snapshot_hash",
    "expires_at",
    "floor_only_risk",
    "operator",
    "policy_bundle_hash",
    "proposal_hash",
    "required_count",
    "required_roles",
];

/// One attester's decoded verification key, both halves.
///
/// Both, because hybrid composition is conjunctive (CR-3): a verifier holding
/// only the classical half cannot distinguish a stripped post-quantum leg from
/// a suite that never carried one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttesterKey {
    pub classical: Vec<u8>,
    pub pq: Vec<u8>,
}

/// The quorum policy, every field of which comes from the **signed bundle**.
///
/// Nothing here may be sourced from the receipt or from an Attestation Object.
/// That is AT-9 for `quorum_k`, PB-KEY for `attesters`, and CR-4 for `floor`.
#[derive(Debug, Clone)]
pub struct QuorumPolicy<'a> {
    /// PB-6. The number of DISTINCT approvals a floor-HIGH action requires.
    pub quorum_k: u64,
    /// The attester registry: identity -> verification key. PB-7 distinctness
    /// is the bundle loader's obligation and is assumed to have run.
    pub attesters: &'a BTreeMap<String, AttesterKey>,
    /// CR-4 suite floor, from the signed manifest.
    pub floor: SuiteId,
}

/// The values every attestation is checked *against*, all recomputed by the
/// verifier before this function is called.
///
/// `risk` in particular is the value `grade.rs` derived from the canonical
/// Proposal, never the receipt's `risk_level_floor_only` — that field is X1,
/// the defect where a compromised issuer asserting `LOW` suppressed
/// attestation entirely.
#[derive(Debug, Clone)]
pub struct DecisionBasis<'a> {
    pub proposal_hash: &'a str,
    pub policy_bundle_hash: &'a str,
    pub bundle_epoch: u64,
    pub risk: Risk,
    pub receipt_issued_at: f64,
}

/// One presented attestation, exactly as it arrives on the wire.
#[derive(Debug, Clone)]
pub struct AttestationEntry {
    /// The AT-1 object the attester signed.
    pub obj: serde_json::Value,
    /// **NOT SIGNATURE-COVERED.** See [`verify_quorum`]'s disclosure.
    pub kind: String,
    /// The registry identity claimed for this entry. It is not believed: it
    /// selects which key the signature must verify under, and a name that
    /// resolves to no key refuses at `9.3-7b-i` (ACK-4).
    pub attester: String,
    pub sig: Vec<SignaturePart>,
    /// Transmitted, and compared against the derived id rather than used
    /// (Y1b). `None` is permitted; a value that disagrees is refused.
    pub attestation_id: Option<String>,
}

/// AT-8a — derive an Attestation Object's id from its canonical bytes.
///
/// `"sha256:" + hex(sha256(canon(obj)))`, reproducing the reference's `h()`.
/// **Derived, never read**: the id names a binding, and a transmitted name for
/// a binding is not evidence of one (Y1b).
///
/// The hex is written out rather than pulled from a crate because `hex` is a
/// dev-dependency elsewhere in this workspace and a decision path should not
/// acquire a runtime dependency for sixteen characters of formatting.
pub fn attestation_id(obj: &serde_json::Value) -> Result<String, Refusal> {
    let bytes = canon(obj)?;
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for b in digest {
        // Infallible: writing to a String cannot fail.
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

/// Read a required string field, refusing under the clause that governs it.
fn str_field<'a>(obj: &'a serde_json::Value, name: &str, clause: &'static str) -> Result<&'a str, Refusal> {
    obj.get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Refusal::new(clause, format!("attestation object field {name} is not a string")))
}

/// Read a required unsigned integer field.
fn u64_field(obj: &serde_json::Value, name: &str, clause: &'static str) -> Result<u64, Refusal> {
    obj.get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Refusal::new(clause, format!("attestation object field {name} is not an integer")))
}

/// Read a required numeric field as `f64`.
///
/// The reference carries `expires_at` as a float, so this must accept one.
/// Note the interaction with ACP-75, which `receipt.rs` documents: `canon`'s
/// float guard is top-level only, so a float *inside* the object encodes
/// happily in both languages. That is why these timestamps round-trip at all.
fn f64_field(obj: &serde_json::Value, name: &str, clause: &'static str) -> Result<f64, Refusal> {
    obj.get(name)
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| Refusal::new(clause, format!("attestation object field {name} is not a number")))
}

/// §9.3 step 7b. Returns the operator established from the **verified**
/// objects, which is the value the caller must use thereafter (Y4).
///
/// # The `kind` disclosure — an unsigned control input
///
/// Whether an entry counts toward the quorum is decided by `kind`, and `kind`
/// is **not** in [`AT1_FIELDS`]. It is therefore not covered by the attester's
/// signature, and the object carries nothing else distinguishing an approval
/// from a confirmation — so an attester cannot express which one they intended,
/// and whoever assembles the receipt chooses per entry whose signature counts.
///
/// The schema declares a signed per-attester `role` (approver / confirmer) that
/// would answer this. Nothing reads it: `AttesterRole` is generated and has no
/// consumer anywhere in the workspace, and the Python reference has no role
/// field at all, so it *cannot* check one.
///
/// This is matched to the reference bug for bug, on the ACP-75 precedent.
/// Consulting `role` here would be a Rust-only rule, and inventing normative
/// behaviour inside the slice that verifies signatures over it is the worst
/// available moment — the fix belongs in the specification first, then in both
/// implementations at once. Both halves are asserted below so the behaviour
/// cannot change silently, and the residual is disclosed rather than carried
/// quietly.
pub fn verify_quorum(
    policy: &QuorumPolicy<'_>,
    basis: &DecisionBasis<'_>,
    entries: &[AttestationEntry],
) -> Result<String, Refusal> {
    if entries.is_empty() {
        return Err(Refusal::new(
            CLAUSE_NO_ATTESTATIONS,
            "floor-HIGH with no attestations",
        ));
    }

    let mut approvals: BTreeSet<String> = BTreeSet::new();
    let mut operators: BTreeSet<String> = BTreeSet::new();

    for e in entries {
        let obj = &e.obj;
        let Some(map) = obj.as_object() else {
            return Err(Refusal::new(
                CLAUSE_NO_OBJECT,
                "attestation carries no object (v1.3.2 form)",
            ));
        };

        // AT-8b: CLOSED schema. Exact field set, never normalized.
        let present: BTreeSet<&str> = map.keys().map(String::as_str).collect();
        let expected: BTreeSet<&str> = AT1_FIELDS.iter().copied().collect();
        if present != expected {
            let missing: Vec<&str> = expected.difference(&present).copied().collect();
            let extra: Vec<&str> = present.difference(&expected).copied().collect();
            return Err(Refusal::new(
                CLAUSE_OBJECT_SCHEMA,
                format!("object schema violation missing={missing:?} extra={extra:?}"),
            ));
        }

        // (i) the id is DERIVED from the canonical object, and it is also the
        // message the attester signed. Deriving it before the signature check
        // is what makes the signature cover the whole object rather than a
        // digest someone else chose.
        let aid = attestation_id(obj)?;

        // CR-5: `alg` is an AT-1 field, so the suite is signature-covered — an
        // issuer cannot rewrite it without invalidating the object.
        //
        // CR-4 by CONTAINMENT. An UNKNOWN suite refuses here under CR-4 rather
        // than CR-1, matching `Bundle.suite_ok`, which returns False for a name
        // it does not know. The receipt path spells the same condition CR-1;
        // the differential compares refusal names, so the reference wins.
        let alg = str_field(obj, "alg", CLAUSE_ATTESTATION_SUITE)?;
        let suite_ok = parse_suite(alg)
            .is_ok_and(|s| s.satisfies_floor(suite_of(policy.floor)));
        if !suite_ok {
            return Err(Refusal::new(
                CLAUSE_ATTESTATION_SUITE,
                format!("attestation suite {alg} below bundle floor"),
            ));
        }
        // Re-parsed rather than threaded out of the closure above: the suite is
        // a PARAMETER of the conjunctive combiner and must be the one the
        // object declared, not one this function chose.
        let suite = parse_suite(alg)?;

        // (i) the signature, over the derived id, under the REGISTRY key.
        //
        // An identity absent from the signed registry is not an attester
        // (ACK-4): it refuses here rather than resolving to a default, because
        // a name nobody enrolled must not be able to satisfy INV-1-HIGH.
        let Some(key) = policy.attesters.get(&e.attester) else {
            return Err(Refusal::new(CLAUSE_ATTESTER_SIG, "attester signature invalid"));
        };
        let mut verdicts = Vec::with_capacity(e.sig.len());
        for part in &e.sig {
            let verdict = match part.primitive {
                Primitive::Classical => verify_ed25519(&key.classical, aid.as_bytes(), &part.bytes),
                Primitive::Pq => verify_mldsa65(&key.pq, aid.as_bytes(), &part.bytes),
                // Declared, not implemented. Never a pass, and never dropped
                // from the set — dropping it would let a suite naming it be
                // satisfied by the primitives that remain.
                Primitive::PqSlh => PrimitiveVerdict::Unsupported,
            };
            verdicts.push((part.primitive, verdict));
        }
        if acp_crypto::verify_hybrid(suite, &verdicts).is_err() {
            return Err(Refusal::new(CLAUSE_ATTESTER_SIG, "attester signature invalid"));
        }

        // (ii) THE BINDING. Y1: a genuine signature over an object bound to a
        // DIFFERENT proposal is a valid attestation to something else.
        if str_field(obj, "proposal_hash", CLAUSE_BINDING)? != basis.proposal_hash {
            return Err(Refusal::new(
                CLAUSE_BINDING,
                "attestation bound to a DIFFERENT proposal",
            ));
        }

        // (iii) the policy basis the attester was shown.
        if str_field(obj, "policy_bundle_hash", CLAUSE_POLICY_BASIS)? != basis.policy_bundle_hash
            || u64_field(obj, "bundle_epoch", CLAUSE_POLICY_BASIS)? != basis.bundle_epoch
        {
            return Err(Refusal::new(
                CLAUSE_POLICY_BASIS,
                "attestation policy basis mismatch",
            ));
        }
        // TR-8: compared against the RECOMPUTED grade, never the receipt's.
        if str_field(obj, "floor_only_risk", CLAUSE_POLICY_BASIS)? != basis.risk.as_wire() {
            return Err(Refusal::new(
                CLAUSE_POLICY_BASIS,
                "attestation risk != recomputed risk",
            ));
        }

        // (iii) AT-9's SECOND requirement: CONSENT, not threshold.
        //
        // This is not how the quorum size is obtained — that is `quorum_k`
        // below, and this field is never consulted for it. Deleting this line
        // cannot lower a quorum. What it catches is an AT-3 consent failure:
        // `required_count` is part of what the attester was SHOWN and signed,
        // so a mismatch means the humans approved under a policy the engine did
        // not apply.
        //
        // A first pass at the reference's fix DELETED this check, arguing the
        // threshold is already bound transitively through `policy_bundle_hash`
        // so an equality test kills no mutant. The argument was sound and the
        // conclusion wrong: it considered only attacks that LOWER the
        // threshold. Raising the stated count is not an attack on the invariant
        // at all — it is an attack on consent, and it has its own mutant.
        let stated = u64_field(obj, "required_count", CLAUSE_CONSENT)?;
        if stated != policy.quorum_k {
            return Err(Refusal::new(
                CLAUSE_CONSENT,
                format!(
                    "attester signed for quorum {stated}, bundle requires {}",
                    policy.quorum_k
                ),
            ));
        }

        // (iii) freshness of the object itself, against the receipt's issuance.
        if f64_field(obj, "expires_at", CLAUSE_POLICY_BASIS)? < basis.receipt_issued_at {
            return Err(Refusal::new(
                CLAUSE_POLICY_BASIS,
                "attestation expired before issuance",
            ));
        }

        // (iii-a) the operator comes from the VERIFIED object (Y4), never from
        // the receipt body — a body/object disagreement must not be resolved in
        // favour of the body.
        operators.insert(str_field(obj, "operator", CLAUSE_POLICY_BASIS)?.to_string());

        // (v) Y1b: the derived id is authoritative. A transmitted id is
        // permitted to be absent and refused when it disagrees.
        if let Some(claimed) = &e.attestation_id
            && claimed != &aid
        {
            return Err(Refusal::new(
                CLAUSE_DERIVED_ID,
                "transmitted attestation_id != derived id",
            ));
        }

        // Cross-receipt single-use of `aid` — the reference's
        // `ledger.claim_attestation` — is DEFERRED to ACP-46, which is where a
        // ledger that survives a restart lands. It is named here rather than
        // omitted silently: replay protection that forgets is not replay
        // protection, and this module currently provides none.

        // The `kind` routing disclosed in this function's docs. Distinct
        // ATTESTERS, not distinct entries: the set is what AT-3 counts.
        if e.kind == "approval" {
            approvals.insert(e.attester.clone());
        }
        // A non-approval entry is collected by the reference into a
        // `confirmations` list that nothing ever reads. DR-9 confirmation is a
        // separate signed object handled at release time (`acp_ack.py`), so the
        // list is genuinely unused rather than checked elsewhere. Not
        // reproducing dead state.
    }

    if operators.len() != 1 {
        return Err(Refusal::new(
            CLAUSE_OPERATOR_DISAGREE,
            "attestations disagree on operator",
        ));
    }
    let operator = operators.into_iter().next().expect("len checked above");

    // AT-9's FIRST requirement. Defence in depth, not a control — see the
    // module docs and `mutate_executor.py`'s recorded note. It raises nothing;
    // the refusal below is what carries the mutant.
    let need = policy.quorum_k;
    let got = approvals.len() as u64;
    if got < need {
        return Err(Refusal::new(
            CLAUSE_QUORUM,
            format!("quorum {got} < {need}"),
        ));
    }

    // AT-2 distinctness: the proposer never counts toward their own quorum.
    // DR-9 restates this at release time for confirmations.
    if approvals.contains(&operator) {
        return Err(Refusal::new(
            CLAUSE_OPERATOR_SELF,
            "operator counted toward own quorum",
        ));
    }

    Ok(operator)
}
