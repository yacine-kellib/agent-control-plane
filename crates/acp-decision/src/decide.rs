//! §9.3, the receipt-consumption checklist, composed in the order the
//! specification states it.
//!
//! The other modules in this crate each answer one question. This one asks
//! them in sequence, and **the sequence is the point**: on an input carrying
//! more than one defect, the order decides *which clause fires*, and the clause
//! is what a refusal tells an operator. Two implementations that both refuse a
//! forged, expired receipt — one saying `9.3-1`, the other `9.3-5` — have not
//! been shown to agree on anything an operator could act on. That is the
//! property `tools/check-decision-differential.py` compares, and it is why this
//! module exists as a composition rather than as a caller's convenience.
//!
//! # What is here, and what is NOT — read this before trusting a green run
//!
//! The checklist has ten steps. This module implements the **stateless** ones.
//! The rest are not stubbed, not approximated, and not silently skipped: they
//! are absent, and [`UNIMPLEMENTED_STEPS`] names each one with the ticket that
//! owns it, so a caller cannot mistake this for a complete Executor.
//!
//! | step | rule | here |
//! | --- | --- | --- |
//! | 1–2 | CR-1 / CR-4 / CR-3, then `decision` | ✅ [`receipt::verify_receipt`] |
//! | 3 | `proposal_hash` recomputed (B-1a) | ✅ |
//! | 4 | policy basis and epoch | ✅ *(epoch **compare** only — the high-water mark is ACP-46)* |
//! | 5 | temporal position and L-14 window | ✅ |
//! | 6 | receipt nonce single-use (CL-2) | ❌ **ACP-46** — needs a ledger that survives restart |
//! | 7 | TR-8 recomputation, RV-3 | ✅ [`crate::grade_floor_risk`] |
//! | 7b | the AT-\* quorum | ✅ [`quorum::verify_quorum`] |
//! | 8 | tenant scoping | ✅ |
//! | 9 | live capability recheck | ❌ **Context Store** — no provider chosen (§8.8) |
//! | 10 | DS-6 delivery identity, idempotency | ❌ **ACP-46** — origin pinning is ledger state |
//! | — | DR-13 notice below floor-HIGH | ✅ (the *refusal*; recording the notice is ledger state) |
//! | — | DR-1 deferred-release gate | ❌ **ACP-47** — see [`Outcome::deferred`] |
//!
//! **An absent step is a divergence, not an agreement.** A case whose Python
//! verdict depends on step 6 will produce `Passed` here and `REFUSED CL-2`
//! there, and the differential reports that as a divergence unless the case is
//! explicitly classified as blocked. That is deliberate: the failure mode this
//! repository is most exposed to is a green run that means nothing, and a
//! checklist that quietly returns "fine" for the steps it does not have is
//! exactly that. Classification is asserted in the harness, not assumed here.
//!
//! # Suite 12 classification — R / B / T
//!
//! Written with the code, per ACP-45. Every control input this module reads,
//! classified **R** (recomputed), **B** (bound to signed bytes) or **T**
//! (trusted as transmitted). An unlisted `T` is a conformance failure.
//!
//! | input | class | why |
//! | --- | :---: | --- |
//! | `receipt.alg` | **B** | names the suite the signature is then verified under; an unknown name refuses at CR-1 before anything reads it |
//! | `receipt.sig` | **B** | verified against `bundle.receipt_key`, which is the verifier's out-of-band configuration |
//! | `receipt.decision` | **B** | read only *after* the signature verifies, so reading it can only ever cause a refusal (step 2) |
//! | `receipt.proposal_hash` | **R** | compared against the hash of the Proposal **we** received (B-1a) |
//! | `receipt.policy_bundle_hash` | **B** | compared against the verifier's own bundle — see the residual below |
//! | `receipt.bundle_epoch` | **B** | compared against the verifier's own bundle |
//! | `receipt.issued_at` / `expires_at` | **B** | signature-covered; `now` is the verifier's clock, never the receipt's |
//! | `now` (the [`decide`] parameter) | **T** | the caller's reading of the verifier's clock. This crate reads no clock and compares it against nothing, and it alone decides whether step 5 refuses — residual 3 |
//! | `receipt.risk_level_floor_only` | **R** | recomputed by [`crate::grade_floor_risk`] and compared (TR-8/X1) |
//! | `receipt.reversibility` | **R** | recomputed from the signed bundle and compared (RV-3) |
//! | `receipt.fidelity` | **R** | recomputed from the adapter binding and compared (TR-8) |
//! | `receipt.tenant_id` | **B** | compared against the Proposal's, which the verifier received independently |
//! | `receipt.operator` | **B** at floor-HIGH | established from the *verified* attestations (Y4). See the residual below for below-HIGH. |
//! | `receipt.attestations` | — | classified per field in [`quorum`] |
//! | the risk grade, floors, reversibility, notice targets | **R** | derived from the signed bundle and the canonical Proposal |
//!
//! ## Disclosed residuals — the `T` entries
//!
//! **1. `receipt.operator` below floor-HIGH is `T`.** At floor-HIGH the
//! operator is returned by [`quorum::verify_quorum`] from the AT-1 objects, so
//! it is signature-covered (Y4 closed it there). Below floor-HIGH there is no
//! quorum, so the reference reads `receipt.operator` from the receipt body.
//! It *is* covered by the receipt signature, which makes it **B** against the
//! KMS — but the KMS is a party under verification, and no second party
//! attests to it. It reaches [`Outcome::operator`] and the DR-13 notice record,
//! so it is an input to what a human is told. Matched to the reference.
//!
//! **2. `receipt.policy_bundle_hash` is compared against a value this crate
//! does not derive.** [`BundleView::policy_bundle_hash`] is supplied by the
//! caller. In a deployment it is `acp-bundle`'s tree hash of the bundle the
//! verifier loaded and verified — the specification's object (§8.2, PB-8:
//! "SHA-256 of the canonical bundle tree"). It is **not** recomputed here
//! because this crate never sees the bundle *tree*, only a typed view of its
//! contents, and inventing a second derivation would be two definitions of one
//! object. **The reference has exactly that defect** — see ACP-81 — and the
//! consequence for this crate is that the two implementations cannot agree on
//! this value by construction; the harness supplies the verifier's own copy to
//! both. The residual is that a caller passing a hash from anywhere other than
//! a verified bundle silently voids step 4.
//!
//! **3. `now` is `T`: the verifier's clock as the *caller* supplies it.** It is
//! not the receipt's — the reference threads a `_now` field through the signed
//! body, and a verifier taking its notion of the present from the party it is
//! verifying would be RES-8 with a clock — but neither is it derived here. This
//! crate reads no clock, so nothing in it can check the value against anything:
//! a caller passing a stale or forward `now` voids the expiry and skew checks
//! entirely while `issued_at` and `expires_at` stay signature-covered and
//! unaltered, and the refusal that then does not happen leaves no trace. Only
//! L-14's window ceiling survives such a caller, because it compares the two
//! receipt fields against each other and never reads the clock. The differential
//! cannot catch this by construction — the harness passes the same value to both
//! sides, so a wrong clock is wrong identically in Python and in Rust. Closing it
//! means a time source the verifier holds and can state the provenance of; it
//! does **not** mean this crate calling `SystemTime::now()` itself, which moves
//! the same trust one frame inward and makes the checklist untestable besides.
//!
//! **4. Everything [`UNIMPLEMENTED_STEPS`] names is a residual too**, and the
//! larger one. A `Passed` from this module is not "the receipt may be
//! consumed"; it is "the stateless half of §9.3 found nothing".

use std::collections::BTreeMap;

use acp_core::generated::{Reversibility, Risk, SuiteId};
use acp_crypto::Primitive;

use crate::grade::{grade_floor_risk, notice_recipients, recompute_reversibility};
use crate::quorum::{self, AttestationEntry, AttesterKey, DecisionBasis, QuorumPolicy};
use crate::receipt::{self, ReceiptKey, SignaturePart};
use crate::{Policy, Proposal, Refusal};

/// The clock skew step 5 tolerates, in seconds. The reference's `iat > now + 5`.
const CLOCK_SKEW_SECS: f64 = 5.0;

/// L-14's ceiling on a receipt's validity window, in seconds.
const MAX_VALIDITY_WINDOW_SECS: f64 = 120.0;

/// The §9.3 steps this module does NOT implement, each with its owner.
///
/// Exported and asserted, not written in prose only. `tools/check-decision-
/// differential.py` reads the same list through the harness's classification
/// and refuses to run a conformance case that depends on one of these — so a
/// step arriving here without this list being updated makes the harness
/// classify a case it can now actually answer, and a step *removed* from the
/// implementation without being added here makes cases silently pass.
///
/// A gap named in a doc comment is a gap nothing can check.
pub const UNIMPLEMENTED_STEPS: &[(&str, &str, &str)] = &[
    ("9.3-6", "CL-2", "receipt nonce single-use — needs a ledger that survives restart (ACP-46)"),
    ("9.3-4", "RAD-3", "bundle-epoch high-water mark — must live in the ledger, shared across Executors (ACP-46)"),
    ("9.3-7b", "CL-3", "attestation_id single-use across receipts — same ledger (ACP-46)"),
    ("9.3-9", "9.3-9", "live capability recheck — needs the Context Store, no provider chosen (§8.8)"),
    ("9.3-10", "DS-6f", "delivery identity and idempotency — origin pinning is ledger state (ACP-46)"),
    ("DR-1", "DR-1", "the deferred-release gate — the two doors (ACP-47)"),
];

/// The verifier's own view of the signed bundle.
///
/// Every field is what the **verifier** holds, never what a receipt claims.
/// Borrowed rather than owned for the reason [`Policy`] gives: §1250 names
/// caching a bundle instead of re-reading it as a way to manufacture a `T`.
pub struct BundleView<'a> {
    pub epoch: u64,
    pub quorum_k: u64,
    /// CR-4 suite floor, from the signed manifest.
    pub min_suite: SuiteId,
    /// See residual 2 in the module docs. Supplied, not derived here.
    pub policy_bundle_hash: &'a str,
    pub policy: &'a Policy<'a>,
    pub attesters: &'a BTreeMap<String, AttesterKey>,
    pub receipt_key: &'a ReceiptKey,
}

/// What §9.3 concluded, when it concluded anything.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The **recomputed** grade (TR-8), never the receipt's claim.
    pub risk: Risk,
    /// The operator. At floor-HIGH this comes from the verified attestations
    /// (Y4); below it, from the receipt body — residual 1 above.
    pub operator: String,
    pub reversibility: Reversibility,
    pub fidelity: String,
    /// Who DR-13 requires be told before this runs. `None` when no notice is
    /// owed. **Computing the recipient list is not sending the notice**; the
    /// record the reference writes is ledger state and is not here.
    pub notice_recipients: Option<Vec<String>>,
    /// True when DR-1 would hand this to the deferred-release gate instead of
    /// executing it. The gate itself is ACP-47, so this is a **statement about
    /// what §9.3 concluded**, not a release decision. A caller treating
    /// `deferred == true` as permission to act has skipped the door.
    pub deferred: bool,
}

/// Run the stateless half of §9.3 in specification order.
///
/// `now` is the **verifier's** clock. The reference threads a `_now` field
/// through the receipt for testability; that field is inside the signature, but
/// a verifier taking its notion of the present from the party it is verifying
/// would be RES-8 with a clock, so it is a parameter here and the harness
/// passes the same value to both sides.
/// That makes it `T` at this crate's boundary, not `R`: see residual 3 in the
/// module docs for what a caller can silently switch off with it.
pub fn decide(
    receipt_json: &serde_json::Value,
    proposal_json: &serde_json::Value,
    typed_proposal: &Proposal,
    bundle: &BundleView<'_>,
    now: f64,
) -> Result<Outcome, Refusal> {
    // ---------------------------------------------------------- steps 1-2
    let alg = receipt_json
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Refusal::new(receipt::CLAUSE_UNKNOWN_SUITE, "receipt declares no suite"))?;

    // The body is everything but `sig`, canonicalised. `serde_json::Map` is a
    // BTreeMap here (the crate is pulled in with `default-features = false`,
    // so `preserve_order` is off), which is what makes this sorted-key
    // canonical form agree with Python's `sort_keys=True`.
    let body = {
        let mut m = receipt_json
            .as_object()
            .ok_or_else(|| Refusal::new(receipt::CLAUSE_SIGNATURE, "receipt is not an object"))?
            .clone();
        m.remove("sig");
        serde_json::Value::Object(m)
    };
    let signed_bytes = receipt::canon(&body)?;

    let parts = parse_sig(receipt_json.get("sig"), alg)?;

    receipt::verify_receipt(
        alg,
        bundle.min_suite,
        bundle.receipt_key,
        &signed_bytes,
        &parts,
        receipt_json
            .get("decision")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
    )?;

    // ------------------------------------------------------------ step 3
    // B-1a: hash the Proposal WE received. The field is compared, never used —
    // a transmitted identifier is a name for a binding, not evidence of one
    // (RES-9/TR-10).
    //
    // (9.3-3-proposal-binding mutation target: compare the field against
    // itself, or drop the comparison, and a receipt signed over one proposal
    // executes a different one — B-1a exactly as it was.)
    let proposal_hash = quorum::attestation_id(proposal_json)?;
    if receipt_json.get("proposal_hash").and_then(serde_json::Value::as_str)
        != Some(proposal_hash.as_str())
    {
        return Err(Refusal::new("9.3-3", "receipt not bound to this proposal"));
    }

    // ------------------------------------------------------------ step 4
    // The policy basis. Both halves refuse under 9.3-4: a receipt issued
    // against a different bundle and one issued against a different epoch of
    // the same bundle are the same failure — the Executor and the issuer do not
    // hold the same policy.
    //
    // (9.3-4-policy-basis mutation target: drop the bundle-hash comparison and
    // a receipt issued under a bundle trusting DIFFERENT attester keys is
    // accepted — PB-KEY, which is why the registry is inside the hash.)
    if receipt_json.get("policy_bundle_hash").and_then(serde_json::Value::as_str)
        != Some(bundle.policy_bundle_hash)
    {
        return Err(Refusal::new("9.3-4", "policy bundle hash mismatch"));
    }
    if receipt_json.get("bundle_epoch").and_then(serde_json::Value::as_u64) != Some(bundle.epoch) {
        return Err(Refusal::new("9.3-4", "bundle epoch mismatch"));
    }
    // NOT the epoch high-water mark. That is RAD-3 and it is ledger state:
    // a mark held per process starts at zero on a fresh replica, so a second
    // Executor accepts a superseded bundle with no restart at all (DP-40).
    // Named in UNIMPLEMENTED_STEPS rather than approximated here.

    // ------------------------------------------------------------ step 5
    let iat = receipt_json.get("issued_at").and_then(serde_json::Value::as_f64);
    let exp = receipt_json.get("expires_at").and_then(serde_json::Value::as_f64);
    let (Some(iat), Some(exp)) = (iat, exp) else {
        return Err(Refusal::new("9.3-5", "missing temporal fields"));
    };
    if now > exp {
        return Err(Refusal::new("9.3-5", "receipt expired"));
    }
    if iat > now + CLOCK_SKEW_SECS {
        return Err(Refusal::new("9.3-5", "issued in the future beyond skew"));
    }
    // L-14 is a SEPARATE clause from 9.3-5 and refuses under its own name. The
    // window length is not a position check: a receipt whose window is legal
    // today but 10x too long is an attacker widening the interval in which a
    // stolen receipt is usable (Y2), and calling that "expired" would tell an
    // operator the wrong thing.
    //
    // (l14-window-ceiling mutation target: delete this and Y2 succeeds — a
    // receipt with an hour-long validity window is consumed as fresh.)
    if exp - iat > MAX_VALIDITY_WINDOW_SECS {
        return Err(Refusal::new(
            "L-14",
            format!("validity window {}s exceeds {MAX_VALIDITY_WINDOW_SECS}s", exp - iat),
        ));
    }

    // step 6 — CL-2 nonce single-use — is ACP-46. See UNIMPLEMENTED_STEPS.

    // ------------------------------------------------------------ step 7
    // TR-8. Every value below is derived from the signed bundle and the
    // canonical Proposal; the receipt's own claims are COMPARED and never used.
    // X1 is what happens when they are used: an issuer asserting `LOW`
    // suppressed attestation entirely.
    let risk = grade_floor_risk(typed_proposal, bundle.policy)?;
    if let Some(claimed) = receipt_json.get("risk_level_floor_only").and_then(serde_json::Value::as_str) {
        if claimed != risk_wire(risk) {
            return Err(Refusal::new(
                "TR-8",
                format!("receipt claims risk {claimed}, recomputed {}", risk_wire(risk)),
            ));
        }
    }

    let fidelity = recompute_fidelity(typed_proposal, bundle.policy)?;
    if let Some(claimed) = receipt_json.get("fidelity").and_then(serde_json::Value::as_str) {
        if claimed != fidelity {
            return Err(Refusal::new(
                "TR-8",
                "receipt fidelity disagrees with adapter binding",
            ));
        }
    }

    let reversibility = recompute_reversibility(typed_proposal, bundle.policy);
    if let Some(claimed) = receipt_json.get("reversibility").and_then(serde_json::Value::as_str) {
        if claimed != rev_wire(reversibility) {
            return Err(Refusal::new(
                "RV-3",
                "receipt asserts a different reversibility class",
            ));
        }
    }

    // ----------------------------------------------------------- step 7b
    let operator = if risk == Risk::High {
        let entries = parse_attestations(receipt_json.get("attestations"))?;
        let policy = QuorumPolicy {
            quorum_k: bundle.quorum_k,
            attesters: bundle.attesters,
            floor: bundle.min_suite,
        };
        let basis = DecisionBasis {
            proposal_hash: &proposal_hash,
            policy_bundle_hash: bundle.policy_bundle_hash,
            bundle_epoch: bundle.epoch,
            risk,
            receipt_issued_at: iat,
        };
        quorum::verify_quorum(&policy, &basis, &entries)?
    } else {
        // Residual 1. Below floor-HIGH there is no quorum, so this is the
        // receipt's own field. Signature-covered, but attested by nobody.
        receipt_json
            .get("operator")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned()
    };

    // ------------------------------------------------------------ step 8
    // Tenant scoping compares the receipt against the PROPOSAL, which the
    // verifier received independently — not against a tenant the receipt also
    // supplies. Both sides of a binding must come from artifacts the verifier
    // trusts separately, or the comparison proves only that the issuer is
    // self-consistent.
    //
    // (9.3-8-tenant-scoping mutation target: delete this and a receipt minted
    // for tenant A consumes a Proposal belonging to tenant B.)
    if receipt_json.get("tenant_id") != proposal_json.get("tenant_id") {
        return Err(Refusal::new("9.3-8", "tenant mismatch"));
    }

    // step 9 — the live capability recheck — needs the Context Store.
    // step 10 — DS-6 delivery identity — is ledger state.

    // ------------------------------------------------------------- DR-13
    // Notice BEFORE execution, for AU-7's reason: a record written after the
    // action can be suppressed by whatever the action enabled, and detection
    // that can be erased is not detection. Computing the recipients is what
    // this crate can do; writing the record is ledger state.
    let notice = notice_recipients(typed_proposal, bundle.policy, risk, reversibility)?
        .cloned();

    Ok(Outcome {
        risk,
        operator,
        reversibility,
        fidelity,
        notice_recipients: notice,
        // DR-1 scopes the gate to floor-HIGH. Reported, never acted on here.
        deferred: risk == Risk::High,
    })
}

/// TR-8 for the adapter binding: `schema_id` -> fidelity class.
///
/// Shares [`crate::build_env`]'s rule and its refusal, because a `schema_id`
/// bound to no registered adapter must fail the same way whether it is being
/// read into the EL-1 environment or compared against a receipt's claim. Two
/// spellings of one rule is how the two diverge.
fn recompute_fidelity(p: &Proposal, pol: &Policy<'_>) -> Result<String, Refusal> {
    let sid = p.schema_id.as_deref().unwrap_or("");
    pol.adapters
        .get(sid)
        .cloned()
        .ok_or_else(|| Refusal::new("TR-8", "schema_id not bound to a registered adapter"))
}

/// Parse a wire `sig` object into the parts the CR-3 combiner verifies.
///
/// # The key set must be EXACTLY the suite's, and that is a control
///
/// The reference spells it `set(sig.keys()) != required`. Three distinct
/// attacks live in the difference, and each is a conformance case:
///
/// - a **scalar** `sig` (CR-2 legacy format) — format confusion is a downgrade
///   in disguise, so a bare string is refused rather than coerced;
/// - a **missing** primitive (CR-3 stripped leg) — caught downstream by the
///   conjunctive combiner too, but caught here first and for the right reason;
/// - an **extra, undeclared** primitive — a verifier that only checks "every
///   declared primitive verifies" accepts it, and an accepted extra primitive
///   is an undeclared code path the attacker chose.
///
/// The unknown-name case cannot even be represented downstream: [`Primitive`]
/// has no variant for `"experimental"`. Refusing it here rather than dropping
/// it is the same rule — a dropped part would let a suite be satisfied by the
/// parts that remain.
///
/// (cr3-sig-key-set mutation target: accept any superset of the required
/// primitives and `a_CR3_extra_primitive` succeeds.)
fn parse_sig(sig: Option<&serde_json::Value>, alg: &str) -> Result<Vec<SignaturePart>, Refusal> {
    // CR-1 first, for the reason receipt.rs gives: an unparseable suite has no
    // primitive set at all, so asking which primitives it requires would be a
    // category error rather than a refusal.
    let suite = receipt::parse_suite(alg)?;

    let Some(map) = sig.and_then(serde_json::Value::as_object) else {
        return Err(Refusal::new(
            receipt::CLAUSE_SIGNATURE,
            "receipt signature is not a per-primitive object",
        ));
    };

    let required: Vec<Primitive> = suite.primitives().to_vec();
    if map.len() != required.len() || !required.iter().all(|p| map.contains_key(prim_wire(*p))) {
        return Err(Refusal::new(
            receipt::CLAUSE_SIGNATURE,
            "signature primitives are not exactly those the declared suite requires",
        ));
    }

    let mut parts = Vec::with_capacity(required.len());
    for primitive in required {
        let hex = map
            .get(prim_wire(primitive))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Refusal::new(receipt::CLAUSE_SIGNATURE, "signature value is not a hex string")
            })?;
        parts.push(SignaturePart { primitive, bytes: unhex(hex)? });
    }
    Ok(parts)
}

/// Parse the presented attestations. Shape errors refuse under AT-8b, the
/// closed-object clause, because a malformed entry is an encoding the schema
/// does not permit rather than a failed check.
fn parse_attestations(v: Option<&serde_json::Value>) -> Result<Vec<AttestationEntry>, Refusal> {
    let Some(list) = v.and_then(serde_json::Value::as_array) else {
        // An absent list is not malformed — it is a floor-HIGH decision with no
        // attestations, which verify_quorum refuses under INV-1-HIGH. Reporting
        // AT-8b here would name the wrong rule.
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(list.len());
    for e in list {
        let obj = e
            .get("obj")
            .ok_or_else(|| Refusal::new("AT-8b", "attestation entry carries no object"))?
            .clone();
        let alg = obj
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Refusal::new("AT-8b", "attestation object declares no suite"))?;
        out.push(AttestationEntry {
            sig: parse_sig(e.get("sig"), alg).map_err(|r| {
                // An attestation's signature refuses under the ATTESTATION
                // clause, not the receipt's. Same shape, different step.
                if r.clause == receipt::CLAUSE_SIGNATURE {
                    Refusal::new("9.3-7b-i", r.message)
                } else {
                    r
                }
            })?,
            kind: e
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned(),
            attester: e
                .get("attester")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Refusal::new("AT-8b", "attestation entry names no attester"))?
                .to_owned(),
            attestation_id: e
                .get("attestation_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            obj,
        });
    }
    Ok(out)
}

fn prim_wire(p: Primitive) -> &'static str {
    match p {
        Primitive::Classical => "classical",
        Primitive::Pq => "pq",
        Primitive::PqSlh => "pq-slh",
    }
}

fn unhex(s: &str) -> Result<Vec<u8>, Refusal> {
    if s.len() % 2 != 0 {
        return Err(Refusal::new(receipt::CLAUSE_SIGNATURE, "signature hex has odd length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Refusal::new(receipt::CLAUSE_SIGNATURE, "signature is not hex"))
        })
        .collect()
}

/// The wire spellings. Written out rather than derived from `Debug`, because a
/// derive would make the comparison depend on a formatting trait nobody
/// considers a wire contract.
///
/// Public because the differential's driver needs them and the alternative was
/// `{:?}`. That is not a style preference: the first run of
/// `check-decision-differential.py` reported eight divergences that were
/// nothing but `HIGH` vs `High` — `Debug` on the generated enum. A harness
/// whose comparison depends on a formatting trait reports noise in the same
/// channel it reports findings, and the reader has to tell them apart by hand.
pub fn risk_wire(r: Risk) -> &'static str {
    match r {
        Risk::Low => "LOW",
        Risk::Medium => "MEDIUM",
        Risk::High => "HIGH",
    }
}

pub fn rev_wire(r: Reversibility) -> &'static str {
    match r {
        Reversibility::Reversible => "REVERSIBLE",
        Reversibility::Irreversible => "IRREVERSIBLE",
    }
}
