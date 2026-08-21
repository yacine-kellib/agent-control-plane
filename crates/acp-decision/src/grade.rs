//! The fold itself: §8.4 grading, RV-1, DR-13.

//! # Suite 12 classification — R / B / T
//!
//! | input | class | why |
//! | --- | :---: | --- |
//! | `p.task_type` | **B** | selects the risk function and the reversibility class; it is a field of the canonical Proposal the verifier received independently (B-1a), and `decide.rs` step 3 binds that Proposal to the receipt |
//! | `p.params`, `p.targets`, `p.cidrs`, `p.schema_id` | **B** | likewise — all of one artifact, bound as a whole |
//! | `floors`, `risk_functions`, `reversibility`, `notice_targets`, `adapters` | **R** | read from the signed bundle. Not "recomputed" in the arithmetic sense; recomputed in RES-8's sense — the verifier derives the value from policy it trusts instead of accepting the issuer's answer |
//! | the resulting risk, reversibility, fidelity, notice recipients | **R** | *derived here*. These are the values X1 and RV-3 exist because an Executor once read from the receipt instead |
//!
//! **No `T` entries, and this module is the reason there are none downstream.**
//! Every value it produces is one a compromised issuer would otherwise assert.
//! X1 is the concrete history: a receipt claiming `risk: LOW` suppressed
//! attestation entirely, because the Executor read the field.
//!
use acp_core::generated::{Reversibility, Risk};

use crate::{build_env, risk_of, risk_ord, Policy, Proposal, Refusal};

/// Recompute the **floor-only** risk grade (§8.4, TR-8).
///
/// "Floor-only" (TR-5) is not a simplification: Context-Store raises are
/// deliberately excluded, so the grade depends on signed policy and the
/// canonical Proposal alone. A Context Store that can raise the grade can also
/// decline to, and a control whose input the adversary supplies is not a
/// control.
///
/// # 8.4-3: an action with no risk function is REFUSED
///
/// Not graded HIGH. This is the rule most likely to be "helpfully" relaxed by
/// someone reading P-4 as "unknown is always the worst case", so it is worth
/// the sentence: grading HIGH routes an unknown action into the human quorum,
/// which looks conservative and is worse. It teaches approvers to rubber-stamp
/// things the policy author never considered (T-26 habituation, AT-7), and it
/// converts a policy gap into routine traffic instead of surfacing it.
///
/// # RK-3: the fold is a monotone `max`
///
/// Clauses can only ever raise. A `raise_to` whose `then` is *below* the
/// running level leaves it alone, so clause order cannot change the result and
/// a policy author cannot lower a grade by appending. That is what makes the
/// fold order-independent, which §8.3.1 also requires of evaluation itself.
///
/// (rk3-monotone-max mutation target: replace the `max` with assignment and a
/// later clause grading LOW starts lowering a grade an earlier clause raised.)
pub fn grade_floor_risk(p: &Proposal, pol: &Policy<'_>) -> Result<Risk, Refusal> {
    // 8.4-3 first, and BEFORE the environment is built. Building the
    // environment can itself refuse under TR-8, and an action with no risk
    // function must report 8.4-3 rather than whichever refusal the environment
    // happened to hit first -- the differential compares clause ids, and an
    // implementation that reports a true refusal for the wrong reason has not
    // been shown to agree with the reference.
    let rf = pol.risk_functions.get(&p.task_type).map_err(|a| {
        Refusal::new(
            "8.4-3",
            format!("no risk function for task_type {:?} ({})", p.task_type, a.table),
        )
    })?;

    let env = build_env(p, pol)?;

    let mut level = risk_ord(rf.base);
    for clause in &rf.raise_to {
        // A clause that does not parse is a REFUSAL, never a skipped clause.
        // Skipping is the permissive direction: a malformed `if` in signed
        // policy would silently stop being able to raise, and the grade would
        // come out at whatever the remaining clauses allow. EL-1 parse errors
        // carry clause 8.3.1 and are surfaced unchanged.
        let holds = acp_el1::evaluate(&clause.r#if, &env)
            .map_err(|e| Refusal::new("8.3.1", e.message))?;
        if holds {
            level = level.max(risk_ord(clause.then));
        }
    }
    Ok(risk_of(level))
}

/// Recompute reversibility from the signed bundle (RV-1, RV-3).
///
/// Never read from a receipt. RV-3: an issuer asserting `REVERSIBLE` otherwise
/// obtains Silent mode, which is X1's shape one field over. Proven in
/// `reference/proofs/binding.dfy` as `RV3_TrustedModeAcceptsDowngrade`.
///
/// The generated accessor already returns `IRREVERSIBLE` for an unclassified
/// action, so there is no `Option` here for a caller to `unwrap_or` into the
/// permissive value. `acp_executor.py` additionally validates the string
/// against the two legal classes and refuses under RV-1 if it is neither; that
/// check has no counterpart here **by construction**, because `Reversibility`
/// is a two-valued generated enum and an illegal class cannot be represented.
/// A positive-path obligation, not a control: it carries no mutant, because
/// there is no branch to delete.
pub fn recompute_reversibility(p: &Proposal, pol: &Policy<'_>) -> Reversibility {
    pol.reversibility.get(&p.task_type)
}

/// DR-13: who must be told before an IRREVERSIBLE action runs BELOW floor-HIGH.
///
/// Returns `Ok(None)` when no notice is owed, `Ok(Some(recipients))` when one
/// is, and `Err` when one is owed and the bundle names nobody.
///
/// # Why this rule exists at all
///
/// DR-1 scopes the deferred-release gate to floor-HIGH, so an IRREVERSIBLE
/// action graded below HIGH never reaches it. Until v1.3.15 that meant
/// reversibility was computed, compared against the receipt for RV-3, and then
/// **dropped** — RV-1's fail-safe default set a value nothing on this path
/// read, and an irreversible action on a T0/T1 target executed with no
/// notification, no acknowledgement, and no record that a human existed. Found
/// by `art_harness.py` case `fx-04` on its first run; the shape is mail
/// exfiltration.
///
/// It is also the repository's own example of *a fail-safe default that
/// changes no outcome is documentation, not a control*. This function is the
/// branch that reads it.
///
/// # Absent AND empty both refuse
///
/// The generated accessor refuses when the key is absent. This function must
/// **also** refuse when the key is present with an empty list — Python spells
/// both as `.get(...) or []` followed by `if not targets`. An implementation
/// that only handled the absent case would execute unwatched whenever a bundle
/// carried `"task": []`, which is the easier mistake to make and the one a
/// generated `Result` does not prevent.
///
/// (dr13-empty-recipients mutation target: drop the `is_empty` check and a
/// bundle naming an empty recipient list starts executing unwatched.)
///
/// # No acknowledgement is required here, deliberately
///
/// DR-9's friction is affordable at floor-HIGH because a human quorum has
/// already been paid for. Below HIGH there is no quorum and the traffic is the
/// bulk of the deployment, so requiring acknowledgement would page a human for
/// routine work at volume — T-26 habituation and AT-7 rubber-stamping, which
/// W2 already showed is what saturation produces. Detection instead of
/// prevention, and weaker on purpose.
pub fn notice_recipients<'a>(
    p: &Proposal,
    pol: &'a Policy<'a>,
    risk: Risk,
    reversibility: Reversibility,
) -> Result<Option<&'a Vec<String>>, Refusal> {
    if risk == Risk::High || reversibility == Reversibility::Reversible {
        return Ok(None);
    }

    let targets = pol.notice_targets.get(&p.task_type).map_err(|_| {
        Refusal::new(
            "DR-13",
            format!(
                "{} is IRREVERSIBLE at risk {risk:?} and the bundle names no \
                 notice recipients for it",
                p.task_type
            ),
        )
    })?;

    if targets.is_empty() {
        return Err(Refusal::new(
            "DR-13",
            format!(
                "{} is IRREVERSIBLE at risk {risk:?} and its notice_targets \
                 entry is empty, which is not a detection channel",
                p.task_type
            ),
        ));
    }
    Ok(Some(targets))
}
