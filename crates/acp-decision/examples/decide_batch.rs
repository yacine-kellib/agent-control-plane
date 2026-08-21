//! Batch driver for `tools/check-decision-differential.py`.
//!
//! Reads a JSON array of cases on argv[1], runs [`acp_decision::decide`] on
//! each, and prints one line per case. The line protocol is the comparison
//! surface, so it is deliberately narrow:
//!
//! ```text
//! PASSED\t<risk>\t<operator>
//! REFUSED\t<clause>
//! ```
//!
//! **`REFUSED` carries the clause and nothing else.** The message is not on the
//! wire because the differential must compare *which rule fired*, and a
//! comparison that included prose would go red on a reworded message while
//! staying green on a genuinely wrong clause — precisely inverted.
//!
//! An example rather than a bin: this is test machinery, and a `[[bin]]` would
//! ship it in any build of the crate.

use std::collections::BTreeMap;

use acp_core::generated::{Floors, NoticeTargets, ReversibilityTable, RiskFunctions, SuiteId};
use acp_decision::decide::{decide, risk_wire, BundleView};
use acp_decision::quorum::AttesterKey;
use acp_decision::receipt::ReceiptKey;
use acp_decision::{Policy, Proposal};

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    now: f64,
    receipt: serde_json::Value,
    proposal: serde_json::Value,
    bundle: WireBundle,
}

/// The verifier's own copy of the bundle, as the harness serialises it.
///
/// Note what is NOT here: nothing the receipt supplies. The harness builds this
/// from the Python `Bundle` object the reference Executor itself holds, so both
/// implementations are answering about the same policy — which is the only way
/// a divergence can mean something about the code rather than about the input.
#[derive(serde::Deserialize)]
struct WireBundle {
    epoch: u64,
    quorum_k: u64,
    min_suite: String,
    policy_bundle_hash: String,
    floors: Floors,
    risk_functions: RiskFunctions,
    reversibility: ReversibilityTable,
    notice_targets: NoticeTargets,
    adapters: BTreeMap<String, String>,
    attesters: BTreeMap<String, WireKey>,
    receipt_key: WireKey,
}

#[derive(serde::Deserialize)]
struct WireKey {
    classical: String,
    pq: String,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture key is hex"))
        .collect()
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: decide_batch <cases.json>");
    let raw = std::fs::read_to_string(&path).expect("cases file");
    let cases: Vec<Case> = serde_json::from_str(&raw).expect("cases json");

    for case in cases {
        let b = &case.bundle;

        // An unknown floor suite is a FIXTURE error, not a decision outcome:
        // the floor comes from the signed manifest, so a bundle naming a suite
        // this build does not know is a bundle that should never have loaded.
        // Panicking is right — reporting it as a refusal would let a broken
        // fixture masquerade as agreement.
        let min_suite: SuiteId = serde_json::from_value(serde_json::Value::String(
            b.min_suite.clone(),
        ))
        .unwrap_or_else(|_| panic!("{}: bundle floor {:?} is not a known suite", case.name, b.min_suite));

        let attesters: BTreeMap<String, AttesterKey> = b
            .attesters
            .iter()
            .map(|(k, v)| {
                (k.clone(), AttesterKey { classical: unhex(&v.classical), pq: unhex(&v.pq) })
            })
            .collect();

        let mut classical = [0u8; 32];
        classical.copy_from_slice(&unhex(&b.receipt_key.classical));
        let receipt_key = ReceiptKey { classical, pq: unhex(&b.receipt_key.pq) };

        let policy = Policy {
            floors: &b.floors,
            risk_functions: &b.risk_functions,
            reversibility: &b.reversibility,
            notice_targets: &b.notice_targets,
            adapters: &b.adapters,
        };
        let view = BundleView {
            epoch: b.epoch,
            quorum_k: b.quorum_k,
            min_suite,
            policy_bundle_hash: &b.policy_bundle_hash,
            policy: &policy,
            attesters: &attesters,
            receipt_key: &receipt_key,
        };

        // The Proposal is deserialised into the typed form HERE rather than by
        // the harness, because that deserialisation IS a control: §8.3.1's
        // parameter domain is enforced by `ParamValue`'s visitor, and a float
        // parameter must refuse under 8.3.1 rather than never reaching the
        // grader. Doing it in the harness would move a refusal out of the
        // implementation under test.
        let typed: Result<Proposal, _> = serde_json::from_value(case.proposal.clone());
        let line = match typed {
            Err(_) => format!("REFUSED\t{}", acp_decision::PARAM_DOMAIN_CLAUSE),
            Ok(typed) => match decide(&case.receipt, &case.proposal, &typed, &view, case.now) {
                // `o.deferred` is NOT on the wire. It states that DR-1 would
                // hand this to the gate; the reference states whether a gate
                // was configured. Two different facts, and comparing them
                // reported a divergence where §9.3 had agreed exactly.
                Ok(o) => format!("PASSED\t{}\t{}", risk_wire(o.risk), o.operator),
                Err(r) => format!("REFUSED\t{}", r.clause),
            },
        };
        println!("{}\t{}", case.name, line);
    }
}
