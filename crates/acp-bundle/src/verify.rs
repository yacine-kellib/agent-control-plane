//! Verify-on-read, and the rule the module is named for:
//!
//! **Trust a value read from the bundle about the bundle — never, until the
//! signature over those exact bytes has checked.**
//!
//! # Why not verify at load
//!
//! A bundle verified once at startup and trusted thereafter fails the moment
//! anything behind it is compromised — the store, the filesystem, the process
//! that unpacked it. The value of a signature is that it is checked *at the
//! point the value is used*, not at the point the bytes were fetched. So
//! [`BundleHost::read`] re-verifies on **every** read, and
//! `a_member_edited_after_activation_is_refused_on_the_next_read` is what says
//! that sentence is true rather than aspirational.
//!
//! That is a deliberate cost. It is also why `acp-crypto` verifies in Rust: the
//! §9.7 latency budget has to absorb one hybrid verification per read, and that
//! budget must be **re-measured** rather than assumed.
//!
//! # The order of operations is the security property
//!
//! Every check below reads its inputs from the signed member bytes, and reads
//! them **after** the signature has verified. Getting that backwards is the
//! whole defect: a verifier that parses `expires_at` before checking the
//! signature is asking an attacker when the attacker's bundle expires.
//! `a_forged_bundle_with_a_generous_expiry_is_refused_for_the_signature` pins
//! the ordering, because the two failure modes are indistinguishable from the
//! outside unless something asserts which one fired.
//!
//! Two values deliberately do **not** come from the bundle at all, and are
//! carried in [`VerifierConfig`] because they were established out-of-band:
//!
//! - the **signing key**, because a bundle vouching for its own key is a
//!   self-signed assertion wearing a registry's clothes; and
//! - the **suite floor** (CR-4), because a floor a bundle can lower is not a
//!   floor.
//!
//! `manifest.custody` is read by nothing here. The schema classifies it **T**
//! and says a verifier MUST NOT weight any decision on it — a compromised
//! signer writes that object freely. Custody strength lives in
//! `acp_crypto::custody::TrustedKeys`, on the verifier's side of the boundary.
//!
//! `manifest.min_suite` is likewise **not** read as this bundle's own floor,
//! and that is worth stating because wiring it in looks like an improvement.
//! It floors the suites of downstream receipts and attestations; the floor the
//! bundle itself must clear is [`VerifierConfig::suite_floor`]. A bundle
//! naming the floor it will be judged against is the RES-8 defect with the
//! serial numbers filed off.
//!
//! # Why the fields are promoted one at a time (ACP-44)
//!
//! Every value this file reads out of a signed member goes through
//! [`promoted`], which deserialises **one named field** into the type
//! `spec/schemas/bundle/` declares for it. Nothing here coerces with
//! `as_str`/`as_u64`/`as_object`: an accessor's return type is a choice made at
//! the call site, and a choice made at the call site is a second definition of
//! a field the specification already types. `quorum_k` is the case that proves
//! it — `as_i64()` refused every threshold above 2^63 as `QuorumInvalid`, which
//! is the accessor's range showing through and not PB-6.
//!
//! It is promotion **per field** rather than one `RawManifest` /
//! `RawAttesterRegistry` deserialise, and that is not a stylistic preference:
//!
//! 1. A whole-document parse collapses every distinct absence into one parse
//!    error. These refusals are distinguishable **by design** — an absent
//!    `quorum_k` is [`Refusal::QuorumInvalid`] and *not* `Malformed`, and
//!    `tools/check-bundle-differential.py` asserts the refusal NAME.
//! 2. It would refuse documents this verifier accepts today, over fields no
//!    verifier reads. `serde` fails the whole struct on any wrongly-typed
//!    member, so a numeric `author.display_name`, a numeric attester `role`, or
//!    a `custody` leg written as a string — which is what every fixture in this
//!    repository writes — would each become a refusal. `custody` is the sharp
//!    one: the schema classifies it **T**, this module reads nothing from it,
//!    and a strict parse would let a compromised signer's malformed `custody`
//!    decide the verdict.
//! 3. The Python reference is lenient in exactly the same places and must not
//!    be edited to match. Tightening one side alone is not a fix, it is a
//!    divergence — and the differential is the thing that would find it.
//!
//! The generated types are still the authority on **which** type each field
//! has: `the_promoted_field_types_are_the_ones_codegen_declares` compares every
//! promotion against `RawManifest` / `RawAttesterRegistry` field by field, so a
//! schema that retypes `bundle_epoch` stops this crate COMPILING rather than
//! letting a hand-picked type drift away from the spec in silence.

use crate::tree::{Member, Tree};
use acp_core::BundleEpoch;
use acp_crypto::{
    Primitive, PrimitiveVerdict, Suite, VerifyingKeys, verify_ed25519, verify_hybrid,
    verify_mldsa65,
};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Why a bundle was refused.
///
/// Distinct variants rather than one `Invalid`, because the reference and this
/// implementation must agree on **which** refusal fires (ACP-39's acceptance),
/// and because an operator paged at 03:00 needs to know whether the bundle is
/// forged, stale, or simply older than the one already running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// PB-1. The signature does not check over these bytes, under the declared
    /// suite, conjunctively.
    SignatureInvalid,
    /// CR-4. The declared suite does not contain every primitive the
    /// out-of-band floor requires.
    SuiteBelowFloor,
    /// PB-1. Past `expires_at`, and past the configured grace window too.
    Expired,
    /// PB-5. The candidate epoch does not strictly exceed the high-water mark.
    EpochRollback,
    /// PB-2. Author and reviewer are the same identity.
    AuthorIsReviewer,
    /// PB-7. Two attester identities carry the same verification key.
    RegistryKeysNotDistinct,
    /// PB-6. `quorum_k` is absent, or not an integer ≥ 1.
    QuorumInvalid,
    /// The bundle is not shaped like a bundle. Static strings only: a refusal
    /// reason is written to logs, and attacker-controlled bytes do not belong
    /// there.
    Malformed(&'static str),
    /// No bundle is active. PB-1: the engine refuses to serve without one.
    NoActiveBundle,
}

/// Whether a served value may back a full Decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serving {
    Normal,
    /// PB-1's grace window: past expiry but inside it. The bundle is still
    /// served and **every Decision is capped at ATTEST**.
    ///
    /// Capping rather than refusing is the point of the window: an expired
    /// bundle in a running control plane is an operational emergency either
    /// way, and a hard stop converts a policy-refresh failure into an outage
    /// while a silent full-strength extension converts it into nothing at all.
    /// The cap is what makes the window safe to configure.
    CappedAtAttest,
}

/// One verified read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading<'a> {
    pub bytes: &'a [u8],
    pub serving: Serving,
}

/// What the verifier was told out-of-band, before any bundle existed.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// The bundle signing key. **Not read from the bundle** (PB-4: no runtime
    /// component holds a key that can produce this signature, so no runtime
    /// component gets to nominate one either).
    pub signing_key: VerifyingKeys,
    /// CR-4 floor. The declared suite must contain every primitive this names.
    pub suite_floor: Suite,
    /// PB-1 grace window, in seconds. Zero means no window.
    pub grace_seconds: u64,
}

/// A signature as it arrives beside a bundle: one part per primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSignature {
    pub parts: Vec<(Primitive, Vec<u8>)>,
}

/// The bundle a host is currently serving, held with the bytes its signature
/// covers.
struct ActiveBundle {
    members: Vec<(String, Vec<u8>)>,
    suite: Suite,
    signature: BundleSignature,
    epoch: BundleEpoch,
}

/// Holds **exactly one** active bundle (PB-3) and a durable epoch high-water
/// mark (PB-5, CL-4).
pub struct BundleHost {
    config: VerifierConfig,
    active: Option<ActiveBundle>,
    high_water: Option<BundleEpoch>,
}

impl BundleHost {
    pub fn new(config: VerifierConfig) -> Self {
        BundleHost {
            config,
            active: None,
            high_water: None,
        }
    }

    /// Restore a host with a persisted high-water mark and no active bundle.
    ///
    /// This is the restart path, and it is why [`Self::high_water`] and
    /// [`Self::active_epoch`] are separate values rather than one. The mark is
    /// **durable** (CL-4); the active bundle is not. A process that came back up
    /// holding the mark but not yet a bundle must still refuse a rollback, and
    /// deriving the mark from whatever is currently serving would lose exactly
    /// that — an attacker would only have to catch the host between a restart
    /// and its first activation.
    pub fn restore(config: VerifierConfig, high_water: BundleEpoch) -> Self {
        BundleHost {
            config,
            active: None,
            high_water: Some(high_water),
        }
    }

    /// The highest epoch this host has ever activated.
    ///
    /// Retained **indefinitely** (CL-4). An expiring high-water mark reopens
    /// rollback, which is why this outlives nonce retention and is not swept
    /// with it.
    pub fn high_water(&self) -> Option<BundleEpoch> {
        self.high_water
    }

    /// The epoch of the bundle currently serving, if one is.
    ///
    /// Equal to [`Self::high_water`] whenever a bundle is active, because
    /// activation is the only thing that moves the mark. Not *derived* from it:
    /// see [`Self::restore`] for the state where the two differ.
    pub fn active_epoch(&self) -> Option<BundleEpoch> {
        self.active.as_ref().map(|a| a.epoch)
    }

    /// Activate a candidate bundle. **Atomic** (PB-3): either every check
    /// passes and the new bundle becomes the only active one, or nothing
    /// changes and whatever was serving keeps serving.
    ///
    /// Written as "validate fully, then assign" for that reason. Mutating
    /// `self.active` first and rolling back on error is the same logic with a
    /// window in which a rejected bundle is live.
    pub fn activate(
        &mut self,
        members: Vec<(String, Vec<u8>)>,
        suite: Suite,
        signature: BundleSignature,
        now: Timestamp,
    ) -> Result<(), Refusal> {
        let candidate = ActiveBundle {
            members,
            suite,
            signature,
            // Provisional. The real value is read below, from bytes whose
            // signature has checked; this exists only so the struct can be
            // formed before verification.
            epoch: BundleEpoch::new(0),
        };

        // Signature FIRST. Everything after this reads verified bytes.
        candidate.check_signature(&self.config)?;

        let manifest = candidate.manifest()?;
        let epoch = read_epoch(&manifest)?;
        check_two_person_integrity(&manifest)?;
        candidate.check_registry()?;

        // PB-5. Strictly greater, via BundleEpoch::accepts -- the type has no
        // `Ord`, deliberately, so `>=` is not reachable by a slip of the
        // keyboard. Re-serving the current epoch is how a rollback is dressed
        // up as a no-op.
        if let Some(hw) = self.high_water
            && !hw.accepts(epoch)
        {
            return Err(Refusal::EpochRollback);
        }

        // Serve-time freshness is checked on READ, not here, so a bundle
        // activated before expiry cannot keep serving forever. This call is
        // only to refuse activating something already dead on arrival.
        let expiry = read_expiry(&manifest)?;
        if serving_at(expiry, now, self.config.grace_seconds).is_none() {
            return Err(Refusal::Expired);
        }

        self.high_water = Some(epoch);
        self.active = Some(ActiveBundle { epoch, ..candidate });
        Ok(())
    }

    /// Read one member, **re-verifying the whole bundle first**.
    ///
    /// The signature is checked here rather than remembered from
    /// [`Self::activate`], because a signature checked once and trusted
    /// afterwards protects the bytes as they were at load, not the bytes being
    /// returned now.
    pub fn read(&self, path: &str, now: Timestamp) -> Result<Reading<'_>, Refusal> {
        let active = self.active.as_ref().ok_or(Refusal::NoActiveBundle)?;

        active.check_signature(&self.config)?;

        let manifest = active.manifest()?;
        let expiry = read_expiry(&manifest)?;
        let serving = serving_at(expiry, now, self.config.grace_seconds).ok_or(Refusal::Expired)?;

        let bytes = active
            .members
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, b)| b.as_slice())
            .ok_or(Refusal::Malformed("no such member in the bundle"))?;

        Ok(Reading { bytes, serving })
    }
}

impl ActiveBundle {
    /// Recompute the tree hash from the CURRENT bytes and check the signature
    /// over it, conjunctively across the declared suite.
    ///
    /// Recomputed, never remembered: a stored hash is a claim about bytes that
    /// may since have changed, and the whole point of reading here is to catch
    /// exactly that.
    fn check_signature(&self, config: &VerifierConfig) -> Result<(), Refusal> {
        // CR-4 before anything else. A suite that does not meet the floor is
        // refused even if its signature is impeccable -- the floor exists to
        // rule out primitives, not forgeries.
        if !self.suite.satisfies_floor(config.suite_floor) {
            return Err(Refusal::SuiteBelowFloor);
        }

        let mut members = Vec::with_capacity(self.members.len());
        for (path, bytes) in &self.members {
            let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(bytes).into();
            members.push(
                Member::new(path.clone(), digest)
                    .map_err(|_| Refusal::Malformed("member path is not a safe relative path"))?,
            );
        }
        let tree = Tree::new(self.suite, members)
            .map_err(|_| Refusal::Malformed("member list is not a valid tree"))?;
        let hash = tree.hash();

        let mut verdicts = Vec::new();
        for (prim, sig) in &self.signature.parts {
            let verdict = match prim {
                Primitive::Classical => verify_ed25519(config.signing_key.classical(), &hash, sig),
                Primitive::Pq => verify_mldsa65(config.signing_key.pq(), &hash, sig),
                // Declared, not implemented. Unsupported rather than Invalid:
                // the refusal is about this build, not about the signature.
                Primitive::PqSlh => PrimitiveVerdict::Unsupported,
            };
            verdicts.push((*prim, verdict));
        }

        // Conjunctive over the DECLARED suite: the parts presented must be
        // exactly those the suite requires, and every one must verify. An
        // `any`-shaped check here is the CR-3 downgrade.
        verify_hybrid(self.suite, &verdicts).map_err(|_| Refusal::SignatureInvalid)
    }

    fn member(&self, path: &str) -> Option<&[u8]> {
        self.members
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, b)| b.as_slice())
    }

    fn manifest(&self) -> Result<serde_json::Value, Refusal> {
        let bytes = self
            .member("manifest.json")
            .ok_or(Refusal::Malformed("bundle has no manifest.json"))?;
        serde_json::from_slice(bytes).map_err(|_| Refusal::Malformed("manifest.json is not JSON"))
    }

    /// PB-7: attester verification keys must be pairwise distinct, compared
    /// **per leg** across identities.
    ///
    /// In the loader rather than in a schema, and the spec says why: JSON
    /// Schema's `uniqueItems` applies to arrays and there is no keyword for
    /// uniqueness across the values of a map. An implementation validating the
    /// registry by schema alone is non-conformant however cleanly it validates.
    ///
    /// # What this used to compare, and why it was wrong (ACP-53)
    ///
    /// Until this revision the loop compared **whole entries** for equality, so
    /// it fired only on byte-identical ones. `role` is part of an entry, so one
    /// key holder could enrol twice —
    ///
    /// ```text
    /// "alice": {"role": "approver",  "classical": K, "pq": K}
    /// "bob":   {"role": "confirmer", "classical": K, "pq": K}
    /// ```
    ///
    /// — and satisfy `quorum_k = 2` alone. That pairing is precisely what DR-9
    /// demands for an irreversible action at floor-HIGH, so the registry handed
    /// over the case the threshold exists to prevent. A role is not a
    /// verification key and must never distinguish two identities.
    ///
    /// **Either leg colliding is a collision, not both.** PB-7 says two
    /// identities differing in their classical key but *sharing* a post-quantum
    /// key are not distinct; requiring the pair to match is CR-3's conjunctive
    /// guarantee undone at the registry instead of at the verifier.
    ///
    /// The reference implementation is wrong in the same way and was corrected
    /// in the same commit — which is the point worth keeping. The differential
    /// agreed throughout, because agreement is evidence about consistency and
    /// never about correctness (§15). A deletion mutant would still have been
    /// killed, because the one shape the check did catch was the one the
    /// fixture built.
    fn check_registry(&self) -> Result<(), Refusal> {
        let bytes = self
            .member("attesters/registry.json")
            .ok_or(Refusal::Malformed("bundle has no attesters/registry.json"))?;
        let registry: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| Refusal::Malformed("attesters/registry.json is not JSON"))?;

        // PB-6. Absent or nonsensical is refused, never defaulted: a default
        // threshold is a threshold nobody chose, and the permissive default
        // (k=1) collapses INV-1-HIGH to single compromise.
        //
        // `u64` because that is the domain the schema declares for this field
        // (`integer, minimum 1`) and the type `RawAttesterRegistry::quorum_k`
        // carries. The `as_i64()` this replaced refused every threshold above
        // 2^63 as QuorumInvalid -- the accessor's range, not PB-6, and a live
        // divergence from the reference, whose integers are unbounded.
        match promoted::<u64>(&registry, &["quorum_k"]) {
            Some(k) if k >= 1 => {}
            _ => return Err(Refusal::QuorumInvalid),
        }

        // An open map of deployment-specific identities, so only its SHAPE is
        // promoted. The entries stay opaque, for the reason below.
        let attesters = promoted::<BTreeMap<String, serde_json::Value>>(&registry, &["attesters"])
            .ok_or(Refusal::Malformed(
                "attesters/registry.json has no attesters map",
            ))?;

        for leg in ["classical", "pq"] {
            let mut seen: Vec<serde_json::Value> = Vec::new();
            for entry in attesters.values() {
                // Promoted only as far as "this is an object". PB-7 asks
                // whether two identities carry the SAME key, never whether a
                // key is well formed, so the leg values are compared as opaque
                // JSON. Typing them `String` -- which is what
                // `RawAttester::classical` does -- would refuse registries the
                // reference accepts and compares, and a leg written `null`
                // would deserialise to `None` and be read as ABSENT when both
                // implementations treat it as present and colliding.
                //
                // Per entry INSIDE this loop, never as one pass over the whole
                // map: a collision at p1 must fire before a malformed p2 is
                // reached, because that is the order the reference refuses in.
                let legs: BTreeMap<String, serde_json::Value> = Deserialize::deserialize(entry)
                    .map_err(|_| Refusal::Malformed("an attester entry has no classical/pq key"))?;
                // A key that is absent cannot be shown distinct from anything.
                // Refusing is the only fail-safe reading.
                let key = legs.get(leg).ok_or(Refusal::Malformed(
                    "an attester entry has no classical/pq key",
                ))?;
                if seen.contains(key) {
                    return Err(Refusal::RegistryKeysNotDistinct);
                }
                seen.push(key.clone());
            }
        }
        Ok(())
    }
}

/// PB-2. Compared on `id`, never on `display_name`: two people can share a
/// display name, and two-person integrity compared on a mutable label is
/// one-person integrity with extra steps.
fn check_two_person_integrity(manifest: &serde_json::Value) -> Result<(), Refusal> {
    // `id` only. `display_name` is not promoted even though `RawIdentity`
    // types it, because a party whose display_name is the wrong type is not a
    // party this check has anything to say about -- and refusing there would
    // be a refusal invented by the type, on a field PB-2 forbids comparing.
    let id = |who: &str| -> Result<String, Refusal> {
        promoted::<String>(manifest, &[who, "id"]).ok_or(Refusal::Malformed(
            "manifest is missing an author or reviewer id",
        ))
    };
    if id("author")? == id("reviewer")? {
        return Err(Refusal::AuthorIsReviewer);
    }
    Ok(())
}

/// One named field of a signed document, promoted into the type
/// `spec/schemas/bundle/` declares for it.
///
/// The single point where this file touches an untyped JSON document, and it
/// is deliberately the only one. `T` is never chosen freely: every call passes
/// the type the generated projection carries for that field, and
/// `the_promoted_field_types_are_the_ones_codegen_declares` fails to COMPILE if
/// the schema and the call site ever disagree.
///
/// `None` covers every way a field can fail to be readable — the document is
/// not an object, the field is absent, or its value is the wrong type. The
/// three are deliberately not distinguished HERE: each caller names the refusal
/// its own clause requires, which is why an absent `quorum_k` is
/// [`Refusal::QuorumInvalid`] while an absent `bundle_epoch` is `Malformed`.
fn promoted<'a, T: Deserialize<'a>>(doc: &'a serde_json::Value, path: &[&str]) -> Option<T> {
    let mut cursor = doc;
    for name in path {
        cursor = cursor.get(name)?;
    }
    T::deserialize(cursor).ok()
}

fn read_epoch(manifest: &serde_json::Value) -> Result<BundleEpoch, Refusal> {
    // `u64`, the type the schema declares (`integer, minimum 0`). A negative
    // epoch is therefore not an epoch: PB-5 counts upward and a high-water mark
    // seeded below zero is a mark an attacker chose.
    promoted::<u64>(manifest, &["bundle_epoch"])
        .map(BundleEpoch::new)
        .ok_or(Refusal::Malformed("manifest has no integer bundle_epoch"))
}

fn read_expiry(manifest: &serde_json::Value) -> Result<Timestamp, Refusal> {
    let raw = promoted::<String>(manifest, &["expires_at"])
        .ok_or(Refusal::Malformed("manifest has no expires_at"))?;
    Timestamp::parse(&raw).ok_or(Refusal::Malformed("expires_at is not RFC 3339 UTC"))
}

/// `None` means refuse; `Some(serving)` says at what strength.
fn serving_at(expiry: Timestamp, now: Timestamp, grace_seconds: u64) -> Option<Serving> {
    if now.unix() <= expiry.unix() {
        return Some(Serving::Normal);
    }
    if now.unix() <= expiry.unix().saturating_add(grace_seconds as i64) {
        return Some(Serving::CappedAtAttest);
    }
    None
}

/// An RFC 3339 UTC instant, to one second.
///
/// A strict parser rather than a permissive one: exactly `YYYY-MM-DDTHH:MM:SSZ`
/// and nothing else. Offsets, fractional seconds and lowercase `z` are all
/// refused rather than normalised, because a permissive decoder silently
/// normalising two spellings into one value is the encoding-split defect that
/// `cbor_suite.py`'s eight cases exist for. Here it would decide when a bundle
/// stops being valid.
///
/// Comparison is on seconds since the Unix epoch rather than on the string, so
/// that the grace window can be added. Two well-formed UTC strings also compare
/// correctly lexicographically, and relying on that would work right up until
/// the first bundle written with an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 20
            || b[4] != b'-'
            || b[7] != b'-'
            || b[10] != b'T'
            || b[13] != b':'
            || b[16] != b':'
            || b[19] != b'Z'
        {
            return None;
        }
        let n = |from: usize, to: usize| -> Option<i64> {
            let part = s.get(from..to)?;
            if !part.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let (y, mo, d) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
        let (h, mi, sec) = (n(11, 13)?, n(14, 16)?, n(17, 19)?);
        // The day is checked against the ACTUAL length of that month, not
        // against 31. A range check alone let `2026-02-31` through, and
        // `days_from_civil` rolled it forward to the same instant as
        // `2026-03-03` — two spellings of one value, which is the encoding
        // split this parser's strictness exists to prevent.
        //
        // `sec` stops at 59: no leap second. The reference `datetime` refuses
        // 23:59:60, and a parser that accepts what the differential partner
        // rejects is a divergence waiting for the first bundle that hits it.
        if !(1..=12).contains(&mo)
            || d < 1
            || d > days_in_month(y, mo)
            || h > 23
            || mi > 59
            || sec > 59
        {
            return None;
        }
        Some(Timestamp(
            days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec,
        ))
    }

    pub fn unix(self) -> i64 {
        self.0
    }
}

/// How many days a month actually has.
///
/// The century rule is the part that gets written wrong: 2000 is a leap year
/// (divisible by 400) and 2100 is not (divisible by 100 but not 400). Both are
/// in the tests, because "divisible by four" passes every casual check for
/// seventy-five years at a time.
const fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
///
/// Howard Hinnant's `days_from_civil`, which is exact for every year in range
/// and avoids depending on a date crate for the one calculation this file
/// needs. Pinned by `the_epoch_conversion_matches_known_instants`, because a
/// leap-year rule that is subtly wrong shifts a bundle's expiry by a day and
/// nothing else in the system would notice.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp_crypto::{CustodyTier, Environment, KeyMaterial, OfflineSigner, Signer};

    const HYBRID: Suite = Suite::HybridEd25519MlDsa65;

    fn manifest(epoch: u64, expires: &str, author: &str, reviewer: &str) -> Vec<u8> {
        format!(
            r#"{{"schema_version":"1","bundle_epoch":{epoch},"created_at":"2026-01-01T00:00:00Z",
                 "author":{{"id":"{author}","display_name":"A"}},
                 "reviewer":{{"id":"{reviewer}","display_name":"R"}},
                 "expires_at":"{expires}","min_suite":"hybrid-ed25519-mldsa65",
                 "custody":{{"tier":"T3","classical":"x","pq":"y"}}}}"#
        )
        .into_bytes()
    }

    fn registry(k: u64, keys: &[&str]) -> Vec<u8> {
        let entries: Vec<(&str, &str, &str)> = keys.iter().map(|k| ("approver", *k, *k)).collect();
        registry_of(k, &entries)
    }

    /// A registry with per-entry control of `role`, `classical` and `pq`.
    ///
    /// The old helper set both legs from one string and emitted no `role` at
    /// all, which is why PB-7 looked covered: with those entries, sharing a key
    /// and being byte-identical were the same thing, so a whole-entry
    /// comparison passed the only test that existed (ACP-53). A fixture that
    /// cannot express the attack cannot test for it.
    fn registry_of(k: u64, entries: &[(&str, &str, &str)]) -> Vec<u8> {
        let entries: Vec<String> = entries
            .iter()
            .enumerate()
            .map(|(i, (role, classical, pq))| {
                format!(r#""person{i}":{{"role":"{role}","classical":"{classical}","pq":"{pq}"}}"#)
            })
            .collect();
        format!(
            r#"{{"schema_version":"1","quorum_k":{k},"attesters":{{{}}}}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    fn members(epoch: u64, expires: &str) -> Vec<(String, Vec<u8>)> {
        vec![
            (
                "manifest.json".into(),
                manifest(epoch, expires, "ana", "bo"),
            ),
            ("floors.json".into(), br#"{"payments":"T3"}"#.to_vec()),
            ("attesters/registry.json".into(), registry(2, &["ka", "kb"])),
        ]
    }

    /// A signer whose key the verifier is configured with, out-of-band.
    fn signing_key() -> KeyMaterial {
        KeyMaterial::from_seed(b"bundle-signing-key")
    }

    fn sign(members: &[(String, Vec<u8>)], suite: Suite, key: KeyMaterial) -> BundleSignature {
        let mut ms = Vec::new();
        for (path, bytes) in members {
            let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(bytes).into();
            ms.push(Member::new(path.clone(), digest).unwrap());
        }
        let hash = Tree::new(suite, ms).unwrap().hash();
        // T1 signs for production and wipes afterwards, which is why each call
        // gets its own signer.
        let signer = OfflineSigner::new(CustodyTier::T1, suite, key).unwrap();
        let sig = signer.sign(&hash, Environment::Production).unwrap();
        BundleSignature {
            parts: sig.parts().to_vec(),
        }
    }

    fn config(grace_seconds: u64) -> VerifierConfig {
        VerifierConfig {
            signing_key: signing_key().public().clone(),
            suite_floor: HYBRID,
            grace_seconds,
        }
    }

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).expect("test timestamp is well formed")
    }

    fn host_with(epoch: u64, expires: &str, now: &str) -> (BundleHost, Vec<(String, Vec<u8>)>) {
        let mut host = BundleHost::new(config(0));
        let m = members(epoch, expires);
        let sig = sign(&m, HYBRID, signing_key());
        host.activate(m.clone(), HYBRID, sig, ts(now)).unwrap();
        (host, m)
    }

    #[test]
    fn a_genuine_bundle_activates_and_reads() {
        let (host, _) = host_with(7, "2027-01-01T00:00:00Z", "2026-08-18T00:00:00Z");
        let r = host
            .read("floors.json", ts("2026-08-18T00:00:00Z"))
            .unwrap();
        assert_eq!(r.bytes, br#"{"payments":"T3"}"#);
        assert_eq!(r.serving, Serving::Normal);
    }

    #[test]
    fn a_member_edited_after_activation_is_refused_on_the_next_read() {
        // THE POINT OF THE MODULE. Verified at load and trusted afterwards,
        // this read returns the attacker's floors.json with a valid-looking
        // provenance. The bundle activated cleanly; the store behind it was
        // then compromised, which is the scenario a signature is for.
        let mut host = BundleHost::new(config(0));
        let m = members(7, "2027-01-01T00:00:00Z");
        let sig = sign(&m, HYBRID, signing_key());
        host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z"))
            .unwrap();

        assert!(
            host.read("floors.json", ts("2026-08-18T00:00:00Z")).is_ok(),
            "precondition: the untampered bundle reads"
        );

        // Payments demoted from the top tier to the bottom one.
        host.active.as_mut().unwrap().members[1].1 = br#"{"payments":"T1"}"#.to_vec();

        assert_eq!(
            host.read("floors.json", ts("2026-08-18T00:00:00Z")),
            Err(Refusal::SignatureInvalid),
            "an edited member was served because the signature was not rechecked"
        );
    }

    #[test]
    fn every_read_rechecks_not_just_the_first() {
        // A verifier that checked on first read and cached would pass the test
        // above and fail here.
        let mut host = BundleHost::new(config(0));
        let m = members(7, "2027-01-01T00:00:00Z");
        let sig = sign(&m, HYBRID, signing_key());
        host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z"))
            .unwrap();

        for _ in 0..3 {
            assert!(host.read("floors.json", ts("2026-08-18T00:00:00Z")).is_ok());
        }
        host.active.as_mut().unwrap().members[1].1 = b"{}".to_vec();
        assert_eq!(
            host.read("floors.json", ts("2026-08-18T00:00:00Z")),
            Err(Refusal::SignatureInvalid)
        );
    }

    #[test]
    fn a_forged_bundle_with_a_generous_expiry_is_refused_for_the_signature() {
        // ORDER OF OPERATIONS. The forged manifest says it is valid until 2099;
        // a verifier that parsed expiry before checking the signature would ask
        // the attacker when the attacker's bundle expires. The refusal must
        // name the signature, and the only way to know which check fired is to
        // assert on the variant.
        let mut host = BundleHost::new(config(0));
        let m = members(7, "2099-01-01T00:00:00Z");
        let forged = sign(&m, HYBRID, KeyMaterial::from_seed(b"not-the-bundle-key"));
        assert_eq!(
            host.activate(m, HYBRID, forged, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::SignatureInvalid)
        );
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let mut host = BundleHost::new(config(0));
        let m = members(7, "2027-01-01T00:00:00Z");
        let other = sign(&m, HYBRID, KeyMaterial::from_seed(b"someone-else"));
        assert_eq!(
            host.activate(m, HYBRID, other, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::SignatureInvalid)
        );
    }

    #[test]
    fn a_stripped_post_quantum_leg_is_refused() {
        // CR-3 at the bundle. The classical signature is genuine; only the
        // post-quantum leg is missing, which is the downgrade the hybrid suite
        // exists to prevent.
        let mut host = BundleHost::new(config(0));
        let m = members(7, "2027-01-01T00:00:00Z");
        let mut sig = sign(&m, HYBRID, signing_key());
        sig.parts.retain(|(p, _)| *p == Primitive::Classical);
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::SignatureInvalid)
        );
    }

    #[test]
    fn a_suite_below_the_configured_floor_is_refused() {
        // CR-4. The floor is in VerifierConfig, out-of-band, precisely so a
        // bundle cannot lower it.
        let mut host = BundleHost::new(config(0));
        let m = members(7, "2027-01-01T00:00:00Z");
        let sig = sign(&m, Suite::Ed25519, signing_key());
        assert_eq!(
            host.activate(m, Suite::Ed25519, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::SuiteBelowFloor)
        );
    }

    #[test]
    fn an_expired_bundle_is_refused_when_there_is_no_grace_window() {
        let mut host = BundleHost::new(config(0));
        let m = members(7, "2026-08-17T00:00:00Z");
        let sig = sign(&m, HYBRID, signing_key());
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::Expired)
        );
    }

    #[test]
    fn inside_the_grace_window_the_bundle_serves_capped_at_attest() {
        // PB-1's window: served, but every Decision capped at ATTEST. A window
        // that served at full strength would be an expiry that does nothing.
        let mut host = BundleHost::new(config(86_400));
        let m = members(7, "2026-08-18T00:00:00Z");
        let sig = sign(&m, HYBRID, signing_key());
        host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z"))
            .unwrap();

        let r = host
            .read("floors.json", ts("2026-08-18T06:00:00Z"))
            .unwrap();
        assert_eq!(r.serving, Serving::CappedAtAttest);
    }

    #[test]
    fn past_the_grace_window_the_read_is_refused() {
        let mut host = BundleHost::new(config(3600));
        let m = members(7, "2026-08-18T00:00:00Z");
        let sig = sign(&m, HYBRID, signing_key());
        host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z"))
            .unwrap();

        assert_eq!(
            host.read("floors.json", ts("2026-08-18T02:00:00Z")),
            Err(Refusal::Expired),
            "a bundle served past its grace window"
        );
    }

    #[test]
    fn expiry_is_enforced_on_read_not_only_at_activation() {
        // A bundle activated while fresh must stop serving when it expires.
        // Checking only at activation makes expiry a property of when the
        // process last restarted.
        let (host, _) = host_with(7, "2026-08-18T12:00:00Z", "2026-08-18T00:00:00Z");
        assert!(host.read("floors.json", ts("2026-08-18T11:00:00Z")).is_ok());
        assert_eq!(
            host.read("floors.json", ts("2026-08-19T00:00:00Z")),
            Err(Refusal::Expired)
        );
    }

    #[test]
    fn a_lower_epoch_is_refused_as_a_rollback() {
        // PB-5. The superseded bundle is GENUINE and internally consistent --
        // nothing inside it is wrong, which is why nothing inside it can catch
        // this. The durable high-water mark is the only thing in the way.
        let (mut host, _) = host_with(7, "2027-01-01T00:00:00Z", "2026-08-18T00:00:00Z");
        let older = members(6, "2027-01-01T00:00:00Z");
        let sig = sign(&older, HYBRID, signing_key());
        assert_eq!(
            host.activate(older, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::EpochRollback)
        );
    }

    #[test]
    fn re_serving_the_current_epoch_is_refused() {
        // Equal is refused, not accepted. A bundle whose CONTENT changed under
        // an unchanged epoch is exactly what PB-5 forbids, and `>=` would wave
        // it through -- which is why BundleEpoch has no Ord.
        let (mut host, _) = host_with(7, "2027-01-01T00:00:00Z", "2026-08-18T00:00:00Z");
        let mut same = members(7, "2027-01-01T00:00:00Z");
        same[1].1 = br#"{"payments":"T1"}"#.to_vec();
        let sig = sign(&same, HYBRID, signing_key());
        assert_eq!(
            host.activate(same, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::EpochRollback)
        );
    }

    #[test]
    fn a_higher_epoch_replaces_the_active_bundle() {
        let (mut host, _) = host_with(7, "2027-01-01T00:00:00Z", "2026-08-18T00:00:00Z");
        let newer = members(8, "2027-01-01T00:00:00Z");
        let sig = sign(&newer, HYBRID, signing_key());
        assert!(
            host.activate(newer, HYBRID, sig, ts("2026-08-18T00:00:00Z"))
                .is_ok()
        );
        assert_eq!(host.high_water(), Some(BundleEpoch::new(8)));
    }

    #[test]
    fn the_high_water_mark_survives_a_refused_activation() {
        // CL-4: retained indefinitely. If a refused candidate could lower or
        // clear the mark, an attacker would replay a rollback by first offering
        // something that fails.
        let (mut host, _) = host_with(7, "2027-01-01T00:00:00Z", "2026-08-18T00:00:00Z");
        let forged = members(9, "2027-01-01T00:00:00Z");
        let bad = sign(&forged, HYBRID, KeyMaterial::from_seed(b"someone-else"));
        assert!(
            host.activate(forged, HYBRID, bad, ts("2026-08-18T00:00:00Z"))
                .is_err()
        );
        assert_eq!(host.high_water(), Some(BundleEpoch::new(7)));
    }

    #[test]
    fn a_refused_activation_leaves_the_previous_bundle_serving() {
        // PB-3, the atomic half. A rejected candidate must not leave the host
        // with no bundle, or an attacker takes the control plane down by
        // offering something invalid.
        let (mut host, _) = host_with(7, "2027-01-01T00:00:00Z", "2026-08-18T00:00:00Z");
        let forged = members(8, "2027-01-01T00:00:00Z");
        let bad = sign(&forged, HYBRID, KeyMaterial::from_seed(b"someone-else"));
        let _ = host.activate(forged, HYBRID, bad, ts("2026-08-18T00:00:00Z"));

        let r = host
            .read("floors.json", ts("2026-08-18T00:00:00Z"))
            .expect("the previous bundle must still serve");
        assert_eq!(r.bytes, br#"{"payments":"T3"}"#);
    }

    #[test]
    fn a_restored_host_refuses_a_rollback_before_it_has_any_bundle() {
        // RAD-3, and the reason the mark is durable while the active bundle is
        // not. The window between a restart and the first activation is the
        // cheapest moment to serve a superseded bundle: nothing is active, so
        // a host deriving its mark from what is currently serving has no mark
        // at all and accepts anything genuine.
        let mut host = BundleHost::restore(config(0), BundleEpoch::new(7));
        assert_eq!(host.high_water(), Some(BundleEpoch::new(7)));
        assert_eq!(host.active_epoch(), None, "nothing is serving yet");

        let older = members(6, "2027-01-01T00:00:00Z");
        let sig = sign(&older, HYBRID, signing_key());
        assert_eq!(
            host.activate(older, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::EpochRollback)
        );
    }

    #[test]
    fn the_active_epoch_is_the_bundle_that_is_serving() {
        let (host, _) = host_with(7, "2027-01-01T00:00:00Z", "2026-08-18T00:00:00Z");
        assert_eq!(host.active_epoch(), Some(BundleEpoch::new(7)));
    }

    #[test]
    fn reading_without_an_active_bundle_is_refused() {
        let host = BundleHost::new(config(0));
        assert_eq!(
            host.read("floors.json", ts("2026-08-18T00:00:00Z")),
            Err(Refusal::NoActiveBundle)
        );
    }

    #[test]
    fn author_and_reviewer_must_differ() {
        // PB-2, compared on id. Two-person integrity is the control on the
        // highest-leverage artifact in the system.
        let mut host = BundleHost::new(config(0));
        let mut m = members(7, "2027-01-01T00:00:00Z");
        m[0].1 = manifest(7, "2027-01-01T00:00:00Z", "ana", "ana");
        let sig = sign(&m, HYBRID, signing_key());
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::AuthorIsReviewer)
        );
    }

    /// PB-7, all four shapes. The holder of one private key signs two objects
    /// differing only in their attestation nonces, labels them with two names,
    /// and satisfies k=2 alone -- INV-1-HIGH defeated by a single compromise,
    /// through the registry rather than through the threshold.
    ///
    /// Four cases rather than one because until ACP-53 only the first was
    /// tested, only the first was caught, and the other three were accepted by
    /// both implementations. The check compared whole entries; three of these
    /// differ somewhere in the entry while sharing a key.
    fn assert_registry_refused(entries: &[(&str, &str, &str)]) {
        let mut host = BundleHost::new(config(0));
        let mut m = members(7, "2027-01-01T00:00:00Z");
        m[2].1 = registry_of(2, entries);
        let sig = sign(&m, HYBRID, signing_key());
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::RegistryKeysNotDistinct)
        );
    }

    #[test]
    fn two_attesters_with_identical_entries_are_refused() {
        assert_registry_refused(&[("approver", "same", "same"), ("approver", "same", "same")]);
    }

    #[test]
    fn two_attesters_sharing_a_key_under_different_roles_are_refused() {
        // The attack ACP-53 names, and the worst of the four: approver plus
        // confirmer is exactly the pairing DR-9 requires for an irreversible
        // action at floor-HIGH. A role is not a verification key.
        assert_registry_refused(&[("approver", "same", "same"), ("confirmer", "same", "same")]);
    }

    #[test]
    fn two_attesters_sharing_only_the_post_quantum_key_are_refused() {
        // The case the old code comment claimed to handle and did not.
        assert_registry_refused(&[("approver", "ka", "shared"), ("approver", "kb", "shared")]);
    }

    #[test]
    fn two_attesters_sharing_only_the_classical_key_are_refused() {
        assert_registry_refused(&[("approver", "shared", "ka"), ("approver", "shared", "kb")]);
    }

    #[test]
    fn genuinely_distinct_attesters_are_accepted() {
        // Without this the four refusals above are satisfied by a check that
        // refuses everything, which is not a control either.
        let mut host = BundleHost::new(config(0));
        let mut m = members(7, "2027-01-01T00:00:00Z");
        m[2].1 = registry_of(2, &[("approver", "ka", "pa"), ("confirmer", "kb", "pb")]);
        let sig = sign(&m, HYBRID, signing_key());
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Ok(())
        );
    }

    #[test]
    fn an_attester_entry_with_no_verification_key_is_refused() {
        // A key that is absent cannot be shown distinct from anything.
        let mut host = BundleHost::new(config(0));
        let mut m = members(7, "2027-01-01T00:00:00Z");
        m[2].1 = br#"{"schema_version":"1","quorum_k":2,"attesters":{
            "alice":{"role":"approver","classical":"ka","pq":"pa"},
            "bob":{"role":"confirmer","classical":"kb"}}}"#
            .to_vec();
        let sig = sign(&m, HYBRID, signing_key());
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::Malformed(
                "an attester entry has no classical/pq key"
            ))
        );
    }

    #[test]
    fn an_absent_quorum_k_is_refused_rather_than_defaulted() {
        // PB-6. A default threshold is a threshold nobody chose, and the
        // permissive default collapses INV-1-HIGH to single compromise.
        let mut host = BundleHost::new(config(0));
        let mut m = members(7, "2027-01-01T00:00:00Z");
        m[2].1 = br#"{"schema_version":"1","attesters":{"a":{"classical":"x","pq":"x"}}}"#.to_vec();
        let sig = sign(&m, HYBRID, signing_key());
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::QuorumInvalid)
        );
    }

    #[test]
    fn a_zero_quorum_is_refused() {
        let mut host = BundleHost::new(config(0));
        let mut m = members(7, "2027-01-01T00:00:00Z");
        m[2].1 = registry(0, &["ka", "kb"]);
        let sig = sign(&m, HYBRID, signing_key());
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::QuorumInvalid)
        );
    }

    /// Activate a bundle whose manifest or registry is given VERBATIM.
    ///
    /// The shaped helpers above cannot express a malformed document, and a
    /// fixture that cannot express the attack cannot test for it — which is the
    /// lesson ACP-53 left behind.
    fn activate_raw(
        manifest_bytes: Option<&[u8]>,
        registry_bytes: Option<&[u8]>,
    ) -> Result<(), Refusal> {
        let mut host = BundleHost::new(config(0));
        let mut m = members(7, "2027-01-01T00:00:00Z");
        if let Some(b) = manifest_bytes {
            m[0].1 = b.to_vec();
        }
        if let Some(b) = registry_bytes {
            m[2].1 = b.to_vec();
        }
        let sig = sign(&m, HYBRID, signing_key());
        host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z"))
    }

    #[test]
    fn the_promoted_field_types_are_the_ones_codegen_declares() {
        // THE BINDING TO spec/schemas/bundle/. Every field verify.rs promotes
        // is compared against the generated projection's own type for it, so a
        // schema that retypes `bundle_epoch` breaks the BUILD here rather than
        // leaving a hand-picked `u64` drifting quietly away from the spec.
        //
        // The manifest below writes `custody` in its SCHEMA shape, unlike every
        // other fixture in this repository, because `RawManifest` cannot parse
        // the shape the fixtures use. That is the whole reason verify.rs
        // promotes per field instead of deserialising the document, and this
        // test is the one place the strict shape has to appear.
        use acp_core::generated::{RawAttesterRegistry, RawManifest};

        const M: &[u8] = br#"{"schema_version":"1","bundle_epoch":7,
            "created_at":"2026-01-01T00:00:00Z",
            "author":{"id":"ana","display_name":"A"},
            "reviewer":{"id":"bo","display_name":"R"},
            "expires_at":"2027-01-01T00:00:00Z","min_suite":"hybrid-ed25519-mldsa65",
            "custody":{"tier":"T3",
                       "classical":{"tier":"T3","mechanism":"offline laptop"},
                       "pq":{"tier":"T3","mechanism":"offline laptop"}}}"#;
        const R: &[u8] = br#"{"schema_version":"1","quorum_k":2,"attesters":{
            "p0":{"role":"approver","classical":"ka","pq":"pa"},
            "p1":{"role":"confirmer","classical":"kb","pq":"pb"}}}"#;

        let doc: serde_json::Value = serde_json::from_slice(M).unwrap();
        let raw: RawManifest = serde_json::from_slice(M).unwrap();
        assert_eq!(promoted::<u64>(&doc, &["bundle_epoch"]), raw.bundle_epoch);
        assert_eq!(promoted::<String>(&doc, &["expires_at"]), raw.expires_at);
        assert_eq!(
            promoted::<String>(&doc, &["author", "id"]),
            raw.author.and_then(|a| a.id)
        );
        assert_eq!(
            promoted::<String>(&doc, &["reviewer", "id"]),
            raw.reviewer.and_then(|r| r.id)
        );

        let rdoc: serde_json::Value = serde_json::from_slice(R).unwrap();
        let rraw: RawAttesterRegistry = serde_json::from_slice(R).unwrap();
        assert_eq!(promoted::<u64>(&rdoc, &["quorum_k"]), rraw.quorum_k);
        assert_eq!(
            promoted::<BTreeMap<String, serde_json::Value>>(&rdoc, &["attesters"])
                .map(|m| m.keys().cloned().collect::<Vec<_>>()),
            rraw.attesters
                .map(|m| m.keys().cloned().collect::<Vec<_>>()),
            "the attesters map shape must be the one the schema declares"
        );
    }

    #[test]
    fn a_quorum_that_is_not_an_integer_is_quorum_invalid_and_not_malformed() {
        // THE REFUSAL NAMES ARE THE INTERFACE. A whole-document deserialise
        // would turn each of these into one parse error, and an operator paged
        // at 03:00 would be told the bundle is malformed when the truth is that
        // nobody chose a threshold. tools/check-bundle-differential.py asserts
        // the NAME, and the reference refuses these the same way.
        for bad in [
            br#"{"schema_version":"1","quorum_k":"2","attesters":{}}"#.as_slice(),
            br#"{"schema_version":"1","quorum_k":2.5,"attesters":{}}"#.as_slice(),
            br#"{"schema_version":"1","quorum_k":true,"attesters":{}}"#.as_slice(),
            br#"{"schema_version":"1","quorum_k":null,"attesters":{}}"#.as_slice(),
            br#"{"schema_version":"1","quorum_k":-1,"attesters":{}}"#.as_slice(),
            br#"{"schema_version":"1","quorum_k":0,"attesters":{}}"#.as_slice(),
        ] {
            assert_eq!(
                activate_raw(None, Some(bad)),
                Err(Refusal::QuorumInvalid),
                "quorum {} did not refuse as QuorumInvalid",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_quorum_larger_than_an_i64_is_not_refused_for_being_large() {
        // THE ONE VERDICT ACP-44 MOVED, and it moved toward the reference.
        // `as_i64()` returned None for anything above 2^63, so a threshold in
        // that range was refused as QuorumInvalid — the accessor's range
        // showing through, never PB-6, whose rule is "absent or below 1". The
        // reference's integers are unbounded and it accepted these throughout,
        // so this was a live cross-language divergence rather than a hardening.
        let big = format!(
            r#"{{"schema_version":"1","quorum_k":{},"attesters":{{
                "p0":{{"classical":"ka","pq":"pa"}}}}}}"#,
            u64::MAX
        );
        assert_eq!(activate_raw(None, Some(big.as_bytes())), Ok(()));
    }

    #[test]
    fn a_negative_bundle_epoch_is_refused() {
        // PB-5 counts upward from zero — the schema says `integer, minimum 0`
        // — so a negative epoch is not an epoch. A high-water mark seeded below
        // zero is a mark the attacker chose.
        //
        // KNOWN DIVERGENCE: reference/src/acp_bundle.py accepts this, because
        // its `isinstance(epoch, int)` test does not carry the schema's bound.
        // It is pinned in tools/check-bundle-differential.py rather than papered
        // over, and this assertion is the Rust half of that pin.
        let m = br#"{"schema_version":"1","bundle_epoch":-1,
            "created_at":"2026-01-01T00:00:00Z",
            "author":{"id":"ana","display_name":"A"},
            "reviewer":{"id":"bo","display_name":"R"},
            "expires_at":"2027-01-01T00:00:00Z","min_suite":"hybrid-ed25519-mldsa65",
            "custody":{"tier":"T3","classical":"x","pq":"y"}}"#;
        assert_eq!(
            activate_raw(Some(m), None),
            Err(Refusal::Malformed("manifest has no integer bundle_epoch"))
        );
    }

    #[test]
    fn an_attester_entry_that_is_not_an_object_is_refused() {
        // An entry with no fields has no keys, and a key that is absent cannot
        // be shown distinct from anything.
        assert_eq!(
            activate_raw(
                None,
                Some(
                    br#"{"schema_version":"1","quorum_k":2,"attesters":{
                        "p0":"i-am-a-string",
                        "p1":{"classical":"kb","pq":"pb"}}}"#
                )
            ),
            Err(Refusal::Malformed(
                "an attester entry has no classical/pq key"
            ))
        );
    }

    #[test]
    fn attester_keys_are_compared_as_written_not_as_strings() {
        // PB-7 asks whether two identities carry the SAME key, never whether a
        // key is well formed. Typing the legs `String` — which is what
        // `RawAttester` does, and what a whole-document deserialise would
        // impose — refuses all four of these instead of comparing them, and the
        // reference compares them. A `null` leg is the sharp one: serde reads it
        // as `None`, so a present-and-colliding key would be reported ABSENT.
        for (registry, expected) in [
            (
                br#"{"schema_version":"1","quorum_k":2,"attesters":{
                    "p0":{"classical":1,"pq":2},"p1":{"classical":1,"pq":4}}}"#
                    .as_slice(),
                Err(Refusal::RegistryKeysNotDistinct),
            ),
            (
                br#"{"schema_version":"1","quorum_k":2,"attesters":{
                    "p0":{"classical":null,"pq":"a"},"p1":{"classical":null,"pq":"b"}}}"#
                    .as_slice(),
                Err(Refusal::RegistryKeysNotDistinct),
            ),
            (
                br#"{"schema_version":"1","quorum_k":2,"attesters":{
                    "p0":{"classical":{"k":1},"pq":"a"},"p1":{"classical":{"k":1},"pq":"b"}}}"#
                    .as_slice(),
                Err(Refusal::RegistryKeysNotDistinct),
            ),
            (
                br#"{"schema_version":"1","quorum_k":2,"attesters":{
                    "p0":{"classical":1,"pq":2},"p1":{"classical":3,"pq":4}}}"#
                    .as_slice(),
                Ok(()),
            ),
        ] {
            assert_eq!(
                activate_raw(None, Some(registry)),
                expected,
                "{}",
                String::from_utf8_lossy(registry)
            );
        }
    }

    #[test]
    fn the_distinctness_check_refuses_per_entry_in_order() {
        // A collision at p1 fires BEFORE a malformed p2 is reached, because
        // that is the order the reference refuses in. Deserialising the whole
        // attesters map up front would reverse it and report Malformed for a
        // registry whose real defect is that one key holder enrolled twice.
        assert_eq!(
            activate_raw(
                None,
                Some(
                    br#"{"schema_version":"1","quorum_k":2,"attesters":{
                        "p0":{"classical":"same","pq":"a"},
                        "p1":{"classical":"same","pq":"b"},
                        "p2":"i-am-a-string"}}"#
                )
            ),
            Err(Refusal::RegistryKeysNotDistinct)
        );
        // ...and the mirror image, so the assertion above is about ORDER and
        // not about one of the two refusals always winning.
        assert_eq!(
            activate_raw(
                None,
                Some(
                    br#"{"schema_version":"1","quorum_k":2,"attesters":{
                        "p0":"i-am-a-string",
                        "p1":{"classical":"same","pq":"a"},
                        "p2":{"classical":"same","pq":"b"}}}"#
                )
            ),
            Err(Refusal::Malformed(
                "an attester entry has no classical/pq key"
            ))
        );
    }

    #[test]
    fn a_field_no_verifier_reads_cannot_cause_a_refusal() {
        // THE REASON THIS FILE PROMOTES PER FIELD. Each document below is
        // wrong in a field this module never reads, and each must still
        // activate. A `RawManifest` / `RawAttesterRegistry` deserialise refuses
        // all four, because serde fails the whole struct on any wrongly-typed
        // member — and `custody` is the one that matters: the schema classifies
        // it T, this verifier reads nothing from it, and letting it decide the
        // verdict would hand a compromised signer a refusal switch.
        let custody_malformed = br#"{"schema_version":"1","bundle_epoch":7,
            "created_at":"2026-01-01T00:00:00Z",
            "author":{"id":"ana","display_name":"A"},
            "reviewer":{"id":"bo","display_name":"R"},
            "expires_at":"2027-01-01T00:00:00Z","min_suite":"hybrid-ed25519-mldsa65",
            "custody":{"tier":9,"classical":["x"]}}"#;
        assert_eq!(activate_raw(Some(custody_malformed), None), Ok(()));

        let custody_absent = br#"{"schema_version":"1","bundle_epoch":7,
            "created_at":"2026-01-01T00:00:00Z",
            "author":{"id":"ana","display_name":"A"},
            "reviewer":{"id":"bo","display_name":"R"},
            "expires_at":"2027-01-01T00:00:00Z","min_suite":"hybrid-ed25519-mldsa65"}"#;
        assert_eq!(activate_raw(Some(custody_absent), None), Ok(()));

        // display_name is typed by RawIdentity and forbidden to PB-2, which
        // compares on id: two people can share a display name.
        let display_name_numeric = br#"{"schema_version":"1","bundle_epoch":7,
            "created_at":"2026-01-01T00:00:00Z",
            "author":{"id":"ana","display_name":7},
            "reviewer":{"id":"bo","display_name":"R"},
            "expires_at":"2027-01-01T00:00:00Z","min_suite":"hybrid-ed25519-mldsa65",
            "custody":{"tier":"T3","classical":"x","pq":"y"}}"#;
        assert_eq!(activate_raw(Some(display_name_numeric), None), Ok(()));

        // A role is not a verification key (ACP-53) and is not read at all, so
        // its type cannot be a refusal either.
        assert_eq!(
            activate_raw(
                None,
                Some(
                    br#"{"schema_version":"1","quorum_k":2,"attesters":{
                        "p0":{"role":7,"classical":"ka","pq":"pa"},
                        "p1":{"role":8,"classical":"kb","pq":"pb"}}}"#
                )
            ),
            Ok(())
        );
    }

    #[test]
    fn the_epoch_conversion_matches_known_instants() {
        // A leap-year rule that is subtly wrong shifts an expiry by a day and
        // nothing else in the system notices. Which is precisely what happened
        // while writing this: the 2026 value below was first typed 86_400 too
        // low, the test went red, and Python's `datetime` settled it — the
        // conversion was right and the expectation was wrong. Values are taken
        // from an independent implementation for that reason, not read back out
        // of this one.
        //
        //   python3 -c "import datetime as dt; print(int(dt.datetime.strptime(
        //     '2026-08-18T00:00:00Z','%Y-%m-%dT%H:%M:%SZ')
        //     .replace(tzinfo=dt.timezone.utc).timestamp()))"
        //
        // 2000-03-01 is here because it is the day after the leap day of the
        // century year that IS a leap year, which is the case the /100 and /400
        // rules disagree about.
        assert_eq!(ts("1970-01-01T00:00:00Z").unix(), 0);
        assert_eq!(ts("2000-03-01T00:00:00Z").unix(), 951_868_800);
        assert_eq!(ts("2026-08-18T00:00:00Z").unix(), 1_787_011_200);
        assert_eq!(ts("2038-01-19T03:14:07Z").unix(), 2_147_483_647);
    }

    #[test]
    fn an_impossible_calendar_date_is_refused_rather_than_rolled_over() {
        // FOUND AFTER THE FIRST VERSION SHIPPED, and it is the defect this
        // module's own doc forbids. `2026-02-31` used to parse, and
        // days_from_civil rolled it forward to the same unix second as
        // `2026-03-03`: two spellings of one instant, in the field that decides
        // when a bundle stops being valid. An author writing a nonsense expiry
        // would have got a silently different one.
        //
        // The reference `datetime` refuses all of these, so accepting them
        // would also be a live divergence the moment ACP-41 compares the two.
        for bad in [
            "2026-02-31T00:00:00Z",
            "2026-02-29T00:00:00Z", // 2026 is not a leap year
            "2026-04-31T00:00:00Z",
            "2026-06-31T00:00:00Z",
            "2100-02-29T00:00:00Z", // divisible by 100, not by 400
            "2026-01-00T00:00:00Z",
        ] {
            assert!(
                Timestamp::parse(bad).is_none(),
                "accepted an impossible date {bad:?}"
            );
        }

        // And the leap days that are real must still parse, or the fix would
        // be a refusal dressed as a validation.
        assert!(Timestamp::parse("2024-02-29T00:00:00Z").is_some());
        assert!(Timestamp::parse("2000-02-29T00:00:00Z").is_some());
        assert!(Timestamp::parse("2026-01-31T00:00:00Z").is_some());
    }

    #[test]
    fn a_leap_second_is_refused_because_the_reference_refuses_it() {
        // `sec > 60` admitted 23:59:60. Python's datetime rejects it, so
        // leaving it in meant either a divergence in ACP-41 or a case the
        // differential never reaches. Agreeing with the reference is the point
        // of having one.
        assert!(Timestamp::parse("2026-08-18T23:59:60Z").is_none());
        assert!(Timestamp::parse("2026-08-18T23:59:59Z").is_some());
    }

    #[test]
    fn a_permissive_timestamp_spelling_is_refused_not_normalised() {
        // Two spellings of one instant is the encoding split, deciding when a
        // bundle stops being valid.
        for bad in [
            "2026-08-18T00:00:00+00:00",
            "2026-08-18T00:00:00.000Z",
            "2026-08-18t00:00:00z",
            "2026-08-18 00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-08-18T24:00:00Z",
            "",
        ] {
            assert!(
                Timestamp::parse(bad).is_none(),
                "accepted a non-canonical timestamp {bad:?}"
            );
        }
    }
}
