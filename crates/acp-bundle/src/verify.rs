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

use crate::tree::{Member, Tree};
use acp_core::BundleEpoch;
use acp_crypto::{
    Primitive, PrimitiveVerdict, Suite, VerifyingKeys, verify_ed25519, verify_hybrid,
    verify_mldsa65,
};

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
    /// over the **complete suite**.
    ///
    /// In the loader rather than in a schema, and the spec says why: JSON
    /// Schema's `uniqueItems` applies to arrays and there is no keyword for
    /// uniqueness across the values of a map. An implementation validating the
    /// registry by schema alone is non-conformant however cleanly it validates.
    ///
    /// The comparison is over the whole entry, not over one leg. Two identities
    /// differing in their classical key but sharing a post-quantum key are not
    /// distinct, and treating them as such is CR-3's conjunctive guarantee
    /// undone at the registry instead of at the verifier.
    fn check_registry(&self) -> Result<(), Refusal> {
        let bytes = self
            .member("attesters/registry.json")
            .ok_or(Refusal::Malformed("bundle has no attesters/registry.json"))?;
        let registry: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| Refusal::Malformed("attesters/registry.json is not JSON"))?;

        // PB-6. Absent or nonsensical is refused, never defaulted: a default
        // threshold is a threshold nobody chose, and the permissive default
        // (k=1) collapses INV-1-HIGH to single compromise.
        match registry.get("quorum_k").and_then(|v| v.as_i64()) {
            Some(k) if k >= 1 => {}
            _ => return Err(Refusal::QuorumInvalid),
        }

        let attesters = registry
            .get("attesters")
            .and_then(|v| v.as_object())
            .ok_or(Refusal::Malformed(
                "attesters/registry.json has no attesters map",
            ))?;

        let mut seen: Vec<&serde_json::Value> = Vec::new();
        for key in attesters.values() {
            if seen.contains(&key) {
                return Err(Refusal::RegistryKeysNotDistinct);
            }
            seen.push(key);
        }
        Ok(())
    }
}

/// PB-2. Compared on `id`, never on `display_name`: two people can share a
/// display name, and two-person integrity compared on a mutable label is
/// one-person integrity with extra steps.
fn check_two_person_integrity(manifest: &serde_json::Value) -> Result<(), Refusal> {
    let id = |who: &str| -> Result<String, Refusal> {
        manifest
            .get(who)
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(Refusal::Malformed(
                "manifest is missing an author or reviewer id",
            ))
    };
    if id("author")? == id("reviewer")? {
        return Err(Refusal::AuthorIsReviewer);
    }
    Ok(())
}

fn read_epoch(manifest: &serde_json::Value) -> Result<BundleEpoch, Refusal> {
    manifest
        .get("bundle_epoch")
        .and_then(|v| v.as_u64())
        .map(BundleEpoch::new)
        .ok_or(Refusal::Malformed("manifest has no integer bundle_epoch"))
}

fn read_expiry(manifest: &serde_json::Value) -> Result<Timestamp, Refusal> {
    let raw = manifest
        .get("expires_at")
        .and_then(|v| v.as_str())
        .ok_or(Refusal::Malformed("manifest has no expires_at"))?;
    Timestamp::parse(raw).ok_or(Refusal::Malformed("expires_at is not RFC 3339 UTC"))
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
        let entries: Vec<String> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| format!(r#""person{i}":{{"classical":"{k}","pq":"{k}"}}"#))
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

    #[test]
    fn two_attesters_sharing_a_key_are_refused() {
        // PB-7. The holder of one private key signs two objects differing only
        // in their attestation nonces, labels them with two names, and
        // satisfies k=2 alone -- INV-1-HIGH defeated by a single compromise,
        // through the registry rather than through the threshold.
        let mut host = BundleHost::new(config(0));
        let mut m = members(7, "2027-01-01T00:00:00Z");
        m[2].1 = registry(2, &["same", "same"]);
        let sig = sign(&m, HYBRID, signing_key());
        assert_eq!(
            host.activate(m, HYBRID, sig, ts("2026-08-18T00:00:00Z")),
            Err(Refusal::RegistryKeysNotDistinct)
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
