//! Key custody: who holds the bundle signing key, and what that buys.
//!
//! [`Signer`] is the producing half of the rule store. Until it existed this
//! crate could verify and could not produce, so "Python verifies a Rust
//! signature" was an obligation nobody had discharged — named as such in
//! `lib.rs` and in `tests/python_interop.rs`. It is discharged by
//! `tools/check-rust-signatures.py`, which is run by `tools/selftest.sh`.
//!
//! # Custody is pluggable on purpose
//!
//! A design that only works with an HSM is a design most deployments quietly
//! bypass, and a bypassed control is worse than an absent one because it is
//! still written down. So the tiers are ordered by what they cost to operate,
//! and every one of them is a real position someone occupies:
//!
//! | Tier | Mechanism | Fits |
//! | --- | --- | --- |
//! | [`CustodyTier::T0`] | passphrase-encrypted key file | development only — **refuses to sign for production** |
//! | [`CustodyTier::T1`] | age/GPG-encrypted key, air-gapped host, key wiped after use | small org, no compliance mandate |
//! | [`CustodyTier::T2`] | cloud KMS, non-exportable | most companies — the key never leaves, but it is online |
//! | [`CustodyTier::T3`] | PKCS#11 HSM | FIPS 140-2/3, or a regulatory mandate |
//!
//! **Split custody is a first-class case and is better**, not a degraded
//! fallback: PB-2 requires author ≠ reviewer, and two identities holding
//! different keys at possibly different tiers is the shape that requirement is
//! asking for.
//!
//! # THE CONSTRAINT THAT DECIDES THE API (RES-8)
//!
//! **A custody tier cannot be self-certified.** A bundle carrying "this was
//! signed at T3" is a security-determining value read from the party being
//! verified, which is the defect class this document has now hit five times
//! (C2 → X1 → Y1 → Z3 → W1), each time inside machinery the previous fix
//! introduced.
//!
//! So the tier is a property of a *key*, established when the verifier was
//! configured out-of-band, and it is held by [`TrustedKeys`] on the verifying
//! side. Concretely, and these are the parts that keep it true rather than
//! merely stated:
//!
//! - [`CustodyTier`] has no parser and no deserialiser. There is deliberately
//!   no `from_wire`, because [`Suite::from_wire`] exists and the asymmetry is
//!   the point: a suite is announced by the signer and *checked* against a
//!   signed floor, whereas a tier is never announced at all. If a tier appears
//!   in a bundle it is documentation, classified `T` with a disclosed residual.
//! - [`TrustedKeys::tier_of`] answers only for keys the verifier was configured
//!   with, and answers `None` for everything else. A key the verifier has never
//!   heard of does not acquire a tier by asserting one.
//!
//! # CUSTODY DISCLOSURE
//!
//! What is implemented here is the **policy** attached to a tier — which
//! environments it may sign for, whether the key survives a signature, and
//! whether the tier can be used in this build at all. Every one of those is
//! enforced and has a test that fails when it is removed.
//!
//! What is **not** implemented here is encryption at rest. T0's passphrase file
//! and T1's age/GPG file are decrypted by an external tool and the plaintext
//! key bytes are handed to [`KeyMaterial::from_secret_bytes`]. This crate does
//! not define a key-file format, and should not: a bespoke KDF-and-AEAD
//! container written here would be a second definition of a solved problem,
//! living in the one file where getting it wrong is unrecoverable. `age` and
//! `gpg` are the mechanism; this module is what happens after they run.
//!
//! **T2 is implemented** as of ACP-61, behind the `kms` feature: see
//! [`KmsSigner`]. **T3 is still declared and not implemented**, behind `hsm`,
//! and fails closed exactly as `pq-slh` does in [`crate::suite`]: asking for a
//! tier this build cannot provide is [`CustodyError::TierUnavailable`], never a
//! silent downgrade to a tier it can. A downgrade would be the interesting
//! failure — a deployment believing its key is in an HSM while it sits in
//! process memory — so it is the one the type system is arranged to prevent.
//!
//! What T2 implements is the **custody policy**, not a cloud SDK: the key never
//! enters this process, the public key is checked against the operator's
//! configuration rather than adopted from the KMS, every declared primitive
//! must be KMS-held or the tier is refused, and a returned signature is
//! verified before it is handed back. The transport to a particular cloud is a
//! [`KmsBackend`] the deployment writes, on the same principle that `age` and
//! `gpg` — not this crate — decrypt T0 and T1 key files.
//!
//! **Why ACP-61 existed at all**, recorded because the gap was invisible until
//! someone asked what would sign a receipt in production: T0 refuses production
//! and T1 wipes its key after one signature, so before T2 there was no
//! implemented tier that could sign a production receipt *twice*. The KMS in
//! the deployment architecture signs every accepted transaction. Phase 9 would
//! have emitted Decision Receipts that no conformant deployment could sign,
//! and every gate would have stayed green while it did.

use crate::primitives::MLDSA_CTX;
use crate::suite::{Primitive, Suite};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// Where a signing key is held. Established out-of-band, never transmitted.
///
/// No `from_wire`, no `Deserialize`, and that is not an oversight — see the
/// module note on RES-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyTier {
    /// Passphrase-encrypted key file. Development only.
    T0,
    /// Encrypted key on an air-gapped host, wiped after use.
    T1,
    /// Cloud KMS, non-exportable. Requires the `kms` feature.
    T2,
    /// PKCS#11 HSM. Requires the `hsm` feature.
    T3,
}

/// What a signature is *for*. T0 may not sign for production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl CustodyTier {
    /// Whether this tier may sign for `env`.
    ///
    /// T0 is a passphrase-encrypted file on a developer's laptop. It exists so
    /// the tooling is usable without a KMS, and the moment it can sign a
    /// production bundle the other three tiers are decorative — an attacker
    /// picks the cheapest key that produces a signature anyone honours, and so
    /// does a hurried engineer. The refusal is what makes the tier table a
    /// control rather than a description.
    pub const fn permits(self, env: Environment) -> bool {
        !matches!((self, env), (CustodyTier::T0, Environment::Production))
    }

    /// Whether this build can actually operate the tier.
    ///
    /// Mirrors [`Primitive::is_implemented`]. Naming is not implementing, and a
    /// tier that cannot be operated must refuse rather than substitute.
    pub const fn is_available(self) -> bool {
        match self {
            CustodyTier::T0 | CustodyTier::T1 => true,
            CustodyTier::T2 => cfg!(feature = "kms"),
            CustodyTier::T3 => cfg!(feature = "hsm"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyError {
    /// T0 was asked for a production signature.
    TierForbidsProduction,
    /// A T1 key was used twice. It was wiped after the first signature.
    KeyConsumed,
    /// The tier is declared but this build cannot operate it. Never downgraded.
    TierUnavailable,
    /// The suite names a primitive this build cannot produce.
    SuiteUnsupported,
    /// The backend refused. Carried as a static string so an error path cannot
    /// leak key material into a log line.
    Backend(&'static str),
}

/// The public halves of one hybrid identity.
///
/// Kept separately from [`KeyMaterial`] so it outlives a wiped private key: a
/// T1 signer must still be able to say which identity it just signed as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKeys {
    classical: [u8; 32],
    pq: Vec<u8>,
}

impl VerifyingKeys {
    /// Assemble an identity from public bytes.
    ///
    /// This is how a verifier loads the key it was configured with
    /// out-of-band — from a file placed by an operator, not from a bundle.
    /// Both halves are required and neither has a default: an identity missing
    /// its post-quantum key is not a weaker identity, it is a different one,
    /// and defaulting it to empty would let CR-3's second leg verify against
    /// nothing.
    pub fn from_parts(classical: [u8; 32], pq: Vec<u8>) -> Self {
        VerifyingKeys { classical, pq }
    }

    pub fn classical(&self) -> &[u8; 32] {
        &self.classical
    }

    pub fn pq(&self) -> &[u8] {
        &self.pq
    }

    /// A name for this identity, over **both** halves.
    ///
    /// Mirrors `HybridPub.fingerprint` in `reference/src/acp_crypto.py`, and
    /// `tests/python_interop.rs` asserts the two agree byte for byte. Covering
    /// both primitives is the whole point: a fingerprint over the classical
    /// half alone would let the post-quantum key be swapped without moving the
    /// identity, which is CR-3's conjunctive guarantee undone at the registry
    /// instead of at the verifier.
    ///
    /// This is what an attester registry entry is keyed by (PB-KEY), and what
    /// `acp-bundle` puts inside the tree hash.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.classical);
        h.update(&self.pq);
        format!("sha256:{:x}", h.finalize())
    }
}

/// Private key material for one hybrid identity.
///
/// Both halves zeroize on drop — `ed25519_dalek::SigningKey` implements
/// `ZeroizeOnDrop` under its default `zeroize` feature, and `fips204`'s
/// `PrivateKey` derives it. That is a checked property of those crates, not an
/// aspiration of this one, and [`OfflineSigner`] leans on it for T1.
pub struct KeyMaterial {
    ed: ed25519_dalek::SigningKey,
    ml: fips204::ml_dsa_65::PrivateKey,
    public: VerifyingKeys,
}

impl KeyMaterial {
    /// Load already-decrypted key bytes.
    ///
    /// This is the real entry point: `age`, `gpg` or a passphrase tool decrypts
    /// the key file and hands the plaintext here. See the module's CUSTODY
    /// DISCLOSURE for why the container format is not defined in this crate.
    pub fn from_secret_bytes(ed_secret: &[u8; 32], ml_secret: &[u8]) -> Result<Self, CustodyError> {
        use fips204::traits::SerDes;

        let ml_secret: [u8; fips204::ml_dsa_65::SK_LEN] = ml_secret
            .try_into()
            .map_err(|_| CustodyError::Backend("ML-DSA-65 secret key is the wrong length"))?;
        let ml = fips204::ml_dsa_65::PrivateKey::try_from_bytes(ml_secret)
            .map_err(|_| CustodyError::Backend("ML-DSA-65 secret key did not parse"))?;
        let ed = ed25519_dalek::SigningKey::from_bytes(ed_secret);
        let public = public_of(&ed, &ml);
        Ok(KeyMaterial { ed, ml, public })
    }

    /// Derive both halves from a seed, exactly as `acp_crypto.HybridKey` does.
    ///
    /// **Test and simulation key material.** A deployment loads keys from a KMS
    /// or an HSM; nothing here should be read as endorsing derived keys, and
    /// the identical warning sits on the Python constructor for the identical
    /// reason. It is `pub` because the cross-language fixtures need both sides
    /// to reach one identity from one seed, which is the property
    /// `spec/vectors/CLASSIFICATION.md` rests the vector corpus on.
    ///
    /// The domain separators are wire format, not taste: an implementation that
    /// hashes the bare seed derives a different identity, and every signature
    /// it produces then fails closed against everyone else's.
    pub fn from_seed(seed: &[u8]) -> Self {
        use fips204::traits::KeyGen;

        let mut h = Sha256::new();
        h.update(seed);
        h.update(b"ed");
        let ed = ed25519_dalek::SigningKey::from_bytes(&h.finalize().into());

        let mut h = Sha256::new();
        h.update(seed);
        h.update(b"mldsa");
        let (_, ml) = fips204::ml_dsa_65::KG::keygen_from_seed(&h.finalize().into());

        let public = public_of(&ed, &ml);
        KeyMaterial { ed, ml, public }
    }

    pub fn public(&self) -> &VerifyingKeys {
        &self.public
    }
}

fn public_of(ed: &ed25519_dalek::SigningKey, ml: &fips204::ml_dsa_65::PrivateKey) -> VerifyingKeys {
    use fips204::traits::{SerDes, Signer as _};

    VerifyingKeys {
        classical: ed.verifying_key().to_bytes(),
        pq: ml.get_public_key().into_bytes().to_vec(),
    }
}

/// One signature under a declared suite: one part per primitive the suite
/// requires.
///
/// Shaped to be consumed by [`crate::verify_hybrid`], which is conjunctive over
/// the declared suite. A `Vec<u8>` with the legs concatenated would make
/// "which bytes are the post-quantum leg" a parsing question, and a parsing
/// question is somewhere a downgrade can hide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    suite: Suite,
    parts: Vec<(Primitive, Vec<u8>)>,
}

impl HybridSignature {
    pub fn suite(&self) -> Suite {
        self.suite
    }

    pub fn parts(&self) -> &[(Primitive, Vec<u8>)] {
        &self.parts
    }

    /// The bytes for one primitive, or `None` if the suite does not carry it.
    pub fn part(&self, prim: Primitive) -> Option<&[u8]> {
        self.parts
            .iter()
            .find(|(p, _)| *p == prim)
            .map(|(_, b)| b.as_slice())
    }
}

/// Produces bundle signatures. The custody tier is a property of the
/// implementation, not an argument the caller chooses per call.
pub trait Signer {
    /// The suite this signer issues under.
    fn suite(&self) -> Suite;

    /// The tier this key is held at, as known *by the holder*.
    ///
    /// A verifier must not use this. It is here so the signing host can refuse
    /// its own operation — see [`CustodyTier::permits`] — and so an audit line
    /// on the signing host can record it. The verifying side reads
    /// [`TrustedKeys::tier_of`] instead, which is configured out-of-band.
    fn tier(&self) -> CustodyTier;

    /// The public halves. Survives a wiped private key.
    fn verifying_keys(&self) -> &VerifyingKeys;

    fn sign(&self, message: &[u8], env: Environment) -> Result<HybridSignature, CustodyError>;
}

/// A signer holding decrypted key material in process memory: tiers T0 and T1.
///
/// The two differ in policy, and the policy is the control:
///
/// - **T0** refuses production and keeps its key for the process lifetime.
/// - **T1** may sign for production and its key is **wiped after one
///   signature**, which is what "air-gapped host, key zeroized after use"
///   means when written as code. A second signature from the same load is
///   [`CustodyError::KeyConsumed`], not a silent re-use.
pub struct OfflineSigner {
    tier: CustodyTier,
    suite: Suite,
    public: VerifyingKeys,
    key: Mutex<Option<KeyMaterial>>,
}

impl OfflineSigner {
    /// Build a signer for a tier this build can operate.
    ///
    /// `tier` comes from the operator's configuration of the signing host, not
    /// from anything transmitted. T2 and T3 are refused here rather than
    /// downgraded — see [`CustodyError::TierUnavailable`].
    pub fn new(tier: CustodyTier, suite: Suite, key: KeyMaterial) -> Result<Self, CustodyError> {
        if !tier.is_available() {
            return Err(CustodyError::TierUnavailable);
        }
        if matches!(tier, CustodyTier::T2 | CustodyTier::T3) {
            // Reachable only in a build with the feature on, where a real
            // backend is required; an in-memory key is not that backend, and
            // accepting it here would let a T3 label sit on process memory.
            return Err(CustodyError::TierUnavailable);
        }
        if suite.primitives().iter().any(|p| !p.is_implemented()) {
            return Err(CustodyError::SuiteUnsupported);
        }
        let public = key.public().clone();
        Ok(OfflineSigner {
            tier,
            suite,
            public,
            key: Mutex::new(Some(key)),
        })
    }
}

impl Signer for OfflineSigner {
    fn suite(&self) -> Suite {
        self.suite
    }

    fn tier(&self) -> CustodyTier {
        self.tier
    }

    fn verifying_keys(&self) -> &VerifyingKeys {
        &self.public
    }

    fn sign(&self, message: &[u8], env: Environment) -> Result<HybridSignature, CustodyError> {
        use ed25519_dalek::Signer as _;
        use fips204::traits::Signer as _;

        if !self.tier.permits(env) {
            return Err(CustodyError::TierForbidsProduction);
        }

        let mut slot = self
            .key
            .lock()
            .map_err(|_| CustodyError::Backend("signing key mutex was poisoned"))?;
        let key = slot.as_ref().ok_or(CustodyError::KeyConsumed)?;

        let mut parts = Vec::new();
        for prim in self.suite.primitives() {
            let bytes = match prim {
                Primitive::Classical => key.ed.sign(message).to_bytes().to_vec(),
                Primitive::Pq => key
                    .ml
                    .try_sign(message, MLDSA_CTX)
                    .map_err(|_| CustodyError::Backend("ML-DSA-65 signing failed"))?
                    .to_vec(),
                // Unreachable while `new` refuses an unimplemented suite, and
                // refused again rather than unwrapped: a panic here would be a
                // denial of service on the signing host, and `new`'s check is
                // one edit away from being the only thing holding it.
                Primitive::PqSlh => return Err(CustodyError::SuiteUnsupported),
            };
            parts.push((*prim, bytes));
        }

        if self.tier == CustodyTier::T1 {
            // Dropped here, which zeroizes both halves. The signature is
            // already built, so a caller cannot observe a half-wiped key.
            *slot = None;
        }

        Ok(HybridSignature {
            suite: self.suite,
            parts,
        })
    }
}

/// The verifier's out-of-band configuration: which identities it trusts, and
/// what tier each of their keys is held at.
///
/// **This is the RES-8 boundary.** Everything a verifier believes about custody
/// comes from here, which was populated when the verifier was deployed — never
/// from the bundle, the manifest, or any accompanying message. A bundle may
/// carry a tier claim; nothing in this type will read it.
#[derive(Debug, Default, Clone)]
pub struct TrustedKeys {
    entries: Vec<(String, CustodyTier)>,
}

impl TrustedKeys {
    pub fn new() -> Self {
        TrustedKeys::default()
    }

    /// Record that the key with this fingerprint is held at `tier`.
    ///
    /// Keyed by fingerprint rather than by a name: a name is what an attacker
    /// controls in the message, and the fingerprint covers both public halves.
    pub fn trust(&mut self, fingerprint: impl Into<String>, tier: CustodyTier) {
        let fingerprint = fingerprint.into();
        self.entries.retain(|(f, _)| *f != fingerprint);
        self.entries.push((fingerprint, tier));
    }

    /// The tier this verifier was configured to believe for `keys`, or `None`
    /// if it was never configured with them.
    ///
    /// `None` is a refusal, not "unknown, assume something reasonable". An
    /// unrecognised key has no tier, and P-4 applies: unknown is never the
    /// permissive answer.
    pub fn tier_of(&self, keys: &VerifyingKeys) -> Option<CustodyTier> {
        let fp = keys.fingerprint();
        self.entries.iter().find(|(f, _)| *f == fp).map(|(_, t)| *t)
    }

    /// Whether this verifier trusts `keys` at or above `floor`.
    ///
    /// Tiers ARE ordered for this purpose — unlike suites, which are sets and
    /// were a genuine mistake to rank (see [`Suite::satisfies_floor`]). T0..T3
    /// is a single chain of custody strength with no incomparable pair: every
    /// tier holds one key under one mechanism, and T3 does everything T2 does.
    pub fn satisfies(&self, keys: &VerifyingKeys, floor: CustodyTier) -> bool {
        match self.tier_of(keys) {
            Some(t) => rank(t) >= rank(floor),
            None => false,
        }
    }
}

const fn rank(t: CustodyTier) -> u8 {
    match t {
        CustodyTier::T0 => 0,
        CustodyTier::T1 => 1,
        CustodyTier::T2 => 2,
        CustodyTier::T3 => 3,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// T2 — cloud KMS, non-exportable (ACP-61)
// ─────────────────────────────────────────────────────────────────────────────

/// One non-exportable key, held by a KMS, for exactly one primitive.
///
/// This crate deliberately does **not** depend on a cloud SDK, for the same
/// reason it does not define a key-file format for T0 and T1: a bespoke
/// re-implementation of a solved problem, living in the one file where getting
/// it wrong is unrecoverable. The deployment implements this trait against its
/// own KMS; what lives here is the **custody policy**, which is the part with
/// security content.
///
/// # What "non-exportable" buys, and what it costs
///
/// T2's whole claim is that the private key never enters this process. That is
/// a *structural* property of [`KmsSigner`] — it has no [`KeyMaterial`] field
/// and no constructor that accepts one — rather than a promise in a comment.
/// The cost is that every signature is a network call to a service that can be
/// slow, throttled, or wrong, so every method here returns [`CustodyError`] and
/// none of them may be unwrapped.
///
/// # Both halves must be KMS-held or the tier is not T2
///
/// A hybrid identity whose classical key sits in a KMS and whose post-quantum
/// key sits in process memory is **not** a T2 identity, and calling it one is
/// precisely the failure this module's header names: *"a deployment believing
/// its key is in an HSM while it sits in process memory."* A custody tier
/// describes the weakest half, never the strongest. [`KmsSigner::new`]
/// therefore requires a backend for **every** primitive the suite declares and
/// refuses to construct otherwise.
///
/// This is reachable today rather than aspirational: AWS KMS carries both
/// `ML_DSA_65` (signing algorithm `ML_DSA_SHAKE_256`) and `ED25519_SHA_512`,
/// and [`crate::primitives::MLDSA_CTX`] is empty, which is what a KMS that
/// exposes no context parameter will use. A backend for a KMS that signs
/// ML-DSA under a *non-empty* context produces signatures this crate will not
/// verify — which `sign` catches before returning rather than at the verifier,
/// see below.
#[cfg(feature = "kms")]
pub trait KmsBackend: Send + Sync {
    /// Which primitive this key signs. One backend, one primitive.
    fn primitive(&self) -> Primitive;

    /// The public half, **as the KMS reports it**.
    ///
    /// Not trusted. [`KmsSigner::new`] compares it against the identity the
    /// operator configured and refuses on mismatch — see the RES-8 note there.
    fn public_key(&self) -> Result<Vec<u8>, CustodyError>;

    /// Sign `message`, returning the raw signature bytes for this primitive.
    ///
    /// Raw, not DER: `ed25519-dalek` wants 64 bytes and `fips204` wants 3309.
    /// A backend that returns a wrapped encoding is a misconfiguration, and
    /// [`KmsSigner::sign`] is arranged to find it.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CustodyError>;
}

/// A signer whose private key never enters this process: tier T2.
///
/// Contrast [`OfflineSigner`], which holds [`KeyMaterial`] and is refused for
/// T2 for exactly that reason.
#[cfg(feature = "kms")]
pub struct KmsSigner {
    suite: Suite,
    public: VerifyingKeys,
    backends: Vec<Box<dyn KmsBackend>>,
}

#[cfg(feature = "kms")]
impl KmsSigner {
    /// Build a T2 signer over one backend per primitive the suite declares.
    ///
    /// `expected` is the identity **the operator configured this signing host
    /// with**, out-of-band. It is not read from the KMS.
    ///
    /// # THE RES-8 CHECK, and why it is a check and not an assignment
    ///
    /// The obvious implementation asks each backend for its public key and
    /// builds the identity from the answers. That is the defect class this
    /// document has hit five times: the public key is a security-determining
    /// value, the bundle publishes it (PB-KEY) and `acp-bundle` puts it inside
    /// the tree hash, so a KMS that answered with a key it controls would have
    /// its own identity signed into the registry — and every later verification
    /// would succeed against the wrong key while looking perfect.
    ///
    /// So the operator states the identity and this constructor **compares**.
    /// A backend whose reported key differs is [`CustodyError::Backend`], never
    /// an adoption. The distinction is the entire content of RES-8, and it is
    /// one line away from being lost.
    ///
    /// # CR-3 is conjunctive here too
    ///
    /// Every primitive the suite declares must have exactly one backend, and a
    /// backend for a primitive the suite does *not* declare is refused rather
    /// than ignored. An `any`-shaped construction would let a deployment
    /// configure a hybrid suite, supply only the classical backend, and sign
    /// bundles with the post-quantum leg quietly missing — the downgrade the
    /// hybrid suite exists to prevent, arriving through configuration instead
    /// of through the wire.
    pub fn new(
        suite: Suite,
        expected: VerifyingKeys,
        backends: Vec<Box<dyn KmsBackend>>,
    ) -> Result<Self, CustodyError> {
        if !CustodyTier::T2.is_available() {
            // Unreachable under this `cfg`, and kept because `is_available` is
            // the one place the tier table is enforced and this is one edit
            // away from being the only caller that skips it.
            return Err(CustodyError::TierUnavailable);
        }
        if suite.primitives().iter().any(|p| !p.is_implemented()) {
            return Err(CustodyError::SuiteUnsupported);
        }

        let declared = suite.primitives();
        for backend in &backends {
            if !declared.contains(&backend.primitive()) {
                return Err(CustodyError::Backend(
                    "a KMS backend was supplied for a primitive the suite does not declare",
                ));
            }
        }
        for prim in declared {
            let matching = backends.iter().filter(|b| b.primitive() == *prim).count();
            if matching != 1 {
                // Zero is the downgrade; two is an ambiguity about which key
                // the identity names. Both refuse.
                return Err(CustodyError::Backend(
                    "each primitive the suite declares needs exactly one KMS backend",
                ));
            }
        }

        for backend in &backends {
            let reported = backend.public_key()?;
            let configured: &[u8] = match backend.primitive() {
                Primitive::Classical => expected.classical(),
                Primitive::Pq => expected.pq(),
                Primitive::PqSlh => return Err(CustodyError::SuiteUnsupported),
            };
            if reported != configured {
                return Err(CustodyError::Backend(
                    "KMS public key does not match the identity this host was configured with",
                ));
            }
        }

        Ok(KmsSigner {
            suite,
            public: expected,
            backends,
        })
    }
}

#[cfg(feature = "kms")]
impl Signer for KmsSigner {
    fn suite(&self) -> Suite {
        self.suite
    }

    fn tier(&self) -> CustodyTier {
        CustodyTier::T2
    }

    fn verifying_keys(&self) -> &VerifyingKeys {
        &self.public
    }

    /// Sign, then **verify the result before returning it**.
    ///
    /// The verification is not defensive decoration. A KMS is configured by
    /// hand — key spec, signing algorithm, message type, encoding — and every
    /// one of those can be individually plausible and jointly wrong: a DER
    /// wrapper where raw bytes are expected, `ED25519_PH_SHA_512` where
    /// `ED25519_SHA_512` was meant, an ML-DSA context this crate does not use.
    /// Each produces a well-formed signature that fails verification.
    ///
    /// Without this check the failure surfaces at a *verifier*, after the
    /// bundle has been published and the epoch consumed, where it is
    /// indistinguishable from a forgery — and PB-5 forbids re-serving an epoch,
    /// so the recovery is a new epoch rather than a retry. Catching it here
    /// costs one verification per signature on a path that has just made a
    /// network call, and turns an unrecoverable publication into a refusal.
    fn sign(&self, message: &[u8], env: Environment) -> Result<HybridSignature, CustodyError> {
        use crate::primitives::{verify_ed25519, verify_mldsa65};
        use crate::PrimitiveVerdict;

        if !CustodyTier::T2.permits(env) {
            // T2 permits production, so this never fires today. It is here
            // because the tier table is the control and a signer that consults
            // it cannot drift from it — see the T0 mutant.
            return Err(CustodyError::TierForbidsProduction);
        }

        let mut parts = Vec::new();
        for prim in self.suite.primitives() {
            let backend = self
                .backends
                .iter()
                .find(|b| b.primitive() == *prim)
                // `new` established this; refused rather than unwrapped,
                // because a panic here is a denial of service on the signing
                // host and `new`'s check is one edit from being its only guard.
                .ok_or(CustodyError::Backend("no KMS backend for a declared primitive"))?;

            let bytes = backend.sign(message)?;

            let verdict = match prim {
                Primitive::Classical => verify_ed25519(self.public.classical(), message, &bytes),
                Primitive::Pq => verify_mldsa65(self.public.pq(), message, &bytes),
                Primitive::PqSlh => return Err(CustodyError::SuiteUnsupported),
            };
            if verdict != PrimitiveVerdict::Valid {
                return Err(CustodyError::Backend(
                    "the KMS returned a signature that does not verify under the configured key",
                ));
            }

            parts.push((*prim, bytes));
        }

        Ok(HybridSignature {
            suite: self.suite,
            parts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrimitiveVerdict, verify_ed25519, verify_hybrid, verify_mldsa65};

    const HYBRID: Suite = Suite::HybridEd25519MlDsa65;

    fn signer(tier: CustodyTier) -> OfflineSigner {
        OfflineSigner::new(tier, HYBRID, KeyMaterial::from_seed(b"k1")).expect("tier is available")
    }

    #[test]
    fn a_signature_this_crate_produced_verifies_in_this_crate() {
        // The floor of the whole module: sign, then check with the verifying
        // path that already existed. If this fails, nothing below means
        // anything.
        let s = signer(CustodyTier::T1);
        let sig = s
            .sign(b"bundle tree hash", Environment::Production)
            .unwrap();
        let pk = s.verifying_keys();

        assert_eq!(
            verify_ed25519(
                pk.classical(),
                b"bundle tree hash",
                sig.part(Primitive::Classical).unwrap()
            ),
            PrimitiveVerdict::Valid
        );
        assert_eq!(
            verify_mldsa65(
                pk.pq(),
                b"bundle tree hash",
                sig.part(Primitive::Pq).unwrap()
            ),
            PrimitiveVerdict::Valid
        );
    }

    #[test]
    fn the_signature_carries_every_primitive_the_suite_requires() {
        // CR-3 at the producing end. A signer that emitted only the classical
        // leg would hand the verifier a downgrade it is obliged to refuse, and
        // the failure would look like a verifier bug.
        let sig = signer(CustodyTier::T1)
            .sign(b"m", Environment::Production)
            .unwrap();
        let verdicts: Vec<_> = sig
            .parts()
            .iter()
            .map(|(p, _)| (*p, PrimitiveVerdict::Valid))
            .collect();
        assert_eq!(verify_hybrid(HYBRID, &verdicts), Ok(()));
    }

    #[test]
    fn t0_refuses_to_sign_for_production() {
        // THE T0 CONTROL. Delete `permits` and this is the test that goes red.
        // Without it the tier table is a description of intent, and the
        // cheapest key in the building signs production bundles.
        assert_eq!(
            signer(CustodyTier::T0).sign(b"m", Environment::Production),
            Err(CustodyError::TierForbidsProduction)
        );
    }

    #[test]
    fn t0_still_signs_for_development() {
        // The refusal must be about the environment, not about T0 being
        // decorative. A tier nobody can use is a tier nobody configures.
        assert!(
            signer(CustodyTier::T0)
                .sign(b"m", Environment::Development)
                .is_ok()
        );
    }

    #[test]
    fn a_t1_key_does_not_survive_its_signature() {
        // "Zeroized after use" as an enforced property rather than an operator
        // instruction. The second call must fail, and must fail by naming the
        // reason — a silent re-use is exactly what an air-gapped procedure is
        // trying to prevent.
        let s = signer(CustodyTier::T1);
        assert!(s.sign(b"first", Environment::Production).is_ok());
        assert_eq!(
            s.sign(b"second", Environment::Production),
            Err(CustodyError::KeyConsumed)
        );
    }

    #[test]
    fn a_t0_key_survives_because_t0_is_a_development_tier() {
        // The counterpart. If both tiers wiped, `a_t1_key_does_not_survive`
        // would pass for a reason unrelated to T1.
        let s = signer(CustodyTier::T0);
        assert!(s.sign(b"first", Environment::Development).is_ok());
        assert!(s.sign(b"second", Environment::Development).is_ok());
    }

    #[test]
    fn t2_and_t3_are_unavailable_in_a_default_build_and_are_never_downgraded() {
        // Fails closed exactly as `pq-slh` does. The interesting failure is not
        // "cannot sign" — it is a deployment believing its key is in an HSM
        // while it sits in process memory, which is what returning a working
        // T1 signer here would produce.
        for tier in [CustodyTier::T2, CustodyTier::T3] {
            let e = OfflineSigner::new(tier, HYBRID, KeyMaterial::from_seed(b"k1"));
            assert!(
                matches!(e, Err(CustodyError::TierUnavailable)),
                "{tier:?} produced a usable signer in a build that cannot operate it"
            );
        }
    }

    #[test]
    fn an_unimplemented_suite_cannot_be_signed_for() {
        assert!(matches!(
            OfflineSigner::new(
                CustodyTier::T1,
                Suite::SlhDsa128s,
                KeyMaterial::from_seed(b"k1")
            ),
            Err(CustodyError::SuiteUnsupported)
        ));
    }

    #[test]
    fn the_verifier_does_not_learn_the_tier_from_the_signer() {
        // RES-8, as a test rather than as a paragraph. The signing host holds a
        // T1 key. The verifier was configured out-of-band to believe that key
        // is T1 — and if the operator had configured T3, the verifier would
        // believe T3, because the verifier's configuration is the only source.
        // `Signer::tier` is not consulted anywhere in this path.
        let s = signer(CustodyTier::T1);
        let mut trusted = TrustedKeys::new();
        trusted.trust(s.verifying_keys().fingerprint(), CustodyTier::T3);

        assert_eq!(s.tier(), CustodyTier::T1, "the holder knows its own tier");
        assert_eq!(
            trusted.tier_of(s.verifying_keys()),
            Some(CustodyTier::T3),
            "the verifier answers from its own configuration, not from the signer"
        );
    }

    #[test]
    fn an_unconfigured_key_has_no_tier_and_meets_no_floor() {
        // P-4 at the custody boundary: unknown is never the permissive answer.
        // A key the verifier has never been told about does not acquire a tier
        // by presenting itself, which is the whole attack RES-8 describes.
        let stranger = KeyMaterial::from_seed(b"not-configured");
        let trusted = TrustedKeys::new();
        assert_eq!(trusted.tier_of(stranger.public()), None);
        assert!(!trusted.satisfies(stranger.public(), CustodyTier::T0));
    }

    #[test]
    fn a_floor_refuses_a_weaker_tier_and_accepts_a_stronger_one() {
        let key = KeyMaterial::from_seed(b"k1");
        let mut trusted = TrustedKeys::new();
        trusted.trust(key.public().fingerprint(), CustodyTier::T2);

        assert!(trusted.satisfies(key.public(), CustodyTier::T1));
        assert!(trusted.satisfies(key.public(), CustodyTier::T2));
        assert!(
            !trusted.satisfies(key.public(), CustodyTier::T3),
            "a KMS key satisfied an HSM floor"
        );
    }

    #[test]
    fn two_identities_may_be_trusted_at_different_tiers() {
        // PB-2 is author ≠ reviewer, and split custody is the good case rather
        // than a degraded one: the reviewer's key being held differently is a
        // feature of the arrangement, not a gap in it.
        let author = KeyMaterial::from_seed(b"author");
        let reviewer = KeyMaterial::from_seed(b"reviewer");
        let mut trusted = TrustedKeys::new();
        trusted.trust(author.public().fingerprint(), CustodyTier::T1);
        trusted.trust(reviewer.public().fingerprint(), CustodyTier::T3);

        assert_eq!(trusted.tier_of(author.public()), Some(CustodyTier::T1));
        assert_eq!(trusted.tier_of(reviewer.public()), Some(CustodyTier::T3));
    }

    #[test]
    fn the_fingerprint_covers_both_halves() {
        // If it covered only the classical key, two identities differing solely
        // in their post-quantum half would collide — PB-7's pairwise-distinct
        // requirement defeated at the point identities are named, which is
        // CR-3 undone at the registry.
        let a = KeyMaterial::from_seed(b"k1");
        let b = KeyMaterial::from_seed(b"k2");
        assert_ne!(a.public().fingerprint(), b.public().fingerprint());

        let spliced = VerifyingKeys {
            classical: *a.public().classical(),
            pq: b.public().pq().to_vec(),
        };
        assert_ne!(
            spliced.fingerprint(),
            a.public().fingerprint(),
            "swapping the post-quantum half did not move the identity"
        );
    }

    #[test]
    fn a_signature_does_not_verify_under_a_different_identity() {
        let a = signer(CustodyTier::T0);
        let b = OfflineSigner::new(CustodyTier::T0, HYBRID, KeyMaterial::from_seed(b"k2")).unwrap();
        let sig = a.sign(b"m", Environment::Development).unwrap();
        assert_eq!(
            verify_ed25519(
                b.verifying_keys().classical(),
                b"m",
                sig.part(Primitive::Classical).unwrap()
            ),
            PrimitiveVerdict::Invalid
        );
    }

    #[test]
    fn seed_derivation_matches_the_python_reference() {
        // The same three lines `tests/python_interop.rs` checks against the
        // committed fixture, asserted here against the library's own
        // constructor so the two cannot drift: the fixture proves Python and
        // Rust agree, this proves `KeyMaterial::from_seed` is the thing that
        // was proved.
        let k = KeyMaterial::from_seed(b"k1");
        assert_eq!(
            k.public().fingerprint(),
            "sha256:38a223bddb2ee525211f7353bc4f578bf025996eeee3a550dc7ead5d0fdce7eb"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // T2 — cloud KMS (ACP-61)
    //
    // These run only under `--features kms`, which `tools/selftest.sh`
    // supplies. A tier whose tests are excluded from every build that runs is
    // a tier nobody checks, and that is the shape of the defect this ticket
    // exists to close.
    // ─────────────────────────────────────────────────────────────────────

    #[cfg(feature = "kms")]
    mod kms {
        use super::*;

        /// A KMS that happens to run in this process.
        ///
        /// It stands in for the network, not for the custody property: the
        /// point of T2 is that [`KmsSigner`] has nowhere to put a key, and
        /// that is true whatever the backend does. A test double that held no
        /// key could not sign, and one that signs correctly is what lets the
        /// *negative* cases below be about the thing being tested.
        struct FakeKms {
            prim: Primitive,
            key: KeyMaterial,
            /// Corrupt the signature before returning it — a stand-in for
            /// every way a KMS can be plausibly misconfigured.
            corrupt: bool,
            /// Report a public key other than the one that signs.
            reported: Option<Vec<u8>>,
            fail: bool,
        }

        impl FakeKms {
            fn new(prim: Primitive, seed: &[u8]) -> Self {
                FakeKms {
                    prim,
                    key: KeyMaterial::from_seed(seed),
                    corrupt: false,
                    reported: None,
                    fail: false,
                }
            }
        }

        impl KmsBackend for FakeKms {
            fn primitive(&self) -> Primitive {
                self.prim
            }

            fn public_key(&self) -> Result<Vec<u8>, CustodyError> {
                if let Some(r) = &self.reported {
                    return Ok(r.clone());
                }
                Ok(match self.prim {
                    Primitive::Classical => self.key.public().classical().to_vec(),
                    Primitive::Pq => self.key.public().pq().to_vec(),
                    Primitive::PqSlh => return Err(CustodyError::SuiteUnsupported),
                })
            }

            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CustodyError> {
                use ed25519_dalek::Signer as _;
                use fips204::traits::Signer as _;
                if self.fail {
                    return Err(CustodyError::Backend("the KMS was unavailable"));
                }
                let mut bytes = match self.prim {
                    Primitive::Classical => self.key.ed.sign(message).to_bytes().to_vec(),
                    Primitive::Pq => self
                        .key
                        .ml
                        .try_sign(message, MLDSA_CTX)
                        .map_err(|_| CustodyError::Backend("signing failed"))?
                        .to_vec(),
                    Primitive::PqSlh => return Err(CustodyError::SuiteUnsupported),
                };
                if self.corrupt {
                    bytes[0] ^= 0xff;
                }
                Ok(bytes)
            }
        }

        fn hybrid_backends(seed: &[u8]) -> Vec<Box<dyn KmsBackend>> {
            vec![
                Box::new(FakeKms::new(Primitive::Classical, seed)),
                Box::new(FakeKms::new(Primitive::Pq, seed)),
            ]
        }

        fn identity(seed: &[u8]) -> VerifyingKeys {
            KeyMaterial::from_seed(seed).public().clone()
        }

        #[test]
        fn a_t2_signature_verifies_and_the_tier_is_t2() {
            // The floor. If this fails nothing below means anything.
            let s = KmsSigner::new(HYBRID, identity(b"k1"), hybrid_backends(b"k1"))
                .expect("a matching identity and one backend per primitive");
            assert_eq!(s.tier(), CustodyTier::T2);
            let sig = s.sign(b"bundle tree hash", Environment::Production).unwrap();
            let pk = s.verifying_keys();

            // Both legs, through the verifying path that already existed —
            // and then through CR-3's conjunctive composition, because a
            // signature whose halves each verify individually is not yet a
            // hybrid signature.
            let c = verify_ed25519(
                pk.classical(),
                b"bundle tree hash",
                sig.part(Primitive::Classical).unwrap(),
            );
            let q = verify_mldsa65(pk.pq(), b"bundle tree hash", sig.part(Primitive::Pq).unwrap());
            assert_eq!(c, PrimitiveVerdict::Valid);
            assert_eq!(q, PrimitiveVerdict::Valid);
            assert!(
                verify_hybrid(
                    HYBRID,
                    &[(Primitive::Classical, c), (Primitive::Pq, q)],
                )
                .is_ok()
            );
        }

        #[test]
        fn t2_signs_for_production_and_t0_still_does_not() {
            // ACP-61's reason for existing: T0 refuses production and T1 wipes
            // after one signature, so before T2 there was no tier that could
            // sign a production receipt more than once. Both halves are
            // asserted together so a change that relaxes T0 to "fix" the gap
            // fails here rather than passing quietly.
            let t2 = KmsSigner::new(HYBRID, identity(b"k1"), hybrid_backends(b"k1")).unwrap();
            assert!(t2.sign(b"m", Environment::Production).is_ok());
            assert!(t2.sign(b"m", Environment::Production).is_ok(), "T2 is not consumed by use");

            let t0 = signer(CustodyTier::T0);
            assert_eq!(
                t0.sign(b"m", Environment::Production),
                Err(CustodyError::TierForbidsProduction)
            );
        }

        #[test]
        fn a_kms_reporting_a_key_the_operator_did_not_configure_is_refused() {
            // RES-8, and the single most important test in this module. The
            // KMS is the party being verified; its claim about which key it
            // holds is not evidence. `acp-bundle` puts the attester registry
            // inside the tree hash, so adopting this answer would sign the
            // KMS's own identity into the registry and every later
            // verification would succeed against the wrong key.
            let mut rogue = FakeKms::new(Primitive::Classical, b"k1");
            rogue.reported = Some(identity(b"attacker").classical().to_vec());
            let backends: Vec<Box<dyn KmsBackend>> =
                vec![Box::new(rogue), Box::new(FakeKms::new(Primitive::Pq, b"k1"))];

            let r = KmsSigner::new(HYBRID, identity(b"k1"), backends);
            assert!(
                matches!(r, Err(CustodyError::Backend(_))),
                "a KMS key that differs from the configured identity was adopted"
            );
        }

        #[test]
        fn a_hybrid_suite_with_only_the_classical_backend_is_refused() {
            // CR-3 conjunctive, arriving through configuration rather than
            // through the wire. An `any`-shaped construction here would let a
            // deployment declare hybrid and sign with the post-quantum leg
            // missing, which is the downgrade the suite exists to prevent.
            let backends: Vec<Box<dyn KmsBackend>> =
                vec![Box::new(FakeKms::new(Primitive::Classical, b"k1"))];
            assert!(matches!(
                KmsSigner::new(HYBRID, identity(b"k1"), backends),
                Err(CustodyError::Backend(_))
            ));
        }

        #[test]
        fn a_backend_for_an_undeclared_primitive_is_refused_not_ignored() {
            // The mirror of the case above, and the reason `new` checks both
            // directions: silently ignoring an extra backend would let a
            // deployment believe a primitive is covered when the suite never
            // asked for it.
            let ed_only = Suite::Ed25519;
            let backends: Vec<Box<dyn KmsBackend>> = vec![
                Box::new(FakeKms::new(Primitive::Classical, b"k1")),
                Box::new(FakeKms::new(Primitive::Pq, b"k1")),
            ];
            assert!(matches!(
                KmsSigner::new(ed_only, identity(b"k1"), backends),
                Err(CustodyError::Backend(_))
            ));
        }

        #[test]
        fn two_backends_for_one_primitive_are_refused() {
            // Not pedantry: two keys for one primitive is an ambiguity about
            // which key the identity names, and the constructor's public-key
            // check would pass on whichever it happened to compare.
            let backends: Vec<Box<dyn KmsBackend>> = vec![
                Box::new(FakeKms::new(Primitive::Classical, b"k1")),
                Box::new(FakeKms::new(Primitive::Classical, b"k1")),
                Box::new(FakeKms::new(Primitive::Pq, b"k1")),
            ];
            assert!(matches!(
                KmsSigner::new(HYBRID, identity(b"k1"), backends),
                Err(CustodyError::Backend(_))
            ));
        }

        #[test]
        fn a_signature_that_does_not_verify_is_caught_at_the_signer() {
            // The sign-then-verify control. A misconfigured KMS — DER wrapper,
            // Ed25519ph instead of Ed25519, a non-empty ML-DSA context —
            // returns a well-formed signature that fails verification. Without
            // this the failure surfaces at a verifier, after publication, where
            // it is indistinguishable from a forgery; and PB-5 forbids
            // re-serving the epoch, so recovery is a new epoch rather than a
            // retry.
            let mut bad = FakeKms::new(Primitive::Classical, b"k1");
            bad.corrupt = true;
            let backends: Vec<Box<dyn KmsBackend>> =
                vec![Box::new(bad), Box::new(FakeKms::new(Primitive::Pq, b"k1"))];
            let s = KmsSigner::new(HYBRID, identity(b"k1"), backends).unwrap();
            assert!(
                matches!(
                    s.sign(b"m", Environment::Production),
                    Err(CustodyError::Backend(_))
                ),
                "an unverifiable signature was returned to the caller"
            );
        }

        #[test]
        fn an_unavailable_kms_fails_closed() {
            // No cached key, no fallback tier, no partial signature. The
            // interesting failure would be a signer that degraded to something
            // it could do locally, which is why there is nothing local to
            // degrade to.
            let mut down = FakeKms::new(Primitive::Pq, b"k1");
            down.fail = true;
            let backends: Vec<Box<dyn KmsBackend>> = vec![
                Box::new(FakeKms::new(Primitive::Classical, b"k1")),
                Box::new(down),
            ];
            let s = KmsSigner::new(HYBRID, identity(b"k1"), backends).unwrap();
            assert_eq!(
                s.sign(b"m", Environment::Production),
                Err(CustodyError::Backend("the KMS was unavailable"))
            );
        }

        #[test]
        fn an_in_memory_key_still_cannot_wear_a_t2_label() {
            // The property T2 actually sells. `KmsSigner` has no field that
            // could hold a key; `OfflineSigner` has one and is refused the
            // label even in a build where T2 is available — which is this
            // build. Deleting that branch is the mutant for "a deployment
            // believing its key is in a KMS while it sits in process memory".
            assert!(CustodyTier::T2.is_available());
            assert_eq!(
                OfflineSigner::new(CustodyTier::T2, HYBRID, KeyMaterial::from_seed(b"k1"))
                    .err(),
                Some(CustodyError::TierUnavailable)
            );
        }

        #[test]
        fn implementing_t2_did_not_quietly_make_t3_available() {
            // ACP-61 acceptance item 5, asserted in the build where it could
            // plausibly regress. `kms` does not imply `hsm`, but the two tiers
            // sit in one `match` arm apart, and the interesting failure is the
            // silent one: T3 becoming available because the arm below it was
            // edited. A deployment under a FIPS mandate would then hold its key
            // in a KMS while believing it is in an HSM.
            assert!(!CustodyTier::T3.is_available());
            assert_eq!(
                OfflineSigner::new(CustodyTier::T3, HYBRID, KeyMaterial::from_seed(b"k1"))
                    .err(),
                Some(CustodyError::TierUnavailable)
            );
        }
    }
}
