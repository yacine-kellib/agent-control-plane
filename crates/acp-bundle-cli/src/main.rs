//! `acp-bundle` — the offline bundle authoring and signing tool.
//!
//! **This binary must never run in the control-plane domain.** Authoring and
//! signing are air-gapped (PB-1, PB-4): the whole guarantee is that no runtime
//! component — *including a fully compromised Policy Engine* — holds a key that
//! can produce a valid bundle signature. A signing tool on a control-plane host
//! turns that from cryptography back into file permissions.
//!
//! Unlike the scaffolds in `services/`, whose `main()` exits non-zero so a stub
//! cannot be mistaken for a running control plane, this one is real and exits
//! zero when it works.
//!
//! # The discipline is inherited from `tools/sign-release.sh`
//!
//! That script says its rules apply "for the same reason it applies to the
//! policy bundle". It has already been hardened by real defects, and those are
//! not worth rediscovering here:
//!
//! - **Halt on an unrecognised file type**, never silently sign it and never
//!   silently skip it. Enforced in [`acp_bundle::walk_bundle`], so `list` and
//!   `sign` cannot disagree about it — they call the same function.
//! - **Build into `.tmp` and move into place only after the signature exists.**
//!   A mistyped key path must not destroy the last valid SIGNATURE. That defect
//!   happened once, to the release signer.
//! - **`list` works with no key**, so anyone can always see what the next
//!   signature would cover.
//! - **Assert PB-2 (author ≠ reviewer) at signing time**, where the human is,
//!   rather than only at the verifier where it is too late to fix.
//!
//! # Distribution
//!
//! One-way import to the runtime over removable media or a data diode (F2).
//! Exactly one bundle is active and activation is atomic (PB-3) — that is
//! `acp_bundle::BundleHost`'s job, not this tool's.
//!
//! # Undischarged
//!
//! The ticket asks for a **static binary**. This is an ordinary `cargo build`;
//! producing a musl-linked static artifact and checking it in CI is not done.
//! An air-gapped host running a dynamically linked binary against unknown
//! system libraries is a real operational gap, and naming it is not closing it.

use acp_bundle::{
    BundleHost, BundleSignature, Refusal, Serving, Timestamp, VerifierConfig, walk_bundle,
};
use acp_crypto::{
    CustodyTier, Environment, KeyMaterial, OfflineSigner, Primitive, Signer, Suite, VerifyingKeys,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
acp-bundle — offline policy bundle authoring and signing

USAGE:
  acp-bundle list   <bundle-dir> [--suite <name>]
  acp-bundle sign   <bundle-dir> --key <file> [--suite <name>] [--tier T0|T1] [--env development|production]
  acp-bundle verify <bundle-dir> --pubkey <file> [--floor <name>] [--now <RFC3339>] [--grace <seconds>] [--high-water <n>]

SUBCOMMANDS:
  list     Print the members the next signature would cover. Needs no key.
  sign     Write SIGNATURE over the canonical tree hash.
  verify   Check a bundle as the runtime would, and name the refusal if any.

NOTES:
  A key file is JSON: {\"ed25519_sk_hex\": \"...\", \"mldsa65_sk_hex\": \"...\"}
  holding ALREADY-DECRYPTED secret bytes. Decrypt with age or gpg first; this
  tool defines no key-file container of its own.

  There is deliberately no --seed flag. Seeds are test and simulation key
  material, and a signing tool offering derived keys would endorse them.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let result = match command.as_str() {
        "list" => cmd_list(&args[1..]),
        "sign" => cmd_sign(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

// ------------------------------------------------------------------ commands

fn cmd_list(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args)?;
    let dir = a.positional()?;
    let suite = a.suite()?;

    // Same walk `sign` uses. Two walks would be two answers to "what does the
    // signature cover", and the one nobody runs would be the wrong one.
    let tree = walk_bundle(&dir, suite).map_err(describe_walk)?;
    for member in tree.members() {
        println!("{}", member.path());
    }
    println!(
        "{} members, tree hash sha256:{}",
        tree.members().len(),
        hex(&tree.hash())
    );
    Ok(())
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args)?;
    let dir = a.positional()?;
    let suite = a.suite()?;
    let tier = a.tier()?;
    let env = a.env()?;
    let key_path = a.required("--key")?;

    let tree = walk_bundle(&dir, suite).map_err(describe_walk)?;

    // PB-2 BEFORE signing. The verifier checks this too, but by then the
    // bundle is built, distributed, and being refused on an air-gapped host
    // where nobody can see why. The author is standing here.
    check_two_person_integrity(&dir)?;

    let key = load_secret_key(&key_path)?;
    let signer = OfflineSigner::new(tier, suite, key)
        .map_err(|e| format!("cannot sign at {tier:?}: {e:?}"))?;
    let signature = signer.sign(&tree.hash(), env).map_err(|e| match e {
        acp_crypto::CustodyError::TierForbidsProduction => {
            "T0 is a development tier and refuses to sign a production bundle. \
                 Use a key held at T1 or above, or pass --env development."
                .to_string()
        }
        other => format!("signing failed: {other:?}"),
    })?;

    let mut parts = serde_json::Map::new();
    for (prim, bytes) in signature.parts() {
        parts.insert(wire_name(*prim).to_string(), hex(bytes).into());
    }
    let envelope = serde_json::json!({
        "suite": suite.as_wire(),
        "parts": parts,
    });

    // .tmp first, move after. A mistyped key path, a full disk or a crash must
    // not leave the bundle with no signature at all -- the previous one stays
    // valid until a complete replacement exists.
    let final_path = dir.join(acp_bundle::SIGNATURE_FILE);
    let tmp_path = dir.join(format!("{}.tmp", acp_bundle::SIGNATURE_FILE));
    let body = serde_json::to_string_pretty(&envelope)
        .map_err(|e| format!("could not encode the signature: {e}"))?;
    std::fs::write(&tmp_path, body + "\n")
        .map_err(|e| format!("could not write {}: {e}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, &final_path)
        .map_err(|e| format!("could not move the signature into place: {e}"))?;

    println!(
        "signed {} members under {} at {:?}\ntree hash sha256:{}\nwrote {}",
        tree.members().len(),
        suite.as_wire(),
        tier,
        hex(&tree.hash()),
        final_path.display()
    );
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let a = Args::parse(args)?;
    let dir = a.positional()?;
    let pubkey_path = a.required("--pubkey")?;
    let floor = a
        .named_suite("--floor")?
        .unwrap_or(Suite::HybridEd25519MlDsa65);
    let grace = a.number("--grace")?.unwrap_or(0);
    let now = match a.value("--now") {
        Some(raw) => Timestamp::parse(&raw)
            .ok_or_else(|| format!("--now {raw:?} is not RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)"))?,
        None => {
            return Err(
                "--now is required: this tool never reads the host clock, so a \
                            verification is reproducible on any machine"
                    .into(),
            );
        }
    };

    let signing_key = load_public_key(&pubkey_path)?;
    let (members, suite, signature) = load_signed_bundle(&dir)?;

    let mut host = match a.number("--high-water")? {
        Some(n) => BundleHost::restore(
            VerifierConfig {
                signing_key,
                suite_floor: floor,
                grace_seconds: grace,
            },
            acp_core::BundleEpoch::new(n),
        ),
        None => BundleHost::new(VerifierConfig {
            signing_key,
            suite_floor: floor,
            grace_seconds: grace,
        }),
    };

    // The refusal NAME is the output, not a human sentence: `acp_bundle.py`
    // compares against these strings, so they are the shared vocabulary of the
    // Python/Rust differential rather than a message someone may reword.
    if let Err(refusal) = host.activate(members, suite, signature, now) {
        println!("REFUSED {}", refusal_name(&refusal));
        return Err(String::new());
    }

    let reading = match host.read("manifest.json", now) {
        Ok(r) => r,
        Err(refusal) => {
            println!("REFUSED {}", refusal_name(&refusal));
            return Err(String::new());
        }
    };
    println!(
        "OK {}",
        match reading.serving {
            Serving::Normal => "Normal",
            Serving::CappedAtAttest => "CappedAtAttest",
        }
    );
    Ok(())
}

// --------------------------------------------------------------------- bits

/// Stable names for the refusal variants, shared with the Python reference.
///
/// Spelled out rather than derived from `Debug`, because `Debug` output is a
/// formatting detail that a future derive change could alter silently, and this
/// is wire format for the cross-language differential.
fn refusal_name(r: &Refusal) -> &'static str {
    match r {
        Refusal::SignatureInvalid => "SignatureInvalid",
        Refusal::SuiteBelowFloor => "SuiteBelowFloor",
        Refusal::Expired => "Expired",
        Refusal::EpochRollback => "EpochRollback",
        Refusal::AuthorIsReviewer => "AuthorIsReviewer",
        Refusal::RegistryKeysNotDistinct => "RegistryKeysNotDistinct",
        Refusal::QuorumInvalid => "QuorumInvalid",
        Refusal::Malformed(_) => "Malformed",
        Refusal::NoActiveBundle => "NoActiveBundle",
    }
}

fn wire_name(p: Primitive) -> &'static str {
    match p {
        Primitive::Classical => "classical",
        Primitive::Pq => "pq",
        Primitive::PqSlh => "pq-slh",
    }
}

fn parse_primitive(name: &str) -> Option<Primitive> {
    match name {
        "classical" => Some(Primitive::Classical),
        "pq" => Some(Primitive::Pq),
        "pq-slh" => Some(Primitive::PqSlh),
        _ => None,
    }
}

fn describe_walk(e: acp_bundle::WalkError) -> String {
    use acp_bundle::WalkError::*;
    match e {
        UnrecognisedFileType(p) => format!(
            "unrecognised file type in the bundle: {p}\n  \
             Refused rather than skipped: an unsigned file inside a signed bundle is exactly \
             what the signature is meant to deny.\n  \
             Remove it, or add its extension to BUNDLE_EXTS in acp-bundle/src/tree.rs."
        ),
        Symlink(p) => format!(
            "symlink in the bundle: {p}\n  \
             Refused rather than followed: a tree hash must not depend on state outside the bundle."
        ),
        other => format!("cannot walk the bundle: {other:?}"),
    }
}

fn check_two_person_integrity(dir: &Path) -> Result<(), String> {
    let path = dir.join("manifest.json");
    let raw =
        std::fs::read(&path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("manifest.json is not JSON: {e}"))?;
    let id = |who: &str| -> Result<String, String> {
        manifest
            .get(who)
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| format!("manifest.json has no {who}.id"))
    };
    let (author, reviewer) = (id("author")?, id("reviewer")?);
    if author == reviewer {
        return Err(format!(
            "PB-2: author and reviewer are the same identity ({author:?}).\n  \
             Two-person integrity is the control on the highest-leverage artifact in the system, \
             and it is compared on id -- two people can share a display name."
        ));
    }
    Ok(())
}

fn load_secret_key(path: &Path) -> Result<KeyMaterial, String> {
    let raw = std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("key file is not JSON: {e}"))?;
    let ed = unhex(field(&v, "ed25519_sk_hex")?)?;
    let ml = unhex(field(&v, "mldsa65_sk_hex")?)?;
    let ed: [u8; 32] = ed
        .try_into()
        .map_err(|_| "ed25519_sk_hex is not 32 bytes".to_string())?;
    KeyMaterial::from_secret_bytes(&ed, &ml).map_err(|e| format!("key file rejected: {e:?}"))
}

fn load_public_key(path: &Path) -> Result<VerifyingKeys, String> {
    let raw = std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("public key file is not JSON: {e}"))?;
    let ed = unhex(field(&v, "ed25519_pk_hex")?)?;
    let pq = unhex(field(&v, "mldsa65_pk_hex")?)?;
    let ed: [u8; 32] = ed
        .try_into()
        .map_err(|_| "ed25519_pk_hex is not 32 bytes".to_string())?;
    Ok(VerifyingKeys::from_parts(ed, pq))
}

/// The members a signature covers, the suite it was issued under, and the
/// signature itself — everything `BundleHost::activate` needs.
type SignedBundle = (Vec<(String, Vec<u8>)>, Suite, BundleSignature);

/// Read a signed bundle from disk: the members the tree covers, plus SIGNATURE.
fn load_signed_bundle(dir: &Path) -> Result<SignedBundle, String> {
    let sig_path = dir.join(acp_bundle::SIGNATURE_FILE);
    let raw = std::fs::read(&sig_path)
        .map_err(|e| format!("could not read {}: {e}", sig_path.display()))?;
    let envelope: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("SIGNATURE is not JSON: {e}"))?;

    let suite_name = field(&envelope, "suite")?;
    let suite = Suite::from_wire(suite_name)
        .ok_or_else(|| format!("SIGNATURE declares unknown suite {suite_name:?}"))?;

    let parts_obj = envelope
        .get("parts")
        .and_then(|v| v.as_object())
        .ok_or("SIGNATURE has no parts object")?;
    let mut parts = Vec::new();
    for (name, value) in parts_obj {
        let prim = parse_primitive(name)
            .ok_or_else(|| format!("SIGNATURE names unknown primitive {name:?}"))?;
        let bytes = unhex(value.as_str().ok_or("a signature part is not a string")?)?;
        parts.push((prim, bytes));
    }

    // The member list is walked, not read from the signature: the signature
    // says what it covers, and asking it to also say what EXISTS would let a
    // tampered bundle omit a file by omitting its own mention of it.
    let tree = walk_bundle(dir, suite).map_err(describe_walk)?;
    let mut members = Vec::new();
    for m in tree.members() {
        let bytes = std::fs::read(dir.join(m.path()))
            .map_err(|e| format!("could not read {}: {e}", m.path()))?;
        members.push((m.path().to_string(), bytes));
    }

    Ok((members, suite, BundleSignature { parts }))
}

fn field<'a>(v: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    v.get(name)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing string field {name:?}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex field has an odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

/// A forty-line argument parser, in place of a dependency.
struct Args {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
}

impl Args {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut flags = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some(name) = a.strip_prefix("--") {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| format!("--{name} needs a value"))?;
                flags.push((format!("--{name}"), value.clone()));
                i += 2;
            } else {
                positional.push(a.clone());
                i += 1;
            }
        }
        Ok(Args { positional, flags })
    }

    fn value(&self, name: &str) -> Option<String> {
        self.flags
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    fn required(&self, name: &str) -> Result<PathBuf, String> {
        self.value(name)
            .map(PathBuf::from)
            .ok_or_else(|| format!("{name} is required"))
    }

    fn positional(&self) -> Result<PathBuf, String> {
        self.positional
            .first()
            .map(PathBuf::from)
            .ok_or_else(|| format!("a bundle directory is required\n\n{USAGE}"))
    }

    fn number(&self, name: &str) -> Result<Option<u64>, String> {
        match self.value(name) {
            None => Ok(None),
            Some(v) => v
                .parse()
                .map(Some)
                .map_err(|_| format!("{name} {v:?} is not a non-negative integer")),
        }
    }

    fn named_suite(&self, name: &str) -> Result<Option<Suite>, String> {
        match self.value(name) {
            None => Ok(None),
            Some(v) => Suite::from_wire(&v)
                .map(Some)
                // Never defaulted to a known suite. CR-1: an unknown suite is
                // refused rather than ignored.
                .ok_or_else(|| format!("{name} {v:?} is not a known suite")),
        }
    }

    fn suite(&self) -> Result<Suite, String> {
        Ok(self
            .named_suite("--suite")?
            .unwrap_or(Suite::HybridEd25519MlDsa65))
    }

    fn tier(&self) -> Result<CustodyTier, String> {
        match self.value("--tier").as_deref() {
            None | Some("T1") => Ok(CustodyTier::T1),
            Some("T0") => Ok(CustodyTier::T0),
            // T2/T3 are declared and not implemented. Refused here rather than
            // downgraded, matching acp_crypto::custody: the interesting failure
            // is a deployment believing its key is in an HSM.
            Some(t @ ("T2" | "T3")) => Err(format!(
                "custody tier {t} is declared and not implemented in this build \
                 (features `kms` and `hsm`). Refused rather than downgraded."
            )),
            Some(other) => Err(format!("unknown custody tier {other:?}")),
        }
    }

    fn env(&self) -> Result<Environment, String> {
        match self.value("--env").as_deref() {
            None | Some("production") => Ok(Environment::Production),
            Some("development") => Ok(Environment::Development),
            Some(other) => Err(format!(
                "unknown environment {other:?} (expected development or production)"
            )),
        }
    }
}
