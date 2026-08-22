#!/usr/bin/env python3
"""ACP-104: execute the AWS KMS claims instead of reading them.

ACP-90 concluded that the receipt signing key CAN live in a cloud KMS. That
conclusion rests on three claims about AWS, and every one of them was READ from
vendor documentation. Its first version was worse -- it rested on a research
agent's vendor ranking -- and replacing a bad source with a good one is not a
change of method. This repository's premise is "if a claim here does not replay
on your machine, don't believe it," and a vendor's product page is normative
text with no executable consumer, which is the exact defect class the spec has
published three corrections for.

This script is that consumer. It signs real bytes with a real KMS key and hands
the result to `reference/src/acp_crypto.py`, which knows nothing about AWS and
cannot be persuaded by a product page.

  claim under test                          consequence if it is false
  ----------------------------------------  ----------------------------------
  1  ED25519_SHA_512 + MessageType RAW is    the ACP-90 correction collapses
     FIPS 186-5 s7.6 PureEdDSA, verifiable   back to Finding 2. Assured is
     by a plain RFC 8032 verifier            blocked again, and ACP-102 does
                                             NOT rescue it -- a smaller body is
                                             still a body a ph-only signer
                                             cannot sign in a form our verifier
                                             accepts.
  2  MessageType RAW caps at 4,096 bytes     the measured "2-4x over" framing
                                             loses its reference point
  3  EXTERNAL_MU signatures are byte-        only the ML-DSA fallback path
     identical to ordinary RAW signatures    changes, not the recommendation

Claim 1 is the one that carries the milestone. If it fails, ACP-102 is work on
a format that still cannot be signed -- worth discovering for the price of one
script rather than one milestone.

NOT A GATE LINE, and it must never become one. It needs credentials and it
creates billable keys, so neither `verify.sh` nor `selftest.sh` can run it.
What a gate CAN check is that the recorded result stays honest, which is why
the run is committed as a DATED transcript: a vendor capability is a fact that
expires, and an undated one quietly turns back into a claim.

NO MOCKING, EVER. A mocked KMS asserts exactly what we already believe, and it
would be cited as if it had asserted something. If boto3 is missing or
credentials are absent this script REFUSES; it never degrades to a simulation.

WHAT COUNTS AS EVIDENCE. A `ParamValidationError` is raised by botocore before
any packet leaves the machine -- it means the installed SDK has never heard of
the parameter, which is a fact about a pip install and not about AWS. A stale
botocore would otherwise fail `KeySpec='ML_DSA_65'` in a way that reads exactly
like "AWS does not offer ML-DSA": the original wrong finding, manufactured
locally. Only a `ValidationException` from the service is evidence. The two are
separated everywhere below, and the preflight refuses to start when the SDK
cannot express the calls at all.

AN UNRUN STEP IS NOT A PASSED STEP. Every step records PASS, FAIL or NOT-RUN
with a reason, and the exit code is non-zero unless all five say PASS. This is
the same rule the mutation suites live under: a mutant that cannot import is
reported ERROR, never KILL.

Usage:
    python3 tools/check-kms-compat.py --selfcheck     # no AWS, no boto3, no cost
    pip install boto3
    python3 tools/check-kms-compat.py --region us-east-1
    python3 tools/check-kms-compat.py --region us-east-1 --keep-keys

`--selfcheck` is what `selftest.sh` runs. It exercises every part of this file
that does not need AWS -- the DER unwrap, the mu derivation, the size matcher,
the redaction -- INCLUDING the negative cases, and it is the reason a run
against real AWS can be believed. Without it the first time anyone learns that
`raw_from_spki` is broken is halfway through a paid run, and the symptom would
read as a finding about AWS.

Cost: two asymmetric KMS keys (about $1/month each, prorated) and a handful of
requests. Both keys are scheduled for deletion on exit unless --keep-keys is
given; their ARNs are printed either way so nothing can be orphaned silently.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# sys.path manipulation belongs in the runner, not in library code (CLAUDE.md).
sys.path.insert(0, os.path.join(ROOT, "reference", "src"))
sys.path.insert(0, os.path.join(ROOT, "reference", "suites"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from dilithium_py.ml_dsa import ML_DSA_65

from acp_crypto import HybridPub, verify_prim
from acp_executor import canon


# ---------------------------------------------------------------- the claims
#
# Named here rather than inlined so the transcript can record which string was
# actually sent. If AWS renames one of these, the run fails with the name it
# tried -- which is a finding, not a mystery.
KEYSPEC_ED25519 = "ECC_NIST_EDWARDS25519"
KEYSPEC_MLDSA65 = "ML_DSA_65"
ALG_ED25519_PURE = "ED25519_SHA_512"      # claimed FIPS 186-5 s7.6 PureEdDSA
ALG_ED25519_PH = "ED25519_PH_SHA_512"     # FIPS 186-5 s7.8 HashEdDSA -- the trap
ALG_MLDSA = "ML_DSA_SHAKE_256"
MSGTYPE_RAW = "RAW"
MSGTYPE_DIGEST = "DIGEST"
MSGTYPE_EXTERNAL_MU = "EXTERNAL_MU"

ED25519_RAW_CAP = 4096                    # claim 2, under test -- not an assumption
MLDSA65_PK_LEN = 1952                     # FIPS 204 table 2


class Refuse(Exception):
    """The environment cannot produce evidence. Never a finding about AWS."""


# ------------------------------------------------------------------ recording
class Transcript:
    def __init__(self, region: str, quiet: bool = False):
        self.quiet = quiet
        self.doc = {
            "check": "ACP-104 AWS KMS compatibility",
            "verified_as_of": datetime.datetime.now(datetime.timezone.utc)
                                      .date().isoformat(),
            "region": region,
            "environment": {},
            "steps": [],
            "verdict": None,
        }

    def env(self, **kw):
        self.doc["environment"].update(kw)

    def step(self, sid, title, status, detail, **extra):
        rec = {"id": sid, "title": title, "status": status, "detail": detail}
        rec.update(extra)
        self.doc["steps"].append(rec)
        if not self.quiet:
            mark = {"PASS": "  ok  ", "FAIL": " FAIL ",
                    "NOT-RUN": "not-run"}[status]
            print(f"[{mark}] {sid}  {title}")
            print(f"          {detail}")
        return status == "PASS"

    def passed(self, sid) -> bool:
        return any(s["id"] == sid and s["status"] == "PASS"
                   for s in self.doc["steps"])


# Done-when #2 commits this transcript to a PUBLIC repository and a KMS ARN
# embeds the AWS account id. Full ARNs go to the terminal; the FILE is scrubbed.
#
# Applied at the single write point rather than per call site, because per-call
# redaction is what this first shipped as and it covered exactly one field: the
# key ARNs from step 1. Every FAIL path also stores the service's own error
# text, and AWS error messages quote full ARNs back at you --
# "User: arn:aws:iam::<12 digits>:user/x is not authorized..." -- so a failing
# run, which is precisely the run done-when #5 says to commit, would have
# published the account. One choke point cannot be forgotten by the next branch
# that records a new field.
_ARN_ACCOUNT = re.compile(r"(arn:aws[a-z-]*:[^:\s]*:[^:\s]*:)\d{12}")
_BARE_ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")


def scrub(x):
    """Recursively remove AWS account ids from anything about to be written.

    The bare-12-digit rule is deliberately broader than the ARN rule. Nothing
    else this transcript records is a 12-digit run: message sizes are at most
    five digits, signature lengths three, hashes are hex with a `sha256:`
    prefix, and dates are ISO strings. Over-redacting a number would cost
    nothing; under-redacting an account id cannot be undone once pushed.
    """
    if isinstance(x, str):
        return _BARE_ACCOUNT.sub("<account>",
                                 _ARN_ACCOUNT.sub(r"\1<account>", x))
    if isinstance(x, dict):
        return {k: scrub(v) for k, v in x.items()}
    if isinstance(x, list):
        return [scrub(v) for v in x]
    return x


# ----------------------------------------------------------------- DER unwrap
def _tlv(buf, i):
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


def raw_from_spki(der: bytes, expect_len: int, what: str) -> bytes:
    """Unwrap SubjectPublicKeyInfo { AlgorithmIdentifier, BIT STRING }.

    `cryptography` 50 has no ML-DSA loader, so this is hand-rolled -- and it
    asserts the recovered length. A silently mis-parsed key would make step 4
    fail and read as "AWS EXTERNAL_MU is broken", which is the wrong finding
    from the right symptom.
    """
    tag, seq, end = _tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise Refuse(f"{what}: not a single DER SEQUENCE")
    tag, _algid, i = _tlv(seq, 0)
    tag, bits, i = _tlv(seq, i)
    if tag != 0x03:
        raise Refuse(f"{what}: expected BIT STRING, got tag 0x{tag:02x}")
    if not bits or bits[0] != 0:
        raise Refuse(f"{what}: BIT STRING has unused bits")
    raw = bits[1:]
    if len(raw) != expect_len:
        raise Refuse(f"{what}: expected {expect_len} raw bytes, got {len(raw)}")
    return raw


def _names_size(msg: str) -> bool:
    """Does this AWS error message actually name the message size?

    Step 3 is a refusal test, and a refusal test that accepts ANY error is
    satisfied by a permissions failure or a disabled key -- the cap would then
    be "confirmed" by an error about something else entirely. Kept as one
    function so `--selfcheck` exercises the same code the live run uses; a copy
    would be a second definition of the same rule, which is the defect this
    repository has published corrections for.
    """
    return any(w in msg.lower() for w in
               ("length", "size", "too long", "exceed", "4096"))


# ------------------------------------------------------------------- preflight
def preflight(tr: Transcript):
    """Prove the local half before spending a single AWS call."""
    try:
        import boto3
        import botocore
        import botocore.session
    except ImportError as exc:
        raise Refuse(f"boto3 is not installed ({exc}). "
                     "`pip install boto3`. This script does not mock KMS.")

    tr.env(boto3=boto3.__version__, botocore=botocore.__version__,
           python=sys.version.split()[0])
    print(f"boto3 {boto3.__version__} / botocore {botocore.__version__}")

    # What does the INSTALLED SDK believe KMS accepts? A far better source than
    # a documentation page, and free. If a value is absent from a shape that
    # exists, the call would fail client-side -- an environment result wearing
    # the costume of a finding.
    model = botocore.session.get_session().get_service_model("kms")
    seen = {}
    for shape_name, required in (
        ("KeySpec", (KEYSPEC_ED25519, KEYSPEC_MLDSA65)),
        ("SigningAlgorithmSpec", (ALG_ED25519_PURE, ALG_ED25519_PH, ALG_MLDSA)),
        ("MessageType", (MSGTYPE_RAW, MSGTYPE_DIGEST, MSGTYPE_EXTERNAL_MU)),
    ):
        try:
            enum = list(model.shape_for(shape_name).enum)
        except Exception:
            seen[shape_name] = None
            print(f"  ! shape {shape_name} not in this SDK's model; the live "
                  f"call will decide")
            continue
        seen[shape_name] = enum
        missing = [v for v in required if v not in enum]
        if missing:
            raise Refuse(
                f"botocore {botocore.__version__} does not know "
                f"{shape_name}={missing}. Upgrade boto3 and re-run. This is a "
                f"fact about the installed SDK, NOT about AWS -- do not record "
                f"it as a finding.")
    tr.env(sdk_enums=seen)

    # The mu pathway, locally. Not a mock of KMS: it fixes the derivation so a
    # step-4 failure can only indict AWS or the DER unwrap, never this script's
    # reading of FIPS 204 s6.2.
    pk, sk = ML_DSA_65.keygen()
    msg = b"ACP-104 local external-mu preflight"
    mu = ML_DSA_65.prehash_external_mu(pk, msg)
    if len(mu) != 64:
        raise Refuse(f"local mu is {len(mu)} bytes, expected 64")
    if not ML_DSA_65.verify(pk, msg, ML_DSA_65.sign_external_mu(sk, mu)):
        raise Refuse("local external-mu round trip failed; dilithium_py is "
                     "broken or its API moved. Fix that before blaming AWS.")
    print("  local external-mu round trip: ok")
    return boto3


# ------------------------------------------------------------------- the bodies
def bodies():
    """Real receipt bodies from the shared fixture library, never hand-written.

    `reference/suites/conformance.py` is imported, not forked (CLAUDE.md): a
    hand-made body would be a body no Executor ever signs, and its size would
    be a number about nothing.
    """
    import conformance as C
    b = C.make_bundle()
    p = C.proposal()

    def body_of(r):
        return canon({k: v for k, v in r.items() if k != "sig"})

    base = body_of(C.receipt(b, p))
    k2 = body_of(C.receipt(b, p, atts=C.quorum(b, p)[:2]))
    return base, k2


# ----------------------------------------------------------------------- steps
def run(args, tr: Transcript):
    boto3 = preflight(tr)
    from botocore.exceptions import ClientError, ParamValidationError

    def service_error(exc):
        """Separate a finding from a fact about this machine.

        Three things can make an AWS call fail and only one of them is evidence:

          ParamValidationError  the installed SDK cannot express the call. Never
                                left the machine. A stale botocore fails
                                KeySpec=ML_DSA_65 in a way that reads exactly
                                like "AWS does not offer ML-DSA" -- the original
                                wrong finding, manufactured locally.
          AccessDenied*         the caller lacks the permission. Recorded as a
                                step FAIL this would read as "AWS cannot do
                                this", which is a claim about a vendor derived
                                from an IAM policy.
          anything else         the service evaluated the request and refused.
                                That is the only outcome worth writing down.
        """
        if isinstance(exc, ParamValidationError):
            raise Refuse(f"botocore rejected the request before sending it: "
                         f"{exc}. Environment, not evidence.")
        code = exc.response.get("Error", {}).get("Code", "")
        msg = exc.response.get("Error", {}).get("Message", "")
        if "AccessDenied" in code or "NotAuthorized" in code:
            raise Refuse(f"{code}: {msg}\n"
                         f"This credential cannot exercise the claim. Grant "
                         f"kms:CreateKey, kms:GetPublicKey, kms:Sign and "
                         f"kms:ScheduleKeyDeletion and re-run. A permissions "
                         f"failure is a fact about an IAM policy, not about "
                         f"what AWS KMS can do, and must not be recorded as "
                         f"one.")
        return code, msg

    # STS rather than kms:ListKeys: this asks "are there working credentials",
    # which every caller may ask, instead of borrowing a KMS permission the run
    # does not otherwise need and failing narrow-scoped policies for no reason.
    try:
        boto3.client("sts", region_name=args.region).get_caller_identity()
    except Exception as exc:
        raise Refuse(f"no usable AWS credentials for {args.region}: {exc}")
    kms = boto3.client("kms", region_name=args.region)

    base_body, k2_body = bodies()
    print(f"\nreceipt bodies from the reference: base {len(base_body)} B, "
          f"k=2 {len(k2_body)} B\n")
    tr.env(base_body_bytes=len(base_body), k2_body_bytes=len(k2_body))

    # The premise of step 3. If these ever stop straddling the claimed cap the
    # test has nothing to say, and it must say so rather than pass.
    if not (len(base_body) < ED25519_RAW_CAP < len(k2_body)):
        raise Refuse(
            f"the fixtures no longer straddle the {ED25519_RAW_CAP}-byte cap "
            f"({len(base_body)}, {len(k2_body)}); step 3 would be vacuous")

    created = {}
    try:
        # -- step 1 -------------------------------------------------- create keys
        try:
            for label, spec in (("ed25519", KEYSPEC_ED25519),
                                ("mldsa65", KEYSPEC_MLDSA65)):
                r = kms.create_key(KeySpec=spec, KeyUsage="SIGN_VERIFY",
                                   Description=f"ACP-104 compat probe ({spec})")
                created[label] = r["KeyMetadata"]["Arn"]
                print(f"  created {label}: {created[label]}")
            tr.step("1", "create ECC_NIST_EDWARDS25519 and ML_DSA_65 keys",
                    "PASS", f"both key specs accepted in {args.region}",
                    keys=dict(created))
        except ClientError as exc:
            code, msg = service_error(exc)
            tr.step("1", "create ECC_NIST_EDWARDS25519 and ML_DSA_65 keys",
                    "FAIL", f"{code}: {msg}", aws_error=code, aws_message=msg)
            return

        ed_arn, ml_arn = created["ed25519"], created["mldsa65"]

        # -- public halves -------------------------------------------------------
        gp = kms.get_public_key(KeyId=ed_arn)
        signing_algs = gp.get("SigningAlgorithms", [])
        print(f"  ed25519 key advertises: {signing_algs}")
        ed_pk = serialization.load_der_public_key(gp["PublicKey"])
        if not isinstance(ed_pk, Ed25519PublicKey):
            raise Refuse(f"{KEYSPEC_ED25519} returned a "
                         f"{type(ed_pk).__name__}, not an Ed25519 public key")

        gp_ml = kms.get_public_key(KeyId=ml_arn)
        ml_pk = raw_from_spki(gp_ml["PublicKey"], MLDSA65_PK_LEN, "ML_DSA_65")

        # A genuine all-KMS hybrid identity -- the production shape, not a
        # classical key padded with a local ML-DSA half.
        pub = HybridPub(ed_pk, ml_pk)
        print(f"  hybrid fingerprint: {pub.fingerprint()}")
        tr.env(hybrid_fingerprint=pub.fingerprint(),
               ed25519_signing_algorithms=signing_algs,
               mldsa65_signing_algorithms=gp_ml.get("SigningAlgorithms", []))

        # -- step 2 ------------------------------------ THE DECISIVE ASSERTION
        sig_pure = None
        try:
            resp = kms.sign(KeyId=ed_arn, Message=base_body,
                            MessageType=MSGTYPE_RAW,
                            SigningAlgorithm=ALG_ED25519_PURE)
            sig_pure = resp["Signature"]
            ok = verify_prim(pub, base_body, sig_pure.hex(), "classical")
            # The evidence is the VERIFICATION. Whether GetPublicKey also lists
            # the algorithm is a sanity line, recorded but not decisive -- a
            # claim proven by a verifier must not be failed by a listing, and
            # an earlier draft had the status and the explanation branching on
            # different conditions, so a pass could be reported as a failure.
            advertised = ALG_ED25519_PURE in signing_algs
            note = "" if advertised else (
                f"  (odd: GetPublicKey does not list {ALG_ED25519_PURE} in "
                f"{signing_algs}, yet it signed and verified)")
            tr.step(
                "2", f"{ALG_ED25519_PURE} + {MSGTYPE_RAW} is pure RFC 8032",
                "PASS" if ok else "FAIL",
                (("a plain RFC 8032 verifier accepted an AWS signature over the "
                  f"{len(base_body)}-byte body; the ACP-90 correction holds"
                  + note)
                 if ok else
                 "acp_crypto REFUSED the AWS signature over the raw body -- "
                 "ED25519_SHA_512 is not PureEdDSA as documented. ACP-90 "
                 "Finding 2 stands and ACP-102 does not rescue it."),
                signature_len=len(sig_pure),
                verified_by_reference=ok, advertised=advertised)
        except ClientError as exc:
            code, msg = service_error(exc)
            tr.step("2", f"{ALG_ED25519_PURE} + {MSGTYPE_RAW} is pure RFC 8032",
                    "FAIL", f"AWS refused to sign the raw body: {code}: {msg}",
                    aws_error=code, aws_message=msg)

        # -- step 3 ------------------------------------------ the cap is real
        try:
            kms.sign(KeyId=ed_arn, Message=k2_body, MessageType=MSGTYPE_RAW,
                     SigningAlgorithm=ALG_ED25519_PURE)
            tr.step("3", f"{MSGTYPE_RAW} refuses a body over {ED25519_RAW_CAP} B",
                    "FAIL",
                    f"AWS SIGNED a {len(k2_body)}-byte raw body. The "
                    f"{ED25519_RAW_CAP}-byte cap is not real, so the size "
                    f"premise of ACP-102 is wrong.")
        except ClientError as exc:
            code, msg = service_error(exc)
            names_size = _names_size(msg)
            tr.step("3", f"{MSGTYPE_RAW} refuses a body over {ED25519_RAW_CAP} B",
                    "PASS" if names_size else "FAIL",
                    (f"refused, naming the size: {code}: {msg}" if names_size else
                     f"refused, but NOT for size -- {code}: {msg}. This does "
                     f"not confirm the cap."),
                    aws_error=code, aws_message=msg, message_bytes=len(k2_body))

        # -- step 4 ------------------------------- EXTERNAL_MU on the big body
        try:
            mu = ML_DSA_65.prehash_external_mu(ml_pk, k2_body)
            resp = kms.sign(KeyId=ml_arn, Message=mu,
                            MessageType=MSGTYPE_EXTERNAL_MU,
                            SigningAlgorithm=ALG_MLDSA)
            sig_ml = resp["Signature"]
            ok = bool(ML_DSA_65.verify(ml_pk, k2_body, sig_ml))
            tr.step("4", f"{MSGTYPE_EXTERNAL_MU} yields an ordinary ML-DSA-65 "
                         "signature", "PASS" if ok else "FAIL",
                    (f"dilithium_py's plain verify accepted the KMS signature "
                     f"over the whole {len(k2_body)}-byte body"
                     if ok else
                     "plain verify REJECTED it: EXTERNAL_MU does not produce a "
                     "signature over the original message. The ML-DSA half has "
                     "no size escape."),
                    mu_bytes=len(mu), signature_len=len(sig_ml),
                    verified_by_reference=ok)
        except ClientError as exc:
            code, msg = service_error(exc)
            tr.step("4", f"{MSGTYPE_EXTERNAL_MU} yields an ordinary ML-DSA-65 "
                         "signature", "FAIL", f"{code}: {msg}",
                    aws_error=code, aws_message=msg)

        # -- step 5 ---------------------------------- the ph trap is detected
        #
        # The cheapest falsification of the whole ACP-90 correction, and the
        # only step that would go green if Finding 2 had been right all along.
        # It runs ONLY after step 2 produced a True from this same `pub`: a
        # False here must mean the algorithm differs, never that the key was
        # parsed wrong.
        if not tr.passed("2"):
            tr.step("5", f"{ALG_ED25519_PH} is rejected by the reference",
                    "NOT-RUN", "step 2 did not pass, so a rejection here would "
                               "be unattributable")
        elif ALG_ED25519_PH not in signing_algs:
            tr.step("5", f"{ALG_ED25519_PH} is rejected by the reference",
                    "NOT-RUN", f"this key does not advertise {ALG_ED25519_PH}: "
                               f"{signing_algs}")
        else:
            try:
                resp = kms.sign(
                    KeyId=ed_arn,
                    Message=hashlib.sha512(base_body).digest(),
                    MessageType=MSGTYPE_DIGEST,
                    SigningAlgorithm=ALG_ED25519_PH)
                sig_ph = resp["Signature"]
                # Anti-vacuity: the signature must EXIST and must differ from
                # the pure one. Without this a failed Sign call would satisfy
                # "the reference rejects it" by there being nothing to reject.
                produced = bool(sig_ph)
                differs = sig_pure is not None and sig_ph != sig_pure
                rejected = not verify_prim(pub, base_body, sig_ph.hex(),
                                           "classical")
                ok = produced and differs and rejected
                tr.step("5", f"{ALG_ED25519_PH} is rejected by the reference",
                        "PASS" if ok else "FAIL",
                        ("AWS produced a ph signature, it differs from the pure "
                         "one, and acp_crypto refuses it -- the two algorithms "
                         "are distinguishable and step 2 used the right one"
                         if ok else
                         f"produced={produced} differs={differs} "
                         f"rejected={rejected}. If rejected is False, a "
                         f"HashEdDSA signature passed a PureEdDSA verifier, "
                         f"which would be a defect in acp_crypto."),
                        produced=produced, differs_from_pure=differs,
                        rejected_by_reference=rejected)
            except ClientError as exc:
                code, msg = service_error(exc)
                tr.step("5", f"{ALG_ED25519_PH} is rejected by the reference",
                        "NOT-RUN", f"AWS would not produce a ph signature to "
                                   f"test against: {code}: {msg}",
                        aws_error=code, aws_message=msg)
    finally:
        for label, arn in created.items():
            print(f"\n  key {label}: {arn}")
            if args.keep_keys:
                print("    kept (--keep-keys). Delete it yourself; it bills "
                      "monthly.")
                continue
            try:
                r = kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7)
                print(f"    deletion scheduled for {r['DeletionDate']}")
            except Exception as exc:
                print(f"    !! COULD NOT SCHEDULE DELETION: {exc}")
                print("    !! delete it by hand or it bills monthly")


# ------------------------------------------------------------------ selfcheck
def selfcheck() -> int:
    """Everything provable without AWS, including the negative cases.

    NOT a substitute for the real run and never presented as one: it says
    nothing about what AWS does. It says this file is not broken, which is a
    different claim and a prerequisite for the other one -- a paid run against a
    broken DER unwrap would produce a failure at step 4 that reads exactly like
    "AWS EXTERNAL_MU is broken".

    Every positive assertion here is paired with the negative that makes it
    non-vacuous. A check that cannot fail is worthless, and worse than worthless
    in this repository, because it gets published as evidence.
    """
    bad = []

    def chk(name, cond, extra=""):
        print(f"  {'ok  ' if cond else 'FAIL'}  {name}{extra}")
        if not cond:
            bad.append(name)

    # -- the fixtures still straddle the claimed cap ---------------------------
    base, k2 = bodies()
    chk("receipt bodies come from the reference as canonical bytes",
        isinstance(base, bytes) and isinstance(k2, bytes))
    chk(f"base {len(base)} B < {ED25519_RAW_CAP} B cap < k=2 {len(k2)} B",
        len(base) < ED25519_RAW_CAP < len(k2))

    # -- the DER unwrap, both key sizes, and a truncation ----------------------
    ed_sk = Ed25519PrivateKey.generate()
    ed_pk = ed_sk.public_key()
    der = ed_pk.public_bytes(serialization.Encoding.DER,
                             serialization.PublicFormat.SubjectPublicKeyInfo)
    raw32 = ed_pk.public_bytes(serialization.Encoding.Raw,
                               serialization.PublicFormat.Raw)
    chk("raw_from_spki recovers a 32-byte Ed25519 key from a real SPKI",
        raw_from_spki(der, 32, "ed25519") == raw32)

    ml_pk, ml_sk = ML_DSA_65.keygen()
    chk(f"ML-DSA-65 public key is {MLDSA65_PK_LEN} B", len(ml_pk) == MLDSA65_PK_LEN,
        f" (got {len(ml_pk)})")

    def spki(raw):
        """SPKI with a LONG-FORM length, which is what a 1952-byte key forces."""
        def tlv(tag, body):
            if len(body) < 128:
                return bytes([tag, len(body)]) + body
            n = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
            return bytes([tag, 0x80 | len(n)]) + n + body
        algid = tlv(0x30, b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x12")
        return tlv(0x30, algid + tlv(0x03, b"\x00" + raw))

    chk("raw_from_spki recovers a 1952-byte key from a long-form SPKI",
        raw_from_spki(spki(ml_pk), MLDSA65_PK_LEN, "ml") == ml_pk)
    try:
        raw_from_spki(spki(ml_pk[:-1]), MLDSA65_PK_LEN, "ml")
        chk("a truncated key is REFUSED rather than returned short", False,
            " -- it was accepted")
    except Refuse as exc:
        chk("a truncated key is REFUSED rather than returned short",
            "1951" in str(exc), f" ({exc})")

    # -- step 2 and step 5 share a verifier, and it tells them apart -----------
    pub = HybridPub(ed_pk, ml_pk)
    sig_pure = ed_sk.sign(base)
    chk("step 2 shape: a pure Ed25519 signature over the body VERIFIES",
        verify_prim(pub, base, sig_pure.hex(), "classical") is True)
    # A ph signature is a signature over OTHER BYTES; this is that shape, and
    # it is what makes step 5 a test rather than a hope. If this ever returns
    # True, acp_crypto accepts HashEdDSA as PureEdDSA and the trap is undetectable.
    sig_other = ed_sk.sign(hashlib.sha512(base).digest())
    chk("step 5 shape: a signature over other bytes is REJECTED",
        verify_prim(pub, base, sig_other.hex(), "classical") is False)
    chk("step 5 shape: and it differs from the pure signature",
        sig_other != sig_pure)

    # -- the external-mu derivation, and a wrong-key negative -----------------
    mu = ML_DSA_65.prehash_external_mu(ml_pk, k2)
    chk("mu is 64 bytes", len(mu) == 64, f" (got {len(mu)})")
    chk("step 4 shape: an external-mu signature passes PLAIN verify over the "
        "whole body",
        ML_DSA_65.verify(ml_pk, k2, ML_DSA_65.sign_external_mu(ml_sk, mu)) is True)
    other_pk, _ = ML_DSA_65.keygen()
    wrong = ML_DSA_65.sign_external_mu(
        ml_sk, ML_DSA_65.prehash_external_mu(other_pk, k2))
    chk("step 4 shape: mu bound to a different public key does NOT verify",
        ML_DSA_65.verify(ml_pk, k2, wrong) is False)

    # -- the size matcher, both directions ------------------------------------
    for msg in ("1 validation error detected: Value at 'message' failed to "
                "satisfy constraint: Member must have length less than or "
                "equal to 4096",
                "Message size exceeds the maximum allowed",
                "the message is too long to sign"):
        chk("a size error is matched", _names_size(msg), f": {msg[:40]}...")
    # THE LOAD-BEARING HALF. Without these, step 3 would report the 4,096-byte
    # cap as confirmed by an IAM denial.
    for msg in ("User: arn:aws:iam::111:user/x is not authorized to perform: "
                "kms:Sign on resource: arn:aws:kms:...",
                "The request was rejected because the specified key is disabled."):
        chk("a non-size error is NOT counted as the cap", not _names_size(msg),
            f": {msg[:40]}...")

    # -- no account id reaches the committed transcript, by ANY route ---------
    # The second case is the one that matters and the one the first version of
    # this file got wrong: AWS quotes full ARNs back inside its own error text,
    # and a FAILING run is exactly the run that gets committed.
    dirty = {"steps": [
        {"id": "1", "keys": {"ed25519": "arn:aws:kms:us-east-1:123456789012:"
                                        "key/1234abcd-12ab-34cd"},
         "signature_len": 64, "verified_by_reference": True},
        {"id": "2", "aws_message": "User: arn:aws:iam::210987654321:user/x is "
                                   "not authorized to perform: kms:Sign on "
                                   "resource: arn:aws-cn:kms:cn-north-1:"
                                   "210987654321:key/z"},
        {"id": "3", "detail": "refused: Member must have length less than or "
                              "equal to 4096"}]}
    clean = scrub(dirty)
    flat = json.dumps(clean)
    chk("no account id survives scrub, from a key ARN or from AWS error text",
        "123456789012" not in flat and "210987654321" not in flat
        and flat.count("<account>") == 3)
    chk("scrub leaves the size limit and the byte counts alone",
        "4096" in flat and clean["steps"][0]["signature_len"] == 64
        and clean["steps"][0]["verified_by_reference"] is True)

    # -- an unrun step is not a passed step -----------------------------------
    tr = Transcript("selfcheck", quiet=True)
    tr.step("2", "-", "PASS", "-")
    tr.step("5", "-", "NOT-RUN", "-")
    chk("Transcript.passed distinguishes PASS from NOT-RUN",
        tr.passed("2") and not tr.passed("5"))

    print()
    if bad:
        print(f"kms-compat selfcheck FAILED: {len(bad)} broken -- {bad}")
        return 1
    print("kms-compat selfcheck passed: the local half is intact")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--region", default=os.environ.get("AWS_REGION"),
                    help="AWS region (or set AWS_REGION)")
    ap.add_argument("--keep-keys", action="store_true",
                    help="do not schedule the probe keys for deletion")
    ap.add_argument("--out", default=None,
                    help="transcript path (default tools/kms-compat-<date>.json)")
    ap.add_argument("--selfcheck", action="store_true",
                    help="exercise the local half; no AWS, no boto3, no cost")
    args = ap.parse_args()

    if args.selfcheck:
        return selfcheck()

    if not args.region:
        print("--region is required (or set AWS_REGION). It is recorded in the "
              "transcript, because 'unsupported in this region' and "
              "'unsupported' are different findings.", file=sys.stderr)
        return 2

    tr = Transcript(args.region)
    try:
        run(args, tr)
    except Refuse as exc:
        print(f"\nREFUSED: {exc}", file=sys.stderr)
        print("No transcript written. An environment that cannot produce "
              "evidence must not leave a file that looks like evidence.",
              file=sys.stderr)
        return 2

    steps = tr.doc["steps"]
    failed = [s["id"] for s in steps if s["status"] == "FAIL"]
    notrun = [s["id"] for s in steps if s["status"] == "NOT-RUN"]
    missing = [s for s in "12345" if not any(x["id"] == s for x in steps)]
    ok = not failed and not notrun and not missing

    tr.doc["verdict"] = "PASS" if ok else "FAIL"
    tr.doc["failed_steps"] = failed
    tr.doc["not_run_steps"] = notrun + missing

    out = args.out or os.path.join(
        HERE, f"kms-compat-{tr.doc['verified_as_of']}.json")
    with open(out, "w") as fh:
        json.dump(scrub(tr.doc), fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(f"\n{'=' * 70}")
    print(f"verdict: {tr.doc['verdict']}   "
          f"({len(steps) - len(failed) - len(notrun)}/5 pass, "
          f"{len(failed)} fail, {len(notrun) + len(missing)} not run)")
    print(f"transcript: {out}")
    if not ok:
        print("\nACP-104 done-when #5: if step 2 failed, reopen ACP-90 "
              "Finding 2 and mark ACP-102 not-sufficient. That is a SUCCESS "
              "of this test.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
