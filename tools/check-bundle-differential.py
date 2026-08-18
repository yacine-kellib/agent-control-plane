#!/usr/bin/env python3
"""Python and Rust must agree on a bundle: the same hash, the same verdict, the
same refusal.

ACP-38's and ACP-39's acceptance criteria, discharged. `reference/` is the
differential partner for Rust, and the first divergence between the two on a
shared input is a SPECIFICATION AMBIGUITY rather than a bug to patch around --
that is how Z1 was found. Two implementations that never meet on one input are
two codebases; this is where they meet.

    python3 tools/check-bundle-differential.py

Each case below builds a real bundle directory, has PYTHON sign it, then asks
both implementations what they make of it. Python's signature and Rust's
verification means the SIGNATURE envelope (PB-8) is exercised as wire format
rather than assumed compatible.

The comparison is on the REFUSAL NAME, not merely on accept/refuse. Two
implementations that both refuse for different reasons agree on nothing useful:
an operator reading "expired" when the truth is "forged" is being told the
wrong thing, and the class of bug that produces it -- checks running in the
wrong order -- is exactly what this pair is meant to surface.

Read the agreement with its limit, which the spec states in §15: a second
implementation written by consulting the first inherits the first's errors.
Agreement is evidence about consistency and never about correctness.

Needs a Rust toolchain, which is why this lives in tools/ and runs from
selftest.sh rather than from `verify.sh --suites` -- that gate stays runnable
with Python alone.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "reference" / "src"))

from acp_bundle import (  # noqa: E402
    BundleHost, Refused, Timestamp, tree_hash, walk_bundle,
)
from acp_crypto import HybridKey, sign_prim  # noqa: E402
from acp_executor import SUITES  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402

HYBRID = "hybrid-ed25519-mldsa65"
KEY = HybridKey(b"bundle-signing-key")
NOW = "2026-08-18T00:00:00Z"
BIN = REPO / "target" / "debug" / "acp-bundle"


def manifest(epoch=7, expires="2027-01-01T00:00:00Z", author="ana", reviewer="bo"):
    return json.dumps({
        "schema_version": "1", "bundle_epoch": epoch,
        "created_at": "2026-01-01T00:00:00Z",
        "author": {"id": author, "display_name": "A"},
        "reviewer": {"id": reviewer, "display_name": "R"},
        "expires_at": expires, "min_suite": HYBRID,
        "custody": {"tier": "T3", "classical": "x", "pq": "y"},
    }, indent=1).encode()


def registry(k=2, keys=("ka", "kb")):
    return registry_of(k, [("approver", v, v) for v in keys])


def registry_of(k, entries):
    """A registry with per-entry control of role, classical and pq.

    The old fixture set both legs from one string and emitted no `role`, so
    "shares a key" and "is byte-identical" were the same condition and the one
    PB-7 case here passed against a check that compared whole entries. Both
    implementations were wrong in the same way and this file agreed with itself
    (ACP-53) -- which is §15's limit arriving in the tool built to test for it.
    """
    return json.dumps({
        "schema_version": "1", "quorum_k": k,
        "attesters": {
            f"p{i}": {k: v for k, v in
                      (("role", r), ("classical", c), ("pq", q)) if v is not None}
            for i, (r, c, q) in enumerate(entries)},
    }, indent=1).encode()


def manifest_of(**patch):
    """The default manifest with fields REPLACED or dropped.

    Added for ACP-44. The shaped helpers above cannot express a manifest whose
    `bundle_epoch` is a string or whose `author` is not an object, and a fixture
    that cannot express the shape cannot test for it -- which is the lesson
    ACP-53 left behind one file over.
    """
    obj = json.loads(manifest())
    for field, value in patch.items():
        if value is DROP:
            obj.pop(field, None)
        else:
            obj[field] = value
    return json.dumps(obj, indent=1).encode()


def registry_patched(**patch):
    """The default registry with fields REPLACED or dropped. See manifest_of."""
    obj = json.loads(registry())
    for field, value in patch.items():
        if value is DROP:
            obj.pop(field, None)
        else:
            obj[field] = value
    return json.dumps(obj, indent=1).encode()


class _Drop:
    """Sentinel: this field is absent, which is a different case from null."""


DROP = _Drop()


def build(root, *, suite=HYBRID, key=KEY, strip_pq=False, no_quorum=False, **kw):
    """Write a bundle directory and sign it with the PYTHON implementation."""
    os.makedirs(os.path.join(root, "attesters"), exist_ok=True)
    # Popped BEFORE the dict literal: every value in a literal is evaluated,
    # so popping inside it left `keys` in the kwargs `manifest` receives.
    attester_keys = kw.pop("keys", None)
    attester_entries = kw.pop("entries", None)
    # ACP-44. Verbatim documents, for the shapes the helpers cannot build.
    manifest_bytes = kw.pop("manifest_bytes", None)
    registry_bytes_verbatim = kw.pop("registry_bytes", None)
    if registry_bytes_verbatim is not None:
        registry_bytes = registry_bytes_verbatim
    elif no_quorum:
        registry_bytes = json.dumps(
            {"schema_version": "1",
             "attesters": {"a": {"classical": "x", "pq": "x"}}}, indent=1).encode()
    elif attester_entries is not None:
        registry_bytes = registry_of(2, attester_entries)
    elif attester_keys is not None:
        registry_bytes = registry(keys=attester_keys)
    else:
        registry_bytes = registry()
    files = {
        "manifest.json": manifest_bytes if manifest_bytes is not None else manifest(**kw),
        "floors.json": b'{"payments":"T3"}\n',
        "attesters/registry.json": registry_bytes,
    }
    for rel, content in files.items():
        with open(os.path.join(root, *rel.split("/")), "wb") as fh:
            fh.write(content)

    members = walk_bundle(root)
    digest = bytes.fromhex(tree_hash(suite, members).removeprefix("sha256:"))
    parts = {p: sign_prim(key, digest, p).hex() for p in SUITES[suite]}
    if strip_pq:
        del parts["pq"]
    with open(os.path.join(root, "SIGNATURE"), "w") as fh:
        json.dump({"suite": suite, "parts": parts}, fh, indent=2)
    return members, suite, parts


def rust_verdict(root, *, floor=HYBRID, now=NOW, grace=0, high_water=None):
    """Ask the Rust CLI. Returns 'OK <serving>' or 'REFUSED <Name>'."""
    pub = os.path.join(root, "..", "pub.json")
    argv = [str(BIN), "verify", root, "--pubkey", pub, "--now", now,
            "--floor", floor, "--grace", str(grace)]
    if high_water is not None:
        argv += ["--high-water", str(high_water)]
    run = subprocess.run(argv, capture_output=True, text=True)
    out = run.stdout.strip()
    if not out:
        return f"ERROR {run.stderr.strip()[:200]}"
    return out


def python_verdict(root, *, floor=HYBRID, now=NOW, grace=0, high_water=None):
    """Ask the Python reference the same question, the same way."""
    with open(os.path.join(root, "SIGNATURE")) as fh:
        envelope = json.load(fh)
    try:
        members = walk_bundle(root)
    except Exception as e:  # a walk refusal is not a bundle verdict
        return f"ERROR walk {e}"

    host = BundleHost(KEY.public(), floor, grace_seconds=grace, high_water=high_water)
    ts = Timestamp.parse(now)
    try:
        host.activate(members, envelope["suite"], envelope["parts"], ts)
        _, serving = host.read("manifest.json", ts)
        return f"OK {serving}"
    except Refused as r:
        return f"REFUSED {r.name}"


# name -> (build kwargs, verdict kwargs, what the case is for)
CASES = [
    ("genuine", {}, {}, "the positive path -- without it every refusal below is vacuous"),
    ("forged-signature", {"key": HybridKey(b"not-the-bundle-key")}, {},
     "PB-1: a signature from a key the verifier was not configured with"),
    ("stripped-pq-leg", {"strip_pq": True}, {},
     "CR-3: the classical leg is genuine and the post-quantum one is gone"),
    ("expired", {"expires": "2026-08-17T00:00:00Z"}, {},
     "PB-1: past expiry with no grace window"),
    ("inside-grace", {"expires": "2026-08-18T00:00:00Z"},
     {"now": "2026-08-18T06:00:00Z", "grace": 86400},
     "PB-1: served, but capped at ATTEST"),
    ("past-grace", {"expires": "2026-08-18T00:00:00Z"},
     {"now": "2026-08-18T02:00:00Z", "grace": 3600},
     "PB-1: beyond the window, refused"),
    ("author-is-reviewer", {"author": "ana", "reviewer": "ana"}, {},
     "PB-2: two-person integrity, compared on id"),
    # PB-7, all four shapes. Until ACP-53 only the first was here, and it was
    # the only one either implementation caught -- the check compared whole
    # entries, so anything differing anywhere in the entry walked through. Both
    # were wrong identically, so this file agreed and reported agreement, which
    # is exactly what §15 says a differential cannot rule out.
    ("shared-attester-key", {"keys": ("same", "same")}, {},
     "PB-7: one private key satisfying a k=2 quorum alone"),
    ("shared-key-different-roles",
     {"entries": [("approver", "same", "same"), ("confirmer", "same", "same")]}, {},
     "PB-7: a role is not a verification key -- and approver+confirmer is the "
     "pairing DR-9 demands at floor-HIGH"),
    ("shared-pq-leg-only",
     {"entries": [("approver", "ka", "shared"), ("approver", "kb", "shared")]}, {},
     "PB-7: the case the old code comment claimed to handle and did not"),
    ("shared-classical-leg-only",
     {"entries": [("approver", "shared", "ka"), ("approver", "shared", "kb")]}, {},
     "PB-7: either leg colliding is a collision, not both"),
    ("distinct-attesters",
     {"entries": [("approver", "ka", "pa"), ("confirmer", "kb", "pb")]}, {},
     "PB-7 positive path: without it the four refusals above are satisfied by "
     "a check that refuses everything"),
    ("attester-with-no-key",
     {"entries": [("approver", "ka", "pa"), ("confirmer", "kb", None)]}, {},
     "a key that is absent cannot be shown distinct from anything"),
    ("absent-quorum-k", {"no_quorum": True}, {},
     "PB-6: refused rather than defaulted"),
    ("epoch-rollback", {"epoch": 6}, {"high_water": 7},
     "PB-5: a genuine, internally consistent, superseded bundle"),
    ("suite-below-floor", {"suite": "ed25519"}, {},
     "CR-4: containment, not rank"),

    # ------------------------------------------------------------------ ACP-44
    # THE ABSENCES AND WRONG SHAPES. Added when verify.rs stopped coercing
    # fields with as_str()/as_u64()/as_object() and started promoting each one
    # into the type spec/schemas/bundle/ declares for it.
    #
    # They are here because that migration is exactly the kind that looks
    # behaviour-preserving and is not: a whole-document deserialise collapses
    # every distinct absence into ONE parse error, and the refusals below are
    # distinguishable BY DESIGN. Committed as data so the next migration is
    # guarded by a command rather than by whoever is reviewing it.
    ("quorum-k-string", {"registry_bytes": registry_patched(quorum_k="2")}, {},
     "PB-6: a threshold that is not an integer is QuorumInvalid, NOT Malformed "
     "-- the distinction a whole-document parse would destroy"),
    ("quorum-k-zero", {"registry_bytes": registry_patched(quorum_k=0)}, {},
     "PB-6: zero attesters is not a quorum"),
    ("quorum-k-negative", {"registry_bytes": registry_patched(quorum_k=-1)}, {},
     "PB-6: and neither is a negative one. The TRAP in this migration: typing "
     "quorum_k u64 turns this into a deserialisation failure unless the field "
     "is promoted on its own"),
    ("quorum-k-above-i64",
     {"registry_bytes": registry_patched(quorum_k=2 ** 63)}, {},
     "PB-6's rule is 'absent or below 1'. Rust refused this as QuorumInvalid "
     "until ACP-44 because as_i64() overflowed -- the accessor's range showing "
     "through as a policy verdict. THIS CASE WAS RED BEFORE THE MIGRATION"),
    ("epoch-string", {"manifest_bytes": manifest_of(bundle_epoch="7")}, {},
     "PB-5: an epoch that is not an integer"),
    ("expires-at-number",
     {"manifest_bytes": manifest_of(expires_at=1787011200)}, {},
     "PB-1: an expiry that is not a string. A unix integer is not RFC 3339 and "
     "must not be read as one"),
    ("expires-at-unparseable",
     {"manifest_bytes": manifest_of(expires_at="the day after tomorrow")}, {},
     "PB-1: well-typed and not a timestamp"),
    ("author-not-an-object", {"manifest_bytes": manifest_of(author="ana")}, {},
     "PB-2: an identity is an object with an id, not a bare name"),
    ("author-id-not-a-string",
     {"manifest_bytes": manifest_of(author={"id": 5, "display_name": "A"})}, {},
     "PB-2 compares ids byte-for-byte; a number is not an id"),
    ("attesters-is-an-array",
     {"registry_bytes": registry_patched(
         attesters=[{"classical": "ka", "pq": "pa"}])}, {},
     "PB-7: identity -> key is a MAP. An array has no identities, so nothing "
     "can be shown distinct"),
    ("attester-entry-is-a-string",
     {"registry_bytes": registry_patched(attesters={
         "p0": "i-am-a-string", "p1": {"classical": "kb", "pq": "pb"}})}, {},
     "an entry with no fields has no keys"),
    ("custody-absent", {"manifest_bytes": manifest_of(custody=DROP)}, {},
     "custody is schema-REQUIRED and READ BY NOTHING. The schema classifies it "
     "T and a verifier MUST NOT weight a decision on it, so its absence cannot "
     "be a refusal"),
    ("custody-malformed",
     {"manifest_bytes": manifest_of(custody={"tier": 9, "classical": ["x"]})}, {},
     "and neither can its shape -- otherwise a compromised signer holds a "
     "refusal switch over a field nobody reads (RES-8)"),
    ("manifest-unknown-fields",
     {"manifest_bytes": manifest_of(future_field={"a": 1}, another="x")}, {},
     "a field this build does not know is not a field this build refuses on. "
     "The strict projections carry deny_unknown_fields; the verifier must not"),
    ("manifest-empty", {"manifest_bytes": b"{}"}, {},
     "every field absent at once. Whichever check fires first, both "
     "implementations must name the SAME one"),

    # The shapes that decide whether the attester legs may be typed `String`.
    # They may not: the reference compares them as written, and PB-7 asks
    # whether two identities carry the same key, never whether a key is well
    # formed. Keys are named p0/p1/p2 because Rust walks the map sorted and
    # Python in insertion order -- sorted names keep the two walks identical.
    ("attester-legs-numeric-shared",
     {"registry_bytes": registry_patched(attesters={
         "p0": {"classical": 1, "pq": 2}, "p1": {"classical": 1, "pq": 4}})}, {},
     "PB-7: a collision is a collision whatever the key is written as"),
    ("attester-legs-null-shared",
     {"registry_bytes": registry_patched(attesters={
         "p0": {"classical": None, "pq": "a"},
         "p1": {"classical": None, "pq": "b"}})}, {},
     "PB-7, and the sharpest of these: serde reads a null into Option::None, so "
     "a typed leg would report a present-and-colliding key as ABSENT"),
    ("attester-legs-numeric-distinct",
     {"registry_bytes": registry_patched(attesters={
         "p0": {"classical": 1, "pq": 2}, "p1": {"classical": 3, "pq": 4}})}, {},
     "the positive path for the three above, or they are satisfied by a check "
     "that refuses everything"),
    ("attester-role-not-a-string",
     {"registry_bytes": registry_patched(attesters={
         "p0": {"role": 7, "classical": "ka", "pq": "pa"},
         "p1": {"role": 8, "classical": "kb", "pq": "pb"}})}, {},
     "ACP-53: a role is not a verification key. It is not read, so its type "
     "cannot be a refusal either"),
    ("display-name-not-a-string",
     {"manifest_bytes": manifest_of(author={"id": "ana", "display_name": 7})}, {},
     "PB-2 forbids comparing display_name, so its type cannot refuse a bundle"),
    ("collision-before-a-bad-entry",
     {"registry_bytes": registry_patched(attesters={
         "p0": {"classical": "same", "pq": "a"},
         "p1": {"classical": "same", "pq": "b"},
         "p2": "i-am-a-string"})}, {},
     "ORDER. The collision at p1 must fire before the malformed p2 is reached, "
     "or an operator is told the registry is malformed when the truth is that "
     "one key holder enrolled twice"),
    ("bad-entry-before-collision",
     {"registry_bytes": registry_patched(attesters={
         "p0": "i-am-a-string",
         "p1": {"classical": "same", "pq": "a"},
         "p2": {"classical": "same", "pq": "b"}})}, {},
     "the mirror image, so the case above is about ORDER and not about one of "
     "the two refusals always winning"),
]

# Where the two implementations DISAGREE today. PINNED, not hidden.
#
# A differential that quietly omits its disagreements reports agreement it has
# not earned. Each entry asserts BOTH sides' current verdicts, so the pin fails
# if either moves -- including when the defect is fixed, which is the point:
# fixing it must force this list to shrink rather than let the tool keep
# printing a stale exception. They do not count toward the agreement total.
#
# ONE DEFECT, three shapes: the Python reference does not bound its integers to
# the domain the schema declares. `bundle_epoch` is `integer, minimum 0` and
# `quorum_k` is `integer, minimum 1`; Python's ints are unbounded and its
# isinstance() tests carry neither the sign bound nor the 64-bit one, so it
# accepts values Rust refuses. Rust is right on all three and the fix belongs in
# reference/src/acp_bundle.py, which is not this file's to edit.
KNOWN_DIVERGENCES = [
    ("epoch-negative", {"manifest_bytes": manifest_of(bundle_epoch=-1)}, {},
     "REFUSED Malformed", "OK Normal",
     "PB-5 counts upward from zero (schema: integer, minimum 0). The reference "
     "accepts a negative epoch, so a high-water mark can be seeded below zero"),
    ("epoch-above-u64",
     {"manifest_bytes": manifest_of(bundle_epoch=2 ** 64)}, {},
     "REFUSED Malformed", "OK Normal",
     "the same defect at the other end: the reference has no upper bound where "
     "the schema-derived Rust type has u64"),
    ("quorum-k-above-u64",
     {"registry_bytes": registry_patched(quorum_k=2 ** 64)}, {},
     "REFUSED QuorumInvalid", "OK Normal",
     "and again on quorum_k, which is why the three are one finding"),
]


def main() -> int:
    if not BIN.exists():
        print(f"FAIL  {BIN} does not exist -- run `cargo build -p acp-bundle-cli`")
        return 1

    work = tempfile.mkdtemp()
    try:
        # The verifier's key, configured OUT OF BAND -- the whole point of
        # RES-8. Written once, beside the bundles rather than inside them.
        pub = KEY.public()
        with open(os.path.join(work, "pub.json"), "w") as fh:
            json.dump({
                "ed25519_pk_hex": pub.ed_pk.public_bytes(
                    ser.Encoding.Raw, ser.PublicFormat.Raw).hex(),
                "mldsa65_pk_hex": pub.ml_pk.hex(),
            }, fh)

        bad = 0
        agreed = 0
        for name, build_kw, verdict_kw, why in CASES:
            root = os.path.join(work, name)
            os.makedirs(root)
            build(root, **build_kw)

            # (1) THE TREE HASH. Rust's `list` walks the directory itself, so a
            # disagreement here is a disagreement about what the bundle IS,
            # before anything about what it means.
            run = subprocess.run(
                [str(BIN), "list", root, "--suite", build_kw.get("suite", HYBRID)],
                capture_output=True, text=True)
            rust_hash = ""
            for token in run.stdout.split():
                if token.startswith("sha256:"):
                    rust_hash = token
            py_hash = tree_hash(build_kw.get("suite", HYBRID), walk_bundle(root))
            if rust_hash != py_hash:
                print(f"FAIL  {name}: tree hash diverges\n"
                      f"        rust   {rust_hash}\n        python {py_hash}")
                bad += 1

            # (2) THE VERDICT, including WHICH refusal.
            r = rust_verdict(root, **verdict_kw)
            p = python_verdict(root, **verdict_kw)
            if r != p:
                print(f"FAIL  {name}: verdicts diverge ({why})\n"
                      f"        rust   {r}\n        python {p}")
                bad += 1
            else:
                agreed += 1
                print(f"  ok  {name:<22} {p}")

        # The pinned disagreements. Asserted on BOTH sides, so that fixing the
        # reference turns this red and forces the entry to be rewritten as an
        # ordinary case rather than left as a stale exception.
        for name, build_kw, verdict_kw, want_rust, want_python, why in KNOWN_DIVERGENCES:
            root = os.path.join(work, name)
            os.makedirs(root)
            build(root, **build_kw)
            r = rust_verdict(root, **verdict_kw)
            p = python_verdict(root, **verdict_kw)
            if (r, p) == (want_rust, want_python):
                print(f" PIN  {name:<22} rust={r} / python={p}  ({why})")
            elif r == p:
                print(f"FAIL  {name}: the divergence is GONE ({r}). Move this "
                      f"case out of KNOWN_DIVERGENCES and into CASES.")
                bad += 1
            else:
                print(f"FAIL  {name}: the divergence MOVED\n"
                      f"        rust   {r}  (pinned {want_rust})\n"
                      f"        python {p}  (pinned {want_python})")
                bad += 1

        # Non-vacuity: a run where every case errored would print no
        # divergences and mean nothing.
        if agreed < len(CASES):
            print(f"{len(CASES) - agreed} case(s) did not agree")
        if any(v.startswith("ERROR") for v in [python_verdict(
                os.path.join(work, "genuine"))]):
            print("FAIL  the positive path errored; the suite proves nothing")
            bad += 1

        if bad:
            print(f"{bad} divergence(s)")
            return 1
        print(f"python and rust agree on {len(CASES)} bundles: hash, verdict "
              f"and refusal, with {len(KNOWN_DIVERGENCES)} pinned divergence(s) "
              f"in the reference's integer bounds")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
