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
    return json.dumps({
        "schema_version": "1", "quorum_k": k,
        "attesters": {f"p{i}": {"classical": v, "pq": v} for i, v in enumerate(keys)},
    }, indent=1).encode()


def build(root, *, suite=HYBRID, key=KEY, strip_pq=False, no_quorum=False, **kw):
    """Write a bundle directory and sign it with the PYTHON implementation."""
    os.makedirs(os.path.join(root, "attesters"), exist_ok=True)
    # Popped BEFORE the dict literal: every value in a literal is evaluated,
    # so popping inside it left `keys` in the kwargs `manifest` receives.
    attester_keys = kw.pop("keys", None)
    if no_quorum:
        registry_bytes = json.dumps(
            {"schema_version": "1",
             "attesters": {"a": {"classical": "x", "pq": "x"}}}, indent=1).encode()
    elif attester_keys is not None:
        registry_bytes = registry(keys=attester_keys)
    else:
        registry_bytes = registry()
    files = {
        "manifest.json": manifest(**kw),
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
    ("shared-attester-key", {"keys": ("same", "same")}, {},
     "PB-7: one private key satisfying a k=2 quorum alone"),
    ("absent-quorum-k", {"no_quorum": True}, {},
     "PB-6: refused rather than defaulted"),
    ("epoch-rollback", {"epoch": 6}, {"high_water": 7},
     "PB-5: a genuine, internally consistent, superseded bundle"),
    ("suite-below-floor", {"suite": "ed25519"}, {},
     "CR-4: containment, not rank"),
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
        print(f"python and rust agree on {len(CASES)} bundles: hash, verdict and refusal")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
