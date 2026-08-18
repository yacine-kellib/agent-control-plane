#!/usr/bin/env python3
"""Verify, with the Python reference, signatures the Rust signer produced.

THE OTHER DIRECTION. `crates/acp-crypto/tests/python_interop.rs` proves Rust
accepts what Python signed. That is half a differential pair: it shows the Rust
verifier is permissive enough to accept a correct signature, and says nothing
about whether the Rust *signer* produces one. Until `custody.rs` there was no
Rust signer to ask, and both `acp_crypto/src/lib.rs` and the interop test named
this as an obligation nobody had discharged. This is the discharge.

    python3 tools/check-rust-signatures.py

Runs the `emit_signatures` example, then verifies every signature it printed
with `reference/src/acp_crypto.py` — the same functions the conformance suite
uses, not a checker written for this script.

NOTHING IS COMMITTED. The signatures are generated and consumed in one run, so
unlike `gen-crypto-vectors.py` there is no stored fixture that can quietly stop
describing the code. The trade is that this needs a Rust toolchain, which is why
it is a tools/ script rather than a cargo test.

The keys are ALSO re-derived here from the declared seeds and compared, so a
pass means the two implementations agreed on the identity and on the signature.
Verifying against a public key Rust itself printed would be a closed loop: any
consistent-but-wrong derivation would verify against itself perfectly.
"""
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "reference" / "src"))

from acp_crypto import HybridKey, verify_prim  # noqa: E402


def emit() -> dict:
    """Run the Rust example and parse what it printed."""
    run = subprocess.run(
        ["cargo", "run", "--quiet", "--package", "acp-crypto",
         "--example", "emit_signatures"],
        cwd=REPO, capture_output=True, text=True)
    if run.returncode != 0:
        print("FAIL  the Rust signer did not run")
        print(run.stderr.strip()[-2000:])
        sys.exit(1)
    try:
        return json.loads(run.stdout)
    except json.JSONDecodeError as e:
        print(f"FAIL  the Rust signer printed invalid JSON: {e}")
        print(run.stdout[:2000])
        sys.exit(1)


def main() -> int:
    data = emit()
    msg = data["message_utf8"].encode()
    keys = data["keys"]
    bad = 0

    # A vacuous pass here would make every assertion below trivially true.
    if len(keys) < 3:
        print(f"FAIL  expected at least 3 signed identities, got {len(keys)}")
        return 1

    for k in keys:
        seed = k["seed_utf8"]
        # Derived independently from the declared seed. If this used the public
        # key Rust printed, the check would verify Rust against itself.
        pub = HybridKey(seed.encode()).public()

        if pub.fingerprint() != k["fingerprint"]:
            print(f"FAIL  {seed}: identity diverged; Rust says {k['fingerprint']}, "
                  f"Python derives {pub.fingerprint()}")
            bad += 1
            continue

        for prim, field in (("classical", "ed25519_sig_hex"), ("pq", "mldsa65_sig_hex")):
            if not verify_prim(pub, msg, k[field], prim):
                print(f"FAIL  {seed}: Python refused the Rust {prim} signature")
                bad += 1

        # Non-vacuity, per identity rather than once: if verify_prim returned
        # True unconditionally -- the failure mode that looks like success --
        # every line above would pass and this would not.
        if verify_prim(pub, msg + b"!", k["ed25519_sig_hex"], "classical"):
            print(f"FAIL  {seed}: Python accepted a classical signature over a "
                  f"different message")
            bad += 1
        if verify_prim(pub, msg + b"!", k["mldsa65_sig_hex"], "pq"):
            print(f"FAIL  {seed}: Python accepted a post-quantum signature over a "
                  f"different message")
            bad += 1

    if bad:
        print(f"{bad} problem(s)")
        return 1
    print(f"verified {len(keys)} Rust-signed identities, both primitives each")
    return 0


if __name__ == "__main__":
    sys.exit(main())
