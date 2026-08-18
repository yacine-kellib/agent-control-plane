#!/usr/bin/env python3
"""
bundle_suite.py — Suite 11: the policy bundle (PB-1..PB-8, CR-3, CR-4).

The bundle is the rule store the whole control plane reads from, and PB-4 is
the claim that makes it worth having: runtime components — *including a fully
compromised Policy Engine* — hold no key capable of producing a valid bundle
signature. Policy is read-only to the runtime by cryptography, not by file
permissions.

THIS SUITE EXISTS BECAUSE THE CODE IS LOAD-BEARING. `sim/bundle.py` was
load-bearing with no gate line for several releases and silently dropped three
fields from a hash (ACP-35). `acp_bundle.py` is not going to repeat that shape,
so it gets a gate line on the day it lands rather than the release after.

What this does NOT cover is the cross-language half — Python and Rust agreeing
on the tree hash and on which refusal fires. That needs a Rust toolchain, so it
lives in `tools/check-bundle-differential.py` and runs from `tools/selftest.sh`.
Keeping it out of this gate keeps `verify.sh --suites` runnable with Python
alone, which is what "clone, run one command" means here.
"""
import os as _os
import sys

# Run-from-anywhere: see the note in conformance.py. isdir guard keeps it inert
# in mutation temp dirs so a mutant is never shadowed by the real module.
_SRC = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), _os.pardir, "src")
if _os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import json
import shutil
import tempfile

from acp_bundle import (
    BundleHost, Refused, Timestamp, WalkError, tree_hash, walk_bundle,
)
from acp_crypto import HybridKey, sign_prim

HYBRID = "hybrid-ed25519-mldsa65"
KEY = HybridKey(b"bundle-signing-key")
NOW = Timestamp.parse("2026-08-18T00:00:00Z")


def manifest(epoch=7, expires="2027-01-01T00:00:00Z", author="ana", reviewer="bo"):
    return json.dumps({
        "schema_version": "1", "bundle_epoch": epoch,
        "created_at": "2026-01-01T00:00:00Z",
        "author": {"id": author, "display_name": "A"},
        "reviewer": {"id": reviewer, "display_name": "R"},
        "expires_at": expires, "min_suite": HYBRID,
        "custody": {"tier": "T3", "classical": "x", "pq": "y"},
    }).encode()


def registry(k=2, keys=("ka", "kb")):
    return json.dumps({
        "schema_version": "1", "quorum_k": k,
        "attesters": {f"p{i}": {"classical": v, "pq": v} for i, v in enumerate(keys)},
    }).encode()


def members(**kw):
    return [
        ("manifest.json", manifest(**kw)),
        ("floors.json", b'{"payments":"T3"}'),
        ("attesters/registry.json", registry()),
    ]


def sign(ms, suite=HYBRID, key=KEY):
    """Sign the tree hash. One signature value per primitive the suite names."""
    import hashlib
    digest = bytes.fromhex(tree_hash(suite, ms).removeprefix("sha256:"))
    assert digest == hashlib.sha256(
        __import__("acp_bundle").tree_bytes(suite, ms)).digest()
    from acp_executor import SUITES
    return {p: sign_prim(key, digest, p).hex() for p in SUITES[suite]}


def host(**kw):
    return BundleHost(KEY.public(), HYBRID, **kw)


def activated(**kw):
    ms = members(**kw)
    h = host()
    h.activate(ms, HYBRID, sign(ms), NOW)
    return h, ms


def refuses(fn, expected):
    """Assert a refusal fires AND that it is the right one."""
    try:
        fn()
        return False, "accepted"
    except Refused as r:
        return r.name == expected, f"{r.name} (wanted {expected})"


# --------------------------------------------------------------- the cases

def t_genuine_bundle_activates_and_reads():
    h, _ = activated()
    value, serving = h.read("floors.json", NOW)
    return value == b'{"payments":"T3"}' and serving == "Normal", serving


def t_member_edited_after_activation_is_refused():
    # THE POINT OF VERIFY-ON-READ. The bundle activated cleanly; the store
    # behind it was then compromised, which is the scenario a signature is for.
    h, ms = activated()
    h.read("floors.json", NOW)
    ms[1] = ("floors.json", b'{"payments":"T1"}')
    return refuses(lambda: h.read("floors.json", NOW), "SignatureInvalid")


def t_forged_bundle_with_generous_expiry_fails_for_the_signature():
    # ORDER OF OPERATIONS: the forged manifest claims validity until 2099, so a
    # verifier parsing expiry first would ask the attacker when the attacker's
    # bundle expires. Asserting the VARIANT is the only way to know which check
    # fired.
    ms = members(expires="2099-01-01T00:00:00Z")
    forged = sign(ms, key=HybridKey(b"not-the-bundle-key"))
    return refuses(lambda: host().activate(ms, HYBRID, forged, NOW), "SignatureInvalid")


def t_stripped_pq_leg_is_refused():
    # CR-3 at the bundle: the classical signature is genuine and only the
    # post-quantum leg is missing.
    ms = members()
    sig = sign(ms)
    del sig["pq"]
    return refuses(lambda: host().activate(ms, HYBRID, sig, NOW), "SignatureInvalid")


def t_one_leg_presented_twice_does_not_stand_in_for_two():
    ms = members()
    sig = sign(ms)
    sig = {"classical": sig["classical"], "pq": sig["classical"]}
    return refuses(lambda: host().activate(ms, HYBRID, sig, NOW), "SignatureInvalid")


def t_suite_below_the_floor_is_refused():
    ms = members()
    sig = sign(ms, suite="ed25519")
    return refuses(lambda: host().activate(ms, "ed25519", sig, NOW), "SuiteBelowFloor")


def t_expired_bundle_is_refused():
    ms = members(expires="2026-08-17T00:00:00Z")
    return refuses(lambda: host().activate(ms, HYBRID, sign(ms), NOW), "Expired")


def t_grace_window_serves_capped_at_attest():
    ms = members(expires="2026-08-18T00:00:00Z")
    h = host(grace_seconds=86400)
    h.activate(ms, HYBRID, sign(ms), NOW)
    _, serving = h.read("floors.json", Timestamp.parse("2026-08-18T06:00:00Z"))
    return serving == "CappedAtAttest", serving


def t_past_the_grace_window_the_read_is_refused():
    ms = members(expires="2026-08-18T00:00:00Z")
    h = host(grace_seconds=3600)
    h.activate(ms, HYBRID, sign(ms), NOW)
    return refuses(lambda: h.read("floors.json", Timestamp.parse("2026-08-18T02:00:00Z")),
                   "Expired")


def t_expiry_is_enforced_on_read_not_only_at_activation():
    h, _ = activated(expires="2026-08-18T12:00:00Z")
    h.read("floors.json", Timestamp.parse("2026-08-18T11:00:00Z"))
    return refuses(lambda: h.read("floors.json", Timestamp.parse("2026-08-19T00:00:00Z")),
                   "Expired")


def t_lower_epoch_is_refused_as_rollback():
    # The superseded bundle is GENUINE and internally consistent, which is why
    # nothing inside it can catch this. The durable mark is the only thing in
    # the way.
    h, _ = activated()
    older = members(epoch=6)
    return refuses(lambda: h.activate(older, HYBRID, sign(older), NOW), "EpochRollback")


def t_re_serving_the_current_epoch_is_refused():
    h, _ = activated()
    same = members()
    same[1] = ("floors.json", b'{"payments":"T1"}')
    return refuses(lambda: h.activate(same, HYBRID, sign(same), NOW), "EpochRollback")


def t_higher_epoch_replaces_the_active_bundle():
    h, _ = activated()
    newer = members(epoch=8)
    h.activate(newer, HYBRID, sign(newer), NOW)
    return h.active_epoch == 8 and h.high_water == 8, f"epoch {h.active_epoch}"


def t_refused_activation_leaves_the_previous_bundle_serving():
    # PB-3's atomic half: a rejected candidate must not leave the host with no
    # bundle, or an attacker takes the control plane down by offering rubbish.
    h, _ = activated()
    forged = members(epoch=8)
    try:
        h.activate(forged, HYBRID, sign(forged, key=HybridKey(b"other")), NOW)
    except Refused:
        pass
    value, _ = h.read("floors.json", NOW)
    return value == b'{"payments":"T3"}' and h.high_water == 7, f"hw {h.high_water}"


def t_restored_host_refuses_a_rollback_before_it_has_a_bundle():
    # RAD-3: the window between a restart and the first activation is the
    # cheapest moment to serve a superseded bundle.
    h = host(high_water=7)
    older = members(epoch=6)
    return refuses(lambda: h.activate(older, HYBRID, sign(older), NOW), "EpochRollback")


def t_author_and_reviewer_must_differ():
    ms = members(author="ana", reviewer="ana")
    return refuses(lambda: host().activate(ms, HYBRID, sign(ms), NOW), "AuthorIsReviewer")


def t_two_attesters_sharing_a_key_are_refused():
    # PB-7: one private key signs two objects differing only in their nonces,
    # labelled with two names, satisfying k=2 alone.
    ms = members()
    ms[2] = ("attesters/registry.json", registry(keys=("same", "same")))
    return refuses(lambda: host().activate(ms, HYBRID, sign(ms), NOW),
                   "RegistryKeysNotDistinct")


def t_absent_quorum_k_is_refused_not_defaulted():
    ms = members()
    ms[2] = ("attesters/registry.json",
             json.dumps({"schema_version": "1",
                         "attesters": {"a": {"classical": "x", "pq": "x"}}}).encode())
    return refuses(lambda: host().activate(ms, HYBRID, sign(ms), NOW), "QuorumInvalid")


def t_reading_without_an_active_bundle_is_refused():
    return refuses(lambda: host().read("floors.json", NOW), "NoActiveBundle")


# ----------------------------------------------------------------- the walk

def _bundle_dir():
    root = tempfile.mkdtemp()
    _os.makedirs(_os.path.join(root, "attesters"))
    for path, content in members():
        with open(_os.path.join(root, *path.split("/")), "wb") as fh:
            fh.write(content)
    return root


def t_walk_covers_the_attester_registry():
    # PB-KEY: with the registry outside the hash, two Executors trusting
    # DIFFERENT attesters agree they hold the same bundle, so
    # policy_bundle_hash stops determining who was allowed to approve.
    root = _bundle_dir()
    try:
        before = tree_hash(HYBRID, walk_bundle(root))
        with open(_os.path.join(root, "attesters", "registry.json"), "wb") as fh:
            fh.write(registry(keys=("kx", "ky")))
        after = tree_hash(HYBRID, walk_bundle(root))
        return before != after, "hash moved" if before != after else "UNCHANGED"
    finally:
        shutil.rmtree(root)


def t_walk_excludes_the_signature_at_the_root():
    root = _bundle_dir()
    try:
        before = tree_hash(HYBRID, walk_bundle(root))
        with open(_os.path.join(root, "SIGNATURE"), "wb") as fh:
            fh.write(b"not-a-real-signature")
        return tree_hash(HYBRID, walk_bundle(root)) == before, "excluded"
    finally:
        shutil.rmtree(root)


def t_walk_halts_on_an_unrecognised_file_type():
    # Skipping is the dangerous variant: an unsigned file inside a signed
    # bundle is exactly what the signature exists to deny.
    root = _bundle_dir()
    try:
        with open(_os.path.join(root, "helper.sh"), "wb") as fh:
            fh.write(b"#!/bin/sh\n")
        try:
            walk_bundle(root)
            return False, "accepted"
        except WalkError as e:
            return e.kind == "UnrecognisedFileType", e.kind
    finally:
        shutil.rmtree(root)


def t_walk_refuses_a_symlink():
    root = _bundle_dir()
    try:
        _os.symlink("/etc/hosts", _os.path.join(root, "outside.json"))
        try:
            walk_bundle(root)
            return False, "accepted"
        except WalkError as e:
            return e.kind == "Symlink", e.kind
    finally:
        shutil.rmtree(root)


def t_walk_refuses_an_empty_bundle():
    root = tempfile.mkdtemp()
    try:
        try:
            tree_hash(HYBRID, walk_bundle(root))
            return False, "accepted"
        except WalkError as e:
            return e.kind == "Empty", e.kind
    finally:
        shutil.rmtree(root)


# ------------------------------------------------------------- timestamps

def t_impossible_dates_are_refused():
    # A range check of 1..31 lets 2026-02-31 through and the arithmetic rolls
    # it to 2026-03-03 -- three days of validity nobody granted. Live defect,
    # found in Rust first.
    bad = ["2026-02-31T00:00:00Z", "2026-02-29T00:00:00Z", "2026-04-31T00:00:00Z",
           "2100-02-29T00:00:00Z", "2026-01-00T00:00:00Z", "2026-08-18T23:59:60Z"]
    good = ["2024-02-29T00:00:00Z", "2000-02-29T00:00:00Z", "2026-01-31T00:00:00Z"]
    for s in bad:
        if Timestamp.parse(s) is not None:
            return False, f"accepted {s}"
    for s in good:
        if Timestamp.parse(s) is None:
            return False, f"refused {s}"
    return True, f"{len(bad)} refused, {len(good)} accepted"


def t_permissive_spellings_are_refused_not_normalised():
    for s in ["2026-08-18T00:00:00+00:00", "2026-08-18T00:00:00.000Z",
              "2026-08-18t00:00:00z", "2026-08-18 00:00:00Z", "2026-13-01T00:00:00Z", ""]:
        if Timestamp.parse(s) is not None:
            return False, f"accepted {s}"
    return True, "6 refused"


def t_epoch_conversion_matches_datetime():
    import datetime as dt
    for s in ["1970-01-01T00:00:00Z", "2000-03-01T00:00:00Z",
              "2026-08-18T00:00:00Z", "2038-01-19T03:14:07Z"]:
        want = int(dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
                   .replace(tzinfo=dt.timezone.utc).timestamp())
        if Timestamp.parse(s).unix != want:
            return False, f"{s}: {Timestamp.parse(s).unix} != {want}"
    return True, "4 instants"


TESTS = [(n[2:].replace("_", " "), f) for n, f in sorted(globals().items())
         if n.startswith("t_") and callable(f)]


def main():
    print("=" * 74)
    print("SUITE 11 — POLICY BUNDLE (PB-1..PB-8, CR-3, CR-4)")
    print("=" * 74)
    fails = 0
    for name, fn in TESTS:
        try:
            ok, detail = fn()
        except Exception as ex:
            ok, detail = False, f"unexpected {type(ex).__name__}: {ex}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<52} {detail}")
        fails += not ok
    print("=" * 74)
    print(f"RESULT: {len(TESTS)-fails}/{len(TESTS)}"
          f"{' — the bundle holds' if not fails else ' — REVIEW REQUIRED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
