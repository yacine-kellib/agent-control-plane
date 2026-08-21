#!/usr/bin/env python3
"""WE-4 / AT-1: the reference and the schema must accept the same nonces.

There are three definitions of the attestation nonce's type in this repository
and there must be exactly one language:

  1. `reference/src/acp_executor.py` -- `WE4_B64` and `AT1_NONCE_LEN`
  2. `spec/schemas/wire/attestation_object.schema.json` -- the `pattern`
  3. `crates/acp-decision/src/quorum.rs` -- `is_we4_b64` and `AT1_NONCE_LEN`

This checks 1 against 2. The Rust test `we4_and_at1_agree_with_the_reference_on
_the_shared_corpus` checks 3 against the SAME corpus file, and
`tools/check-decision-differential.py` compares 1 against 3 on the conformance
cases -- so every pair is pinned by something executable.

WHY IT EXISTS. Definitions 1 and 2 diverged for a full release and every gate
stayed green. The schema pinned `{22}==` from the day it was written; the
reference accepted `b64:` plus any length with optional padding; and no fixture
anywhere fed a wrong-length nonce, so nothing ever evaluated the two on an input
that told them apart. Aligning them by hand -- which is what ACP-88 started out
as -- fixes the drift that happened and not the next one. A corpus does.

The corpus asserts the refusal NAME, not merely that something was refused. A
check that refuses under the wrong clause has told its reader something false,
and WE-4 and AT-1 are exactly the pair that invites the confusion: a 64-bit
nonce is a well-formed `b64:` value, so a check folding the size into the type
answers `WE-4` for a violation of `AT-1`.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "reference" / "src"))

from acp_executor import AT1_NONCE_LEN, WE4_B64  # noqa: E402

CORPUS = ROOT / "tools" / "nonce-type-vectors.json"
SCHEMA = ROOT / "spec" / "schemas" / "wire" / "attestation_object.schema.json"


def reference_verdict(value):
    """The reference's two rules, in the order `acp_executor` applies them.

    The ORDER is part of the claim. A value wrong in both ways must stop at the
    same rule everywhere, or two implementations that agree about the object
    disagree about the name they refuse it under.
    """
    if not WE4_B64.match(value):
        return "WE-4"
    if len(value) != AT1_NONCE_LEN:
        return "AT-1"
    return None


def main():
    corpus = json.loads(CORPUS.read_text())
    schema = json.loads(SCHEMA.read_text())
    pattern = schema["properties"]["att_nonce"]["pattern"]
    schema_re = re.compile(pattern)

    cases = corpus["cases"]
    if len(cases) < 10:
        print(f"FAIL: corpus holds {len(cases)} cases -- too few to constrain anything")
        return 1

    failures = []
    for case in cases:
        value, want = case["value"], case["clause"]
        got = reference_verdict(value)
        if got != want:
            failures.append(f"reference answered {got!r}, corpus declares {want!r}"
                            f" for {value!r}\n      {case['why']}")
            continue
        # The schema has ONE verdict where the reference has two, so the
        # comparison is conformance against conformance. A schema that accepted
        # a value the reference refuses would let a generated implementation
        # build objects this one rejects, and vice versa.
        if bool(schema_re.match(value)) != (got is None):
            failures.append(
                f"the schema and the reference disagree about {value!r}: schema "
                f"{'accepts' if schema_re.match(value) else 'refuses'}, reference "
                f"{'accepts' if got is None else f'refuses at {got}'}"
                f"\n      {case['why']}")

    print("=" * 74)
    print("WE-4 / AT-1 -- the nonce type has one language across three definitions")
    print("=" * 74)
    print(f"  corpus:    {len(cases)} cases, {sum(c['clause'] is None for c in cases)} conforming")
    print(f"  reference: WE4_B64 = {WE4_B64.pattern}")
    print(f"             AT1_NONCE_LEN = {AT1_NONCE_LEN}")
    print(f"  schema:    {pattern}")
    for f in failures:
        print(f"  FAIL  {f}")
    print("=" * 74)
    if failures:
        print(f"RESULT: {len(failures)} disagreement(s) -- the definitions have drifted")
        return 1
    print("RESULT: PASS -- reference and schema accept exactly the same nonces")
    return 0


if __name__ == "__main__":
    sys.exit(main())
