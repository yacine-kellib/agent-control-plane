# 07 — Reproduction

Every claim in this dossier is replayable. If one is not, it should not be believed.

## Prerequisites

```bash
python3 -m pip install --break-system-packages cryptography dilithium-py
# Dafny 4.9.1: https://github.com/dafny-lang/dafny/releases/tag/v4.9.1
```

## The two gates

```bash
./tools/verify.sh --suites   # proofs + all 13 suites. No release key needed.
./tools/verify.sh            # the above, plus integrity and signature.
```

`--suites` is the gate every commit is measured against. A clean run prints **15** result lines — 1 prerequisites, 1 proofs, 13 suites — and no failures. It is not a reduced gate: it runs every suite the full command runs.

The full command additionally proves the bytes on your disk are the signed release bytes.

**Between releases, sections 1 and 2 are expected to be red, and that is not a finding.** The manifest is signed with an offline key held by one person, so only a commit that person has signed can make integrity and signature green. A red integrity line on a working tree, or on any branch that is not a tagged release, is a property of offline signing — not tampering, and not a broken claim. Check integrity against a release tag; check behaviour with `--suites` anywhere.

This distinction is stated here rather than left for a reader to discover, because a security dossier whose first command prints red teaches exactly the wrong reflex: that red is normal and can be clicked past.

**Never repair a red integrity line by regenerating `MANIFEST.sha256`.** A regenerated manifest whose signature no longer verifies is strictly worse than a stale one, and only the key holder can restore it.

## Verify dossier integrity

```bash
sha256sum -c MANIFEST.sha256
./tools/sign-release.sh list   # what the manifest should cover, no key needed
```

## Replay the formal proofs

```bash
dafny verify --function-syntax:4 reference/proofs/binding.dfy
# expected: 36 verified, 0 errors
```

**Recommended negative control** — do not believe a proof result without checking that it can fail:

```bash
# remove binding clause (ii) from Verify_v133, then re-verify
# expected: 2 errors on BindingSound and Y1_AttackBlocked_Generalized
```

## The consolidated attack registry

```bash
python3 reference/suites/attack_registry.py             # all 73, grouped by suite
python3 reference/suites/attack_registry.py --explain   # each with what it does and why
python3 reference/suites/attack_registry.py --coverage  # which clause each attack exercises
python3 reference/suites/attack_registry.py --compose   # acknowledgement x partitioned ledger
python3 reference/suites/attack_registry.py -i          # interactive browser
```

Every attack is declared once here with the rule it targets and a plain-language statement of what it does. `--coverage` also lists what **no** attack covers and why: A-7, A-8, T-32 and RR-1.

Until v1.3.12 the attacks lived in eight separate files, so a reader running `conformance.py` saw 44/44 and reasonably took it for the whole surface — it is the v1.3.5 historical set, and 33 attacks added since lived elsewhere. Worse, the newer machinery never met the distributed ledger: `--compose` closes that, and it is the first test of an acknowledgement arriving during a partition, which matters because ACK-5's single-use guarantee depends on the ledger.

## Replay the tests

```bash
python3 reference/suites/conformance.py           # expected: 44/44 CONFORMANT
python3 reference/suites/mutate_executor.py       # expected: 19/19 killed
python3 reference/suites/partition_suite.py       # expected: 9/9 CL-6 HOLDS
python3 reference/suites/partition_integration.py # expected: 6/6 INTEGRATION HOLDS
python3 reference/suites/cbor_suite.py            # expected: 8/8 AT-8a HOLDS
python3 reference/suites/class_findings.py        # expected: T-32 reproduced; T-31 closed in v1.3.12
python3 reference/suites/ack_suite.py             # expected: 14/14 T-31 CLOSED
python3 reference/suites/ack_suite.py --mutate    # expected: 6/6 killed
python3 reference/suites/audit_suite.py           # expected: 11/11 AC-5/AU-6/AU-7/AU-8 HOLD
python3 reference/suites/audit_suite.py --mutate  # expected: 4/4 killed
python3 reference/src/acp_crypto.py          # performance measurement
python3 reference/suites/diff_prose.py            # expected: Z1 divergences detected
```

## Replay the performance measurement

The figures in §05 are machine-dependent. What should hold:
- signature size ratio ≈ 53× (algorithm-bound)
- hybrid p99 well above 25 ms on a pure-Python reference implementation

## Attack this dossier

Where a sceptical reader gets the best return, in order:

0. **`acp_audit.py` (Suite 7)** — newest code in the dossier, added in v1.3.11. Three defects surfaced while writing it; the pattern says there is another.
1. **AC-5, AU-7, CL-7** — the newest fixes. The document's own pattern says the next defect is there.
2. **DR-2 path separation** — an architectural property, not provable by the model.
3. **§§6–7 ingress** — never attacked by a third party.
4. **The Dafny model itself** — check the theorems are not vacuous: the non-vacuity witnesses are there to be audited.
