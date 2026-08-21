#!/usr/bin/env python3
"""Python and Rust must agree on §9.3: the same verdict, and the same rule.

ACP-45's acceptance criterion, discharged as far as it can honestly be
discharged today. `reference/` is Rust's differential partner, and the first
divergence between them on a shared input is a SPECIFICATION AMBIGUITY rather
than a bug to patch around -- that is how Z1 was found.

    python3 tools/check-decision-differential.py
    python3 tools/check-decision-differential.py --selfcheck
    python3 tools/check-decision-differential.py --table

WHAT IS COMPARED. For each conformance case, the §9.3 checklist is driven on
BOTH implementations from ONE set of inputs -- the exact receipt, proposal and
bundle the reference Executor itself was handed -- and the answers must match
on the verdict, on the recomputed risk, on the operator, and, when the answer
is a refusal, on WHICH CLAUSE FIRED. Two implementations that both refuse a
forged, expired receipt -- one saying `9.3-1`, the other `9.3-5` -- have not
been shown to agree on anything an operator could act on. The clause is the
payload; that is the entire reason refusals carry names.

THE CASE LIST IS NOT WRITTEN HERE. It is `conformance.py`'s, imported. A second
list of case names would be a second definition of one object, which is the
defect this repository has published corrections for three times. The
consequence is deliberate: adding a case to `conformance.py` turns THIS RED
until someone classifies it, and no silent cap can creep in.

WHY THE CRITERION IS PARTIAL, AND WHY THAT IS SAID OUT LOUD. The ticket asks
for agreement on all 53 cases. `acp-decision` implements the STATELESS half of
§9.3. Nineteen cases turn on machinery that does not exist yet -- a durable
ledger (ACP-46), the Context Store (§8.8, no provider chosen), or the
deferred-release gate (ACP-47) -- and running them would compare a real
implementation against an absent one. They are BLOCKED, each named with its
owner, and the count is printed rather than quietly excluded. A suite that
reports all-pass on its first run has usually been written to agree with
itself.

THE HARNESS PROVES ITSELF FIRST. `--selfcheck` must catch BOTH failure modes it
exists to catch -- a verdict divergence AND a same-verdict-different-clause
divergence -- because the second is the one this comparison was built for and
the one a naive comparator misses. A run reporting "0 divergences" from a
comparator that cannot see one is indistinguishable from a healthy run, and
that is the vacuous-green failure this repository is most exposed to.
"""
import argparse
import copy
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "reference" / "src"))
sys.path.insert(0, str(ROOT / "reference" / "suites"))

import conformance as C  # noqa: E402
from acp_executor import Executor, FailClosed  # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402

EXAMPLE = ["cargo", "run", "-q", "-p", "acp-decision", "--example", "decide_batch", "--"]

# --------------------------------------------------------------- classification
#
# Every conformance case is RUST (comparable today) or blocked by a named piece
# of machinery. The reason strings are not decoration: they are what the run
# prints instead of a silently smaller denominator.
#
# The split is DERIVED, not remembered. A case is blocked iff the reference's
# §9.3 verdict for it depends on state or on a component `acp-decision` does
# not have, and `crates/acp-decision/src/decide.rs::UNIMPLEMENTED_STEPS` carries
# the same list from the other side. `steps_and_classification_agree` in
# selftest.sh asserts the two do not drift.
LEDGER = "ACP-46 — needs a ledger that survives restart"
CONTEXT = "Context Store — §8.8 names three provider classes; none is chosen"
DOOR = "ACP-47 — the deferred-release gate and the two doors"
BUNDLE = "acp-bundle — refused at bundle load, before §9.3 is entered"

BLOCKED = {
    # --- positives
    "DS-6 re-drive dedup": LEDGER,
    # --- attacks whose refusal IS the missing machinery
    "Z3  origin substitution": LEDGER,
    "T15 epoch rollback": LEDGER,
    "T13 receipt nonce replay": LEDGER,
    "T14 attestation replay": LEDGER,
    "T10 capability revoked in window": CONTEXT,
    "PB-DISTINCT one key, two names": BUNDLE,
    "DR-1 release before hold elapsed": DOOR,
    "DR-2 notifier proxies approval UI": DOOR,
    "DR-2 shared render library": DOOR,
    "DR-8 notification undeliverable": DOOR,
    "DR-8 no reachable recipients": DOOR,
    "DR-5 repudiation by non-recipient": DOOR,
    "DR-6 hold outlives receipt": DOOR,
    "DR-6 hold exceeds L-14 ceiling": DOOR,
    "DR-9 irreversible silent release": DOOR,
    "DR-9 operator confirms own action": DOOR,
    "DR-10 sampled silent release": DOOR,
    "RV-1 unclassified defaults irrev.": DOOR,
}

# ------------------------------------------------------------------- pinned
#
# Disclosed divergences, asserted FROM BOTH SIDES (the ACP-54 pattern). If one
# disappears or moves, this goes red rather than passing quietly: a divergence
# nobody re-checks is indistinguishable from one that was silently fixed and
# from one that silently got worse.
PINNED = {
    # ACP-82. An UNKNOWN `alg` on a receipt: the reference names CR-4, Rust
    # names CR-1, and the specification is on Rust's side.
    #
    # CR-4 (§1126) is satisfied "iff the suite it names CONTAINS every primitive
    # the floor's suite names". That predicate ranges over the set of primitives
    # a suite denotes. An unregistered name denotes no set, so the containment
    # test is not false for it -- it is UNDEFINED, and CR-1 ("an unregistered or
    # unknown suite MUST fail closed") is the clause that governs. §1282 names
    # this exact shape as a defect class neither differential nor mutation
    # testing reaches: "a requirement whose comparison is undefined over its
    # domain (CR-4's ordering)".
    #
    # Both sides fail closed, so nothing executes that should not. What differs
    # is what the operator is TOLD, and the remediation each answer implies:
    # "below the floor" says raise the receipt's suite, "unknown suite" says the
    # name is not registered. That is the whole reason refusals carry names, and
    # it is what this harness exists to compare.
    #
    # NOT fixed here, on either side. `conformance.py` records CR-4 as the
    # expected clause for this case, so correcting the reference changes a
    # conformance expectation -- a normative decision that belongs in the
    # specification first and in both implementations at once. Pinned from both
    # sides so it cannot move silently in either direction.
    "CR-1 unknown suite": (
        "REFUSED\tCR-4", "REFUSED\tCR-1",
        "an unknown alg: the reference reports CR-4 (a containment test that is "
        "undefined over an unregistered name); Rust reports CR-1, which §1121 "
        "governs. See ACP-82.",
    ),
}


def wire_key(vk):
    """A verification key as the Rust driver reads it. PUBLIC halves only."""
    return {
        "classical": vk.ed_pk.public_bytes(
            _ser.Encoding.Raw, _ser.PublicFormat.Raw).hex(),
        "pq": vk.ml_pk.hex(),
    }


def wire_bundle(b):
    """The verifier's own copy of the bundle, in the generated types' shape.

    `policy_bundle_hash` is PASSED, not derived on the Rust side, and that is a
    disclosed residual rather than an oversight -- see decide.rs's module docs
    and ACP-81. The reference's `Bundle.hash()` digests an ad-hoc in-memory
    dict; the specification's `policy_bundle_hash` is SHA-256 of the canonical
    bundle tree (§8.2, PB-8), which is what `acp-bundle` implements and what a
    deployment would supply. The two cannot agree by construction, so the
    harness hands both implementations the verifier's own value. That is not
    RES-8: it comes from the bundle, never from the receipt under verification.
    """
    return {
        "epoch": b.epoch,
        "quorum_k": b.quorum_k,
        "min_suite": b.min_suite,
        "policy_bundle_hash": b.hash(),
        "floors": {"schema_version": "1", "floors": b.floors},
        "risk_functions": {"schema_version": "1", "risk_functions": b.risk_functions},
        "reversibility": {"schema_version": "1", "reversibility": b.reversibility},
        "notice_targets": {"schema_version": "1", "notice_targets": b.notice_targets},
        "adapters": b.adapters,
        "attesters": {who: wire_key(k) for who, k in b.attester_keys.items()},
        "receipt_key": wire_key(b.receipt_key),
    }


def capture():
    """Run every conformance case, recording what §9.3 was asked and answered.

    The inputs are taken from INSIDE `Executor.execute`, which is the only way
    to be sure both implementations see the same bytes. Rebuilding the fixtures
    here would produce a second corpus that can drift from the one the
    conformance suite actually runs -- and a differential over inputs nobody
    else uses proves agreement about nothing anybody ships.
    """
    captured = {}
    original = Executor.execute
    current = {"name": None}

    def spy(self, receipt, proposal, **kw):
        rec = captured.setdefault(current["name"], [])
        entry = {
            "now": receipt.get("_now"),
            "receipt": copy.deepcopy(receipt),
            "proposal": copy.deepcopy(proposal),
            "bundle": wire_bundle(self.bundle),
            "verdict": None,
        }
        rec.append(entry)
        try:
            out = original(self, receipt, proposal, **kw)
        except FailClosed as e:
            entry["verdict"] = f"REFUSED\t{e.rule}"
            raise
        # The verdict is: did §9.3 pass, at what recomputed risk, for which
        # operator. WHAT HAPPENS NEXT IS DELIBERATELY NOT COMPARED.
        #
        # The reference returns `pending_release` when a floor-HIGH action is
        # handed to the deferred gate — but only `if self.gate is not None`, so
        # the same receipt under the same policy comes back "executed" from an
        # Executor with no gate configured and "held" from one with. That is a
        # fact about the DEPLOYMENT, not about §9.3, and `acp-decision` is a
        # crate that cannot know it. Comparing the two made `honest floor-HIGH`
        # (no gate) and `deferred hold then release` (gate) look like a
        # divergence when the checklist had reached identical conclusions.
        #
        # (Noted in passing for ACP-47, not chased here: an Executor with no
        # gate skips DR-1 at floor-HIGH entirely. An absent component silently
        # disabling a control is the inverse of the fail-safe-default rule this
        # repository already publishes a correction about.)
        entry["verdict"] = f"PASSED\t{out.get('risk')}\t{out.get('operator')}"
        return out

    Executor.execute = spy
    try:
        for name, fn in C.POSITIVE:
            current["name"] = name
            try:
                fn()
            except Exception:  # noqa: BLE001 -- the case's own outcome is not this tool's subject
                pass
        for name, fn, _expect in C.ATTACKS:
            current["name"] = name
            try:
                fn()
            except Exception:  # noqa: BLE001
                pass
    finally:
        Executor.execute = original
    return captured


def classify(captured):
    """Split the case list, and refuse to run if anything is unaccounted for."""
    names = [n for n, _ in C.POSITIVE] + [n for n, _, _ in C.ATTACKS]
    problems = []

    unknown = sorted(set(BLOCKED) - set(names))
    if unknown:
        problems.append(
            f"BLOCKED names {len(unknown)} case(s) conformance.py does not have: "
            f"{unknown}. A stale exemption silently shrinks the denominator.")

    runnable, blocked = [], []
    for n in names:
        if n in BLOCKED:
            blocked.append(n)
        elif n not in captured:
            # A case that never reached §9.3 and is not classified. This is the
            # arm that catches a NEW conformance case: it is not blocked, and
            # there is nothing to compare, so it must be classified by a human.
            problems.append(
                f"case {n!r} never reached Executor.execute and is not in "
                f"BLOCKED. Classify it before this harness can mean anything.")
        else:
            runnable.append(n)
    return runnable, blocked, problems


def rust(cases):
    """Build once, run once. Returns name -> line."""
    build = subprocess.run(
        ["cargo", "build", "-q", "-p", "acp-decision", "--example", "decide_batch"],
        cwd=ROOT, capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stderr[-3000:], file=sys.stderr)
        raise SystemExit("cargo build failed — the differential did NOT run")

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(cases, fh)
        path = fh.name
    try:
        proc = subprocess.run(EXAMPLE + [path], cwd=ROOT, capture_output=True, text=True)
    finally:
        pathlib.Path(path).unlink(missing_ok=True)

    if proc.returncode != 0:
        print(proc.stderr[-3000:], file=sys.stderr)
        raise SystemExit("decide_batch failed — the differential did NOT run")

    out = {}
    for line in proc.stdout.splitlines():
        name, _, rest = line.partition("\t")
        out[name] = rest
    return out


def build_cases(captured, runnable):
    """One Rust case per §9.3 invocation, keyed so a multi-call case is visible."""
    cases, expect = [], {}
    for name in runnable:
        for i, entry in enumerate(captured[name]):
            key = name if len(captured[name]) == 1 else f"{name} #{i + 1}"
            cases.append({
                "name": key,
                "now": entry["now"],
                "receipt": entry["receipt"],
                "proposal": entry["proposal"],
                "bundle": entry["bundle"],
            })
            expect[key] = entry["verdict"]
    return cases, expect


def kind_probe():
    """ACP-80, pinned ACROSS languages: `kind` decides quorum membership and no
    signature covers it.

    WHY THIS IS NOT A CONFORMANCE CASE. `conformance.py` has none, so the
    capture-based corpus above cannot reach it — a corpus derived from a case
    list only exercises what that list contains, which is the enumeration limit
    T-33 records. The Rust side has its own test; without this probe the two
    implementations would agree about `kind` only by coincidence, and either one
    could be fixed unilaterally without anything going red.

    THE EXPERIMENT. Two runs whose inputs differ in ONE BYTE of unsigned wire
    data — `"confirmation"` vs `"approval"` on one entry. Identical Attestation
    Objects, identical genuine signatures, identical everything a signature
    covers. The outcome flips from refused to accepted, in BOTH implementations.

    Asserted three ways, because the interesting one is the third:
      1. both refuse the first input, under the same clause;
      2. both accept the second;
      3. the two outcomes DIFFER — without which the probe is satisfied by an
         implementation where `kind` changes nothing, and the whole finding
         would be reported as confirmed by a run that never demonstrated it.
    """
    b, ex = C.fresh()
    p = C.proposal()
    phash = C.h(p)
    obj1 = C.att_obj(b, phash, 1600.0)
    # WE-4 and AT-1: a nonce must be `b64:` + RFC 4648 sec 4 base64 with
    # padding, AND 128-bit. This probe used a bare "n2" until WE-4 landed, and
    # Python then refused at WE-4 BEFORE reaching the `kind` logic -- which
    # silently turned an ACP-80 reproduction into a type refusal and would have
    # read as "ACP-80 no longer reproduces".
    #
    # IT HAPPENED A SECOND TIME, one clause later. The hand-written value that
    # fixed the first break was well-formed but 112-bit, so ACP-88's AT-1 length
    # rule refused it at AT-1 and the probe stopped reproducing again -- same
    # failure, different clause, and the fix that "obviously" held did not.
    # Derived through `C.b64n` now rather than typed, so it tracks whatever the
    # conformance fixtures use and cannot drift from them by hand again.
    #
    # Both breaks were caught by the same property: the harness asserts the
    # probe still REPRODUCES, not merely that the two languages agree. Two
    # languages agreeing on a refusal neither of them was supposed to reach is
    # the vacuous green this whole file exists to refuse.
    obj2 = dict(obj1, att_nonce=C.b64n("n2-acp80-probe"))

    def run(kind_of_second, nonce):
        # A FRESH Executor per run: the ledger claims nonces and attestation
        # ids single-use, so reusing one would refuse the second run under CL-2
        # or CL-3 and the probe would "prove" the flip using replay protection.
        _b, _ex = C.fresh()
        entries = [C.entry(obj1, C.A1, "approval"),
                   C.entry(obj2, C.A2, kind_of_second)]
        r = C.receipt(_b, p, atts=entries, nonce=nonce)
        case = {"name": f"kind={kind_of_second}", "now": r["_now"],
                "receipt": copy.deepcopy(r), "proposal": copy.deepcopy(p),
                "bundle": wire_bundle(_b)}
        try:
            out = _ex.execute(r, p)
            py = f"PASSED\t{out.get('risk')}\t{out.get('operator')}"
        except FailClosed as e:
            py = f"REFUSED\t{e.rule}"
        return case, py

    case_a, py_a = run("confirmation", "kind-probe-1")
    case_b, py_b = run("approval", "kind-probe-2")
    got = rust([case_a, case_b])
    rs_a, rs_b = got.get(case_a["name"], "<missing>"), got.get(case_b["name"], "<missing>")

    bad = 0
    if py_a != rs_a:
        print(f"  \033[31mFAIL\033[0m kind=confirmation diverges: python {py_a} / rust {rs_a}")
        bad += 1
    if py_b != rs_b:
        print(f"  \033[31mFAIL\033[0m kind=approval diverges: python {py_b} / rust {rs_b}")
        bad += 1
    # The non-vacuity assertion, and the one that carries the finding.
    if py_a == py_b:
        print(f"  \033[31mFAIL\033[0m ACP-80 no longer reproduces: flipping `kind` changed "
              f"nothing (both {py_a}). If `kind` became signature-covered or stopped "
              f"deciding membership, this probe must be REWRITTEN, not deleted.")
        bad += 1
    if bad == 0:
        print(f"  \033[32mOK\033[0m   ACP-80 pinned in BOTH languages: one byte of unsigned "
              f"wire data flips {py_a.split(chr(9))[0]} -> {py_b.split(chr(9))[0]} "
              f"(python and rust agree on both)")
    return bad


def report_table(runnable, blocked):
    total = len(C.POSITIVE) + len(C.ATTACKS)
    print(f"  {total} conformance cases: {len(runnable)} compared, {len(blocked)} blocked\n")
    by_reason = {}
    for n in blocked:
        by_reason.setdefault(BLOCKED[n], []).append(n)
    for reason, names in sorted(by_reason.items()):
        print(f"  BLOCKED ({len(names)}) — {reason}")
        for n in sorted(names):
            print(f"      {n}")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selfcheck", action="store_true",
                    help="prove the comparator can see a divergence, then exit")
    ap.add_argument("--table", action="store_true",
                    help="print the classification and exit")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--inject-stale", action="store_true",
                    help="add a BLOCKED entry naming a case conformance.py does not "
                         "have, so the gate can prove the stale-exemption detector "
                         "FIRES. A detector nobody makes fail is a detector nobody "
                         "has tested, and a stale exemption is the failure mode that "
                         "still prints green — it shrinks the denominator silently.")
    args = ap.parse_args()

    if args.inject_stale:
        BLOCKED["a case conformance.py does not have"] = LEDGER

    if args.selfcheck:
        return selfcheck()

    captured = capture()
    runnable, blocked, problems = classify(captured)
    if problems:
        for p in problems:
            print(f"  \033[31mFAIL\033[0m {p}")
        return 1

    if args.table:
        report_table(runnable, blocked)
        return 0

    total = len(C.POSITIVE) + len(C.ATTACKS)
    cases, expect = build_cases(captured, runnable)
    got = rust(cases)

    # NON-VACUITY, asserted before the comparison rather than inferred from it.
    # A run that compared nothing would print no divergences and mean nothing,
    # and "0 divergences" is exactly what a healthy run prints.
    if not cases:
        print("  \033[31mFAIL\033[0m no cases were compared — this run is vacuous")
        return 1
    missing = sorted(set(expect) - set(got))
    if missing:
        print(f"  \033[31mFAIL\033[0m Rust returned no line for {len(missing)} case(s): {missing[:3]}")
        return 1

    bad, agreed, pinned_ok = 0, 0, 0
    for key in expect:
        want, have = expect[key], got[key]
        base = key.split(" #")[0]
        if base in PINNED:
            want_py, want_rs, why = PINNED[base]
            if (want, have) == (want_py, want_rs):
                pinned_ok += 1
                if not args.quiet:
                    print(f"  PIN  {key:<36} python={want} / rust={have}")
                continue
            print(f"  \033[31mFAIL\033[0m {key}: the pinned divergence moved\n"
                  f"        why    {why}\n"
                  f"        python {want}  (pinned {want_py})\n"
                  f"        rust   {have}  (pinned {want_rs})")
            bad += 1
            continue
        if want == have:
            agreed += 1
            if not args.quiet:
                print(f"  ok   {key:<36} {want}")
        else:
            bad += 1
            print(f"  \033[31mFAIL\033[0m {key}: §9.3 diverges\n"
                  f"        python {want}\n"
                  f"        rust   {have}")

    # ACP-80 lives outside the conformance corpus, so it is probed separately.
    # A corpus derived from a case list can only exercise what that list holds.
    bad += kind_probe()

    print()
    if bad:
        print(f"  \033[31m{bad} divergence(s)\033[0m of {len(cases)} compared")
        print("  A divergence here is a SPECIFICATION AMBIGUITY until shown otherwise.")
        print("  Do not 'fix' Rust to match Python without deciding which one the")
        print("  specification actually requires — that is how Z1 would have been buried.")
        return 1

    print(f"  \033[32mOK\033[0m   python and rust agree on {agreed} case(s), "
          f"{pinned_ok} pinned divergence(s) hold")
    print(f"  \033[33mPARTIAL\033[0m {len(runnable)}/{total} conformance cases compared; "
          f"{len(blocked)} blocked on machinery that does not exist yet")
    for reason in sorted({BLOCKED[n] for n in blocked}):
        n = sum(1 for b in blocked if BLOCKED[b] == reason)
        print(f"           {n:>2}  {reason}")
    return 0


def selfcheck():
    """Prove the comparator sees BOTH kinds of divergence it exists to catch.

    The second one is the point. A comparator that only checks accept/refuse
    reports agreement on a case where Python refuses at `9.3-1` and Rust at
    `9.3-5` -- both "refused", both wrong for the operator reading it, and
    exactly the class of bug (checks running in the wrong order) this pair was
    built to surface. Asserting only the first would leave the interesting half
    of the comparator untested.

    It also asserts a MATCH, so a comparator that called everything a
    divergence -- which would satisfy both cases above -- fails here.
    """
    cases = [
        ("verdict differs", "PASSED\tHIGH\top_8842", "REFUSED\t9.3-1", True),
        ("same verdict, DIFFERENT CLAUSE", "REFUSED\t9.3-1", "REFUSED\t9.3-5", True),
        ("identical", "REFUSED\tCR-4", "REFUSED\tCR-4", False),
    ]
    bad = 0
    for name, py, rs, want_divergence in cases:
        saw = py != rs
        if saw != want_divergence:
            print(f"  \033[31mFAIL\033[0m selfcheck {name!r}: comparator said "
                  f"{'divergence' if saw else 'agreement'}, expected the opposite")
            bad += 1
        else:
            print(f"  \033[32mOK\033[0m   comparator reports "
                  f"{'a divergence' if saw else 'agreement'} for {name!r}")

    # The classification must also be self-consistent, and that is checked here
    # rather than only on the full run: a stale BLOCKED entry shrinks the
    # denominator, and a shrunken denominator still prints green.
    _, _, problems = classify(capture())
    for p in problems:
        print(f"  \033[31mFAIL\033[0m {p}")
        bad += 1
    if not problems:
        print("  \033[32mOK\033[0m   every conformance case is classified, none stale")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
