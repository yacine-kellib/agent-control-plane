#!/usr/bin/env python3
"""Python vs Rust on generated EL-1 source text.

`diff_prose.py` found Z1 by running two evaluators written independently FROM
THE PROSE and diffing them on generated source text: 493 disagreements in
10,000 cases, 4.9%, on mixed-connective expressions. That method found the
ambiguity. It says nothing about whether the two implementations this
repository actually ships agree today.

§1246 requires parser conformance vectors to be run "against the deployment's
own parser, not only its evaluator". This repository ships two deployments of
one specification, so the same method pointed at `reference/src/acp_executor.py`
and `crates/acp-el1` is the check that the EL-1 fix holds in both. Per
CLAUDE.md, the first divergence between them on a shared input is a
SPECIFICATION AMBIGUITY, not a Rust bug to quietly patch.

WHY GENERATED SOURCE TEXT AND NOT A FIXTURE CORPUS. A committed corpus is a
fixture that can quietly stop describing the code. More importantly, Z1 hid
from a harness that generated ASTs: the parse was upstream of everything the
assurance apparatus looked at. Text is the only input that exercises the
parser, and mixed connectives are the only shapes where the two readings can
differ at all.

THE HARNESS PROVES ITSELF FIRST. `--selfcheck` feeds a case whose Python answer
is computed under the FLAT v1.3.3 reading and requires the comparator to report
a divergence. A differential that reports "0 divergences" while being unable to
detect one is the vacuous-green failure this repository is most exposed to, and
it is exactly what a 100%-agreement run looks like.
"""
import argparse
import pathlib
import random
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "reference" / "src"))

from acp_executor import evaluate as py_evaluate, FailClosed  # noqa: E402

# The vocabulary is deliberately small and free of tabs and colons, because the
# line protocol splits on both. It is also deliberately NARROW: three string
# values over two fields produce collisions and near-misses at a useful rate,
# where a wide alphabet would make almost every comparison false and almost
# every expression trivially the same on both sides.
STRINGS = ["allow", "deny", "read"]
FIELDS_STR = ["action", "verb"]
FIELDS_NUM = ["count", "size"]
FIELDS_TIER = ["resource", "target"]
FIELDS_CIDR = ["net"]
NUMS = [0, 1, 5, 100]
TIERS = ["T0", "T1", "T2", "T3"]
CMP_OPS = ["==", "!=", "<", "<=", ">", ">="]


def gen_atom(rng):
    """One comparison, membership test or prefixlen predicate."""
    kind = rng.choice(["str", "num", "tier", "in", "plen", "mixed"])
    if kind == "str":
        return f"{rng.choice(FIELDS_STR)} {rng.choice(CMP_OPS)} '{rng.choice(STRINGS)}'"
    if kind == "num":
        return f"{rng.choice(FIELDS_NUM)} {rng.choice(CMP_OPS)} {rng.choice(NUMS)}"
    if kind == "tier":
        return f"{rng.choice(FIELDS_TIER)} {rng.choice(CMP_OPS)} {rng.choice(TIERS)}"
    if kind == "in":
        items = rng.sample(STRINGS, rng.randint(1, len(STRINGS)))
        return f"{rng.choice(FIELDS_STR)} in [" + ", ".join(f"'{i}'" for i in items) + "]"
    if kind == "plen":
        return f"{rng.choice(FIELDS_CIDR)}.prefixlen <= {rng.choice([8, 16, 24, 32])}"
    # A deliberate type mismatch, and an absent field. Both are `false` under
    # §8.3.1 totality, and both are places an implementation can diverge by
    # coercing, raising, or -- the one that matters -- making `!=` true.
    return rng.choice([
        f"{rng.choice(FIELDS_NUM)} {rng.choice(CMP_OPS)} '{rng.choice(STRINGS)}'",
        f"{rng.choice(FIELDS_TIER)} {rng.choice(CMP_OPS)} {rng.choice(NUMS)}",
        f"nosuchfield {rng.choice(CMP_OPS)} '{rng.choice(STRINGS)}'",
    ])


def gen_expr(rng, depth=0):
    """A mixed-connective expression. Mixing is the point, not decoration."""
    if depth >= 2 or rng.random() < 0.35:
        return gen_atom(rng)
    n = rng.randint(2, 4)
    parts = [gen_expr(rng, depth + 1) for _ in range(n)]
    # Alternate connectives with a bias toward MIXING them: an expression using
    # one connective throughout cannot distinguish the two readings, so a
    # generator that mixes rarely produces a run that is mostly controls.
    ops = [rng.choice(["&&", "||"]) for _ in range(n - 1)]
    if len(set(ops)) == 1 and rng.random() < 0.7:
        ops[rng.randrange(len(ops))] = "||" if ops[0] == "&&" else "&&"
    out = parts[0]
    for op, part in zip(ops, parts[1:]):
        out += f" {op} {part}"
    if depth and rng.random() < 0.3:
        out = f"({out})"
    return out


def gen_env(rng):
    """A random environment. Fields are omitted at random so the absent-path
    (§8.3.1 totality) is exercised rather than assumed."""
    env = {}
    for f in FIELDS_STR:
        if rng.random() < 0.8:
            env[f] = ("str", rng.choice(STRINGS))
    for f in FIELDS_NUM:
        if rng.random() < 0.8:
            env[f] = ("num", rng.choice(NUMS))
    for f in FIELDS_TIER:
        if rng.random() < 0.8:
            env[f] = ("tier", rng.choice([0, 1, 2, 3]))
    for f in FIELDS_CIDR:
        if rng.random() < 0.8:
            env[f] = ("cidr", rng.choice([8, 16, 24, 32]))
    return env


def py_answer(src, env):
    """('ok', bool) or ('err', clause)."""
    try:
        return ("ok", bool(py_evaluate(src, env)))
    except FailClosed as e:
        return ("err", e.args[0] if e.args else "?")
    except Exception as e:  # noqa: BLE001
        # NOT folded into the FailClosed case. An uncaught exception is a
        # DIFFERENT outcome from a stated refusal: the reference crashing where
        # Rust refuses is a real divergence and must be reported as one, not
        # normalised into agreement by a broad except.
        return ("crash", type(e).__name__)


def encode(src, env):
    bindings = [f"{k}:{t}:{v}" for k, (t, v) in sorted(env.items())]
    return "\t".join([src, *bindings])


def run_rust(cases):
    """Build once, run once. Returns a list of ('ok', bool) / ('err', clause)."""
    build = subprocess.run(
        ["cargo", "build", "-q", "-p", "acp-el1", "--example", "el1_batch"],
        cwd=ROOT, capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stderr[-2000:], file=sys.stderr)
        raise SystemExit("cargo build failed — the differential did NOT run")

    with tempfile.NamedTemporaryFile("w", suffix=".el1", delete=False) as fh:
        fh.write("\n".join(encode(s, e) for s, e in cases) + "\n")
        path = fh.name
    try:
        proc = subprocess.run(
            ["cargo", "run", "-q", "-p", "acp-el1", "--example", "el1_batch", "--", path],
            cwd=ROOT, capture_output=True, text=True)
    finally:
        pathlib.Path(path).unlink(missing_ok=True)

    if proc.returncode != 0:
        print(proc.stderr[-2000:], file=sys.stderr)
        raise SystemExit("el1_batch failed — the differential did NOT run")

    out = []
    for line in proc.stdout.splitlines():
        f = line.split("\t")
        if f[0] == "OK":
            out.append(("ok", f[1] == "true"))
        elif f[0] == "ERR":
            out.append(("err", f[1]))
        else:
            raise SystemExit(f"unparseable line from el1_batch: {line!r}")
    return out


# ---------------------------------------------------------------- pinned
# Known, disclosed divergences. Each is asserted FROM BOTH SIDES, the ACP-54
# pattern: if the divergence disappears or moves, this goes red rather than
# passing quietly. A divergence nobody re-checks is indistinguishable from one
# that was silently fixed and from one that silently got worse.
#
# The integer-width pair below was found by this harness probing the i64
# boundary, in code whose own comment claimed it already refused. It did not:
# an out-of-range all-digit token fell through to a FIELD REFERENCE, resolved
# absent, and evaluated false -- lower risk in Rust than in Python, silently,
# which is the permissive direction. Rust now fails closed at parse. Python
# still accepts the literal, because its integers are arbitrary precision, so
# the divergence is narrower but real: REFUSAL vs a computed answer.
PINNED = [
    (
        "count < 9223372036854775808",
        {"count": ("num", 5)},
        ("ok", True),          # Python: arbitrary precision, 5 < 2^63 is true
        ("err", "8.3.1"),      # Rust: the literal exceeds i64, refused at parse
        "integer literal above i64::MAX (AC-1a width is unspecified)",
    ),
    (
        "count != 9223372036854775808",
        {"count": ("num", 5)},
        ("ok", True),
        ("err", "8.3.1"),
        "same literal, != -- listed separately because the operators diverged "
        "differently before the fix",
    ),
    (
        # The boundary itself must AGREE. Without this row the pair above is
        # satisfied by a Rust that refuses every large number, including ones
        # it can represent -- a check that passes by being uniformly broken.
        "count < 9223372036854775807",
        {"count": ("num", 5)},
        ("ok", True),
        ("ok", True),
        "i64::MAX exactly — the last value both sides represent",
    ),
]


def check_pinned():
    """Every pinned divergence must still hold, exactly as recorded."""
    rust = run_rust([(src, env) for src, env, _, _, _ in PINNED])
    bad = 0
    for (src, env, want_py, want_rs, why), got_rs in zip(PINNED, rust):
        got_py = py_answer(src, env)
        if got_py != want_py or got_rs != want_rs:
            bad += 1
            print(f"  \033[31mFAIL\033[0m pinned divergence moved: {src}")
            print(f"    {why}")
            print(f"    python: want {want_py}, got {got_py}")
            print(f"    rust  : want {want_rs}, got {got_rs}")
    if bad == 0:
        print(f"  \033[32mOK\033[0m   {len(PINNED)} pinned divergence(s) still hold exactly")
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000, help="cases (default 2000)")
    ap.add_argument("--seed", type=int, default=20260820)
    ap.add_argument("--selfcheck", action="store_true",
                    help="prove the comparator can report a divergence, then exit")
    args = ap.parse_args()

    if args.selfcheck:
        return selfcheck()

    rng = random.Random(args.seed)
    cases = [(gen_expr(rng), gen_env(rng)) for _ in range(args.n)]

    # Mixed-connective cases are the only ones where the Z1 class can appear.
    # Counting them makes a run whose generator quietly stopped mixing visible
    # as a small number here, instead of as a confident 0 divergences.
    mixed = sum(1 for s, _ in cases if "&&" in s and "||" in s)
    print(f"  {args.n} cases, {mixed} mixed-connective, seed {args.seed}")
    if mixed == 0:
        raise SystemExit("  FAIL no mixed-connective cases — this run is vacuous for Z1")

    rust = run_rust(cases)
    if len(rust) != len(cases):
        raise SystemExit(f"  FAIL Rust returned {len(rust)} results for {len(cases)} cases")

    diverged = []
    for (src, env), r in zip(cases, rust):
        p = py_answer(src, env)
        # Compare the VERDICT AND, on refusal, the clause id. Two
        # implementations that refuse the same input for different stated
        # reasons have not been shown to agree -- the property
        # check-bundle-differential.py already applies to refusal names.
        if p != r:
            diverged.append((src, env, p, r))

    if diverged:
        print(f"  \033[31mFAIL\033[0m {len(diverged)} divergence(s) of {len(cases)}")
        for src, env, p, r in diverged[:5]:
            print(f"    src   : {src}")
            print(f"    env   : {env}")
            print(f"    python: {p}")
            print(f"    rust  : {r}")
            print()
        print("  A divergence here is a SPECIFICATION AMBIGUITY until shown otherwise.")
        print("  Do not 'fix' Rust to match Python without deciding which one the")
        print("  specification actually requires — that is how Z1 would have been buried.")
        return 1

    print(f"  \033[32mOK\033[0m   Python and Rust agree on all {len(cases)} cases "
          f"({mixed} mixed-connective)")
    # The generated corpus draws from a narrow numeric vocabulary and never
    # reaches the i64 boundary, so agreement above says nothing about it. The
    # pinned cases are checked separately and always.
    return 1 if check_pinned() else 0


def selfcheck():
    """Prove the comparator reports a divergence when one exists.

    Uses the Z1 witness under the assignment that separates the two readings,
    and compares Rust against the FLAT v1.3.3 answer rather than against
    Python. Rust says true; the flat reading says false; the comparator must
    call that a divergence.

    Without this, a run reporting `0 divergences` is indistinguishable from a
    comparator that cannot see one -- and 0 divergences is precisely what a
    healthy run prints.
    """
    src = "action != 'deny' || action == 'allow' && action == 'allow'"
    env = {"action": ("str", "read")}

    rust = run_rust([(src, env)])[0]
    flat = ("ok", False)   # ((a || b) && c) under action='read'
    el1 = ("ok", True)     # (a || (b && c))

    ok = True
    if rust != el1:
        print(f"  \033[31mFAIL\033[0m Rust gave {rust}, EL-1 requires {el1}")
        ok = False
    else:
        print(f"  \033[32mOK\033[0m   Rust evaluates the Z1 witness under EL-1 ({rust})")

    if rust == flat:
        print("  \033[31mFAIL\033[0m Rust agrees with the FLAT v1.3.3 reading")
        ok = False
    else:
        print("  \033[32mOK\033[0m   and disagrees with the flat reading, so the two are "
              "distinguishable here")

    # The comparator itself: the same equality the main loop uses must call
    # these two different.
    if flat != rust:
        print("  \033[32mOK\033[0m   the comparator reports that difference as a divergence")
    else:
        print("  \033[31mFAIL\033[0m the comparator did NOT report a real difference")
        ok = False

    # And Python must land on EL-1 too, or the reference is the one that moved.
    p = py_answer(src, env)
    if p == el1:
        print(f"  \033[32mOK\033[0m   the Python reference also evaluates it under EL-1 ({p})")
    else:
        print(f"  \033[31mFAIL\033[0m Python gave {p}, EL-1 requires {el1}")
        ok = False

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
