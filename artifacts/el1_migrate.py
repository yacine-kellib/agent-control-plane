#!/usr/bin/env python3
"""
el1_migrate.py — ACP-SPEC-001 v1.3.5 bundle migration checker (Z1 residual).

WHY THIS EXISTS
---------------
EL-1 (v1.3.4) fixed the §8.3.1 grammar prospectively: `&&` binds tighter than
`||`, both left-associative. Bundles authored under the AMBIGUOUS grammar may
already encode a different meaning than EL-1 gives them. Upgrading without
checking silently re-grades risk. Per §15, a silent grade change is a
floor-honesty (A-7) event requiring RK-5 review, NOT a routine deploy.

WHAT IT DOES
------------
For every condition in every risk_function of a bundle:
  1. Parses it under BOTH readings (flat left fold vs EL-1 precedence).
  2. Reports STRUCTURAL divergence (different parse trees).
  3. Exhaustively enumerates the truth-assignment space over the condition's
     atoms and reports SEMANTIC divergence (readings differ on some assignment).
  4. Computes, per risk_function, whether any divergent assignment changes the
     RESULTING RISK GRADE -- the only divergence that is operationally load
     bearing, since RK-3 takes the max over matched conditions.

EXIT CODES
----------
  0  no divergence -- bundle means the same thing under EL-1; safe to upgrade
  1  divergence found -- RK-5 review required before upgrade
  2  bundle could not be parsed

Exhaustive over atoms, so "no divergence" is a proof for that bundle, not a
sample. Atom count is capped (default 16 -> 65,536 assignments); above the cap
the rule is reported as UNVERIFIED rather than silently passed.
"""
import itertools, json, sys

RISK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
RANK = {v: k for k, v in RISK.items()}
MAX_ATOMS = 16


# ------------------------------------------------------------------ tokenize
def lex(src):
    toks, i, two = [], 0, {"&&", "||", "==", "!=", "<=", ">="}
    while i < len(src):
        c = src[i]
        if c == " ":
            i += 1; continue
        if src[i:i+2] in two:
            toks.append(src[i:i+2]); i += 2; continue
        if c in "()[],<>":
            toks.append(c); i += 1; continue
        if c == "'":
            j = src.index("'", i+1); toks.append("'" + src[i+1:j] + "'"); i = j+1; continue
        j = i
        while j < len(src) and (src[j].isalnum() or src[j] in "._"):
            j += 1
        if j == i:
            raise SyntaxError(f"unexpected character {c!r} at {i}")
        toks.append(src[i:j]); i = j
    return toks


# -------------------------------------------------------------------- parse
# Atoms are opaque: we care only about connective structure, so an atom is any
# maximal token run containing no connective and no paren at depth boundary.
class Base:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self):
        v = self.t[self.i]; self.i += 1; return v

    def atom(self):
        if self.peek() == "(":
            self.take()
            e = self.expr()
            if self.peek() != ")":
                raise SyntaxError("unbalanced parenthesis")
            self.take()
            return e
        run = []
        depth = 0
        while self.peek() is not None:
            p = self.peek()
            if depth == 0 and p in ("&&", "||", ")"):
                break
            if p == "[":
                depth += 1
            if p == "]":
                depth -= 1
            run.append(self.take())
        if not run:
            raise SyntaxError("empty atom")
        return ("atom", " ".join(run))

    def parse(self):
        e = self.expr()
        if self.i != len(self.t):
            raise SyntaxError(f"trailing tokens at {self.i}")
        return e


class Flat(Base):
    """Literal reading of the pre-EL-1 production: one level, left fold."""
    def expr(self):
        n = self.atom()
        while self.peek() in ("&&", "||"):
            op = self.take()
            n = (op, n, self.atom())
        return n


class EL1(Base):
    """EL-1: && binds tighter than ||; both left-associative."""
    def expr(self):
        n = self.and_expr()
        while self.peek() == "||":
            self.take(); n = ("||", n, self.and_expr())
        return n

    def and_expr(self):
        n = self.atom()
        while self.peek() == "&&":
            self.take(); n = ("&&", n, self.atom())
        return n


# ----------------------------------------------------------------- evaluate
def atoms_of(node, acc):
    if node[0] == "atom":
        acc.append(node[1])
    else:
        atoms_of(node[1], acc); atoms_of(node[2], acc)
    return acc


def ev(node, assign):
    if node[0] == "atom":
        return assign[node[1]]
    a, b = ev(node[1], assign), ev(node[2], assign)
    return (a and b) if node[0] == "&&" else (a or b)


def compare(src):
    """Return (status, detail). status in {ok, structural, semantic, unverified, error}."""
    try:
        toks = lex(src)
        f, e = Flat(list(toks)).parse(), EL1(list(toks)).parse()
    except SyntaxError as ex:
        return "error", str(ex)

    if f == e:
        return "ok", None

    names = sorted(set(atoms_of(f, [])))
    if len(names) > MAX_ATOMS:
        return "unverified", f"{len(names)} atoms exceeds cap {MAX_ATOMS}"

    for combo in itertools.product([False, True], repeat=len(names)):
        assign = dict(zip(names, combo))
        if ev(f, assign) != ev(e, assign):
            return "semantic", {"witness": assign,
                                "flat": ev(f, assign), "el1": ev(e, assign)}
    return "structural", "different parse trees, identical truth table"


# ------------------------------------------------------------- grade impact
def grade_divergence(rf):
    """Does any assignment change the risk grade this risk_function yields?"""
    conds = rf.get("raise_to", [])
    parsed = []
    names = set()
    for c in conds:
        toks = lex(c["if"])
        f, e = Flat(list(toks)).parse(), EL1(list(toks)).parse()
        parsed.append((f, e, c["then"]))
        names |= set(atoms_of(f, []))
    names = sorted(names)
    if len(names) > MAX_ATOMS:
        return None
    base = RISK[rf.get("base", "LOW")]
    for combo in itertools.product([False, True], repeat=len(names)):
        assign = dict(zip(names, combo))
        gf = ge = base
        for f, e, then in parsed:
            if ev(f, assign):
                gf = max(gf, RISK[then])
            if ev(e, assign):
                ge = max(ge, RISK[then])
        if gf != ge:
            return {"witness": assign, "flat_grade": RANK[gf], "el1_grade": RANK[ge]}
    return None


# -------------------------------------------------------------------- main
def main(path):
    try:
        bundle = json.load(open(path))
    except Exception as ex:
        print(f"FATAL: cannot read bundle: {ex}"); return 2

    rfs = bundle.get("risk_functions", [])
    if not rfs:
        print("FATAL: no risk_functions in bundle"); return 2

    print("=" * 72)
    print(f"EL-1 MIGRATION CHECK — {path}")
    print("=" * 72)

    divergent = unverified = errors = 0
    for rf in rfs:
        name = rf.get("applies_to", "<unnamed>")
        rows = []
        for c in rf.get("raise_to", []):
            st, detail = compare(c["if"])
            if st == "ok":
                continue
            rows.append((c["if"], c["then"], st, detail))
        if not rows:
            print(f"\n[OK]        {name} — all conditions unambiguous")
            continue

        print(f"\n[REVIEW]    {name}")
        for src, then, st, detail in rows:
            tag = {"semantic": "SEMANTIC DIVERGENCE",
                   "structural": "structural only (truth table identical)",
                   "unverified": "UNVERIFIED",
                   "error": "PARSE ERROR"}[st]
            print(f"    condition : {src}")
            print(f"    then      : {then}")
            print(f"    status    : {tag}")
            if st == "semantic":
                w = detail["witness"]
                true_atoms = [k for k, v in w.items() if v] or ["(none)"]
                print(f"    witness   : true -> {', '.join(true_atoms)}")
                print(f"                flat={detail['flat']}  EL-1={detail['el1']}")
                divergent += 1
            elif st == "unverified":
                print(f"    reason    : {detail}"); unverified += 1
            elif st == "error":
                print(f"    reason    : {detail}"); errors += 1
            print()

        g = grade_divergence(rf)
        if g:
            print(f"    >>> RISK GRADE CHANGES: flat={g['flat_grade']} "
                  f"EL-1={g['el1_grade']}")
            print(f"    >>> A-7 floor-honesty event. RK-5 review REQUIRED "
                  f"before upgrade.\n")

    print("=" * 72)
    if divergent or unverified or errors:
        print(f"RESULT: NOT SAFE TO UPGRADE — {divergent} semantic divergence(s), "
              f"{unverified} unverified, {errors} parse error(s)")
        print("Each divergent rule must be re-authored with explicit parentheses")
        print("and re-signed under RK-5 before EL-1 is adopted.")
        return 1
    print("RESULT: SAFE — bundle means the same under EL-1 (exhaustive over atoms)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "bundle.json"))
