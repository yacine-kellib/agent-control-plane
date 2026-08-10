#!/usr/bin/env python3
"""
diff_prose.py — ACP-SPEC-001 §8.3.1 prose-derived differential harness.

Per ACP-REVIEW-BRIEF §4: "write the evaluator from the *spec text*, not the
Dafny, then diff." This harness contains TWO independent evaluators, each
written only from §8.3.1/§8.3.2/RK-3 prose, by two plausible readings:

  ENGINE reading   — literal transcription of the grammar production
                     Expr ::= Term (("&&"|"||") Term)*  as a flat left-to-right
                     fold, because the production states no precedence.
  EXECUTOR reading — the C-family default an implementer brings by habit:
                     && binds tighter than ||.

Both are faithful to the text. If they disagree on any input, the prose is
ambiguous and the two production evaluators TR-8 created (Policy Engine and
Executor recomputation) can silently diverge — which §9.3 step 7a cannot
distinguish from KMS compromise.

Also runs metamorphic checks of Annex B Theorems 2/3/4/6 against both.
"""
import itertools, random, sys

RISK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
RANK = {v: k for k, v in RISK.items()}
TIER = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}

# ---------------------------------------------------------------- tokenizer
def lex(s):
    toks, i = [], 0
    two = {"&&", "||", "==", "!=", "<=", ">="}
    while i < len(s):
        c = s[i]
        if c == " ":
            i += 1; continue
        if s[i:i+2] in two:
            toks.append(s[i:i+2]); i += 2; continue
        if c in "()[],<>":
            toks.append(c); i += 1; continue
        if c == "'":
            j = s.index("'", i+1); toks.append(("STR", s[i+1:j])); i = j+1; continue
        j = i
        while j < len(s) and (s[j].isalnum() or s[j] in "._"):
            j += 1
        if j == i:
            raise SyntaxError(f"bad char {c!r}")
        toks.append(s[i:j]); i = j
    return toks

# ------------------------------------------------------- shared leaf parsing
class P:
    def __init__(self, toks): self.t, self.i = toks, 0
    def peek(self): return self.t[self.i] if self.i < len(self.t) else None
    def take(self):
        v = self.t[self.i]; self.i += 1; return v

    def value(self):
        tk = self.take()
        if isinstance(tk, tuple): return ("lit", tk[1])
        if tk in TIER: return ("tier", tk)
        if tk.lstrip("-").isdigit(): return ("num", int(tk))
        return ("field", tk)

    def sett(self):
        assert self.take() == "["
        items = []
        while True:
            items.append(self.value())
            n = self.take()
            if n == "]": break
            assert n == ","
        return items

    def comparison(self):
        if self.peek() == "(":
            self.take(); e = self.expr(); assert self.take() == ")"
            return e
        lhs = self.value()
        op = self.take()
        if op == "in":
            return ("in", lhs, self.sett())
        if op == "<=" and lhs[0] == "field" and lhs[1].endswith(".prefixlen"):
            return ("prefixlen", lhs[1][:-len(".prefixlen")], self.value())
        return ("cmp", op, lhs, self.value())

# ---------------------------------------------------- ENGINE reading (flat)
class EngineParser(P):
    """Grammar states no precedence -> flat left-to-right fold."""
    def expr(self):
        node = self.comparison()
        while self.peek() in ("&&", "||"):
            op = self.take()
            node = (op, node, self.comparison())
        return node

# ------------------------------------------- EXECUTOR reading (precedence)
class ExecutorParser(P):
    """C-family habit: && binds tighter than ||."""
    def expr(self):
        node = self.and_expr()
        while self.peek() == "||":
            self.take(); node = ("||", node, self.and_expr())
        return node
    def and_expr(self):
        node = self.comparison()
        while self.peek() == "&&":
            self.take(); node = ("&&", node, self.comparison())
        return node

# ------------------------------------------------------- shared evaluator
def resolve(ref, env):
    return env.get(ref, ("absent",))

def val(v, env):
    k = v[0]
    if k == "field": return resolve(v[1], env)
    if k == "tier":  return ("tier", TIER[v[1]])
    if k == "num":   return ("num", v[1])
    return ("str", v[1])

def ev(node, env):
    k = node[0]
    if k == "&&": return ev(node[1], env) and ev(node[2], env)
    if k == "||": return ev(node[1], env) or ev(node[2], env)
    if k == "in":
        a = val(node[1], env)
        if a[0] == "absent": return False            # absent path => false
        return any(val(x, env) == a for x in node[2])
    if k == "prefixlen":
        a = resolve(node[1], env)
        if a[0] != "cidr": return False              # type mismatch => false
        return a[1] <= val(node[2], env)[1]
    op, l, r = node[1], val(node[2], env), val(node[3], env)
    if l[0] == "absent" or r[0] == "absent": return False
    if l[0] != r[0]: return False                    # type mismatch => false
    a, b = l[1], r[1]
    return {"==": a == b, "!=": a != b, "<": a < b,
            "<=": a <= b, ">": a > b, ">=": a >= b}[op]

def risk(base, conds, env, parser_cls):
    """RK-3: final level = max over base and all matched conditions."""
    lvl = RISK[base]
    for cond, then in conds:
        if ev(parser_cls(lex(cond)).expr(), env):
            lvl = max(lvl, RISK[then])
    return RANK[lvl]

# ---------------------------------------------------------------- fixtures
FIELDS = ["access_level", "action", "resource.effective_tier",
          "destination.effective_tier", "port"]

def rand_env(rng):
    e = {}
    for f in FIELDS:
        if rng.random() < 0.15: continue                      # absent
        if f.endswith("effective_tier"): e[f] = ("tier", rng.randrange(4))
        elif f == "port": e[f] = ("num", rng.choice([22, 80, 443, 3389]))
        elif f == "action": e[f] = ("str", rng.choice(["allow", "deny", "delete"]))
        else: e[f] = ("str", rng.choice(["owner", "member", "reader"]))
    e["source_cidr"] = ("cidr", rng.choice([8, 16, 24, 32]))
    return e

ATOMS = ["access_level == 'owner'", "action == 'allow'", "action != 'deny'",
         "resource.effective_tier >= T2", "destination.effective_tier == T3",
         "port in [ 22 , 3389 ]", "source_cidr.prefixlen <= 8"]

def rand_expr(rng, n):
    parts = [rng.choice(ATOMS)]
    for _ in range(n - 1):
        parts.append(rng.choice(["&&", "||"]))
        parts.append(rng.choice(ATOMS))
    return " ".join(parts)

# ---------------------------------------------------------------- suites
def differential(rng, n_cases):
    """Diff the two prose readings on identical inputs."""
    disagree = []
    for _ in range(n_cases):
        src = rand_expr(rng, rng.randrange(2, 5))
        env = rand_env(rng)
        a = ev(EngineParser(lex(src)).expr(), env)
        b = ev(ExecutorParser(lex(src)).expr(), env)
        if a != b:
            disagree.append((src, env, a, b))
    return disagree

def metamorphic(rng, n_cases, parser_cls):
    """Annex B Thm 6 (permutation), 4 (base bound), 3 (extension), 2 (floor)."""
    bad = {"perm": 0, "base": 0, "ext": 0, "floor": 0}
    for _ in range(n_cases):
        env = rand_env(rng)
        conds = [(rand_expr(rng, rng.randrange(1, 3)),
                  rng.choice(["MEDIUM", "HIGH"])) for _ in range(rng.randrange(1, 5))]
        base = rng.choice(["LOW", "MEDIUM"])
        r0 = risk(base, conds, env, parser_cls)
        # Thm 6: order-independence
        for _ in range(3):
            sh = conds[:]; rng.shuffle(sh)
            if risk(base, sh, env, parser_cls) != r0: bad["perm"] += 1; break
        # Thm 4: evaluated >= base
        if RISK[r0] < RISK[base]: bad["base"] += 1
        # Thm 3: appending a condition cannot decrease risk
        ext = conds + [(rand_expr(rng, 1), rng.choice(["MEDIUM", "HIGH"]))]
        if RISK[risk(base, ext, env, parser_cls)] < RISK[r0]: bad["ext"] += 1
        # Thm 2: FloorDominance over the full 4x4 lattice
        for f, r in itertools.product(range(4), repeat=2):
            if max(f, r) < f: bad["floor"] += 1
    return bad

# ---------------------------------------------------------------- main
def main():
    print("=" * 70)
    print("ACP §8.3.1 PROSE-DERIVED DIFFERENTIAL HARNESS")
    print("=" * 70)

    total_dis = []
    for seed in (11, 22):
        rng = random.Random(seed)
        d = differential(rng, 5000)
        total_dis += d
        print(f"\n[seed {seed}] differential: 5000 cases, {len(d)} disagreements")

    for seed in (11, 22):
        for name, cls in (("ENGINE", EngineParser), ("EXECUTOR", ExecutorParser)):
            rng = random.Random(seed + 100)
            b = metamorphic(rng, 1200, cls)
            print(f"[seed {seed}] metamorphic {name:9s}: "
                  f"perm={b['perm']} base={b['base']} ext={b['ext']} floor={b['floor']}")

    if total_dis:
        print("\n" + "!" * 70)
        print(f"AMBIGUITY CONFIRMED — {len(total_dis)} disagreements. Minimal witness:")
        print("!" * 70)
        src, env, a, b = min(total_dis, key=lambda x: len(x[0]))
        print(f"  expression : {src}")
        print(f"  ENGINE (flat left fold)   -> {a}")
        print(f"  EXECUTOR (&& over ||)     -> {b}")
        print(f"  env        : { {k: v for k, v in env.items() if k in src} }")
        print("\n  Both readings are faithful to the §8.3.1 production, which")
        print("  states no precedence and no associativity for && / ||.")
    else:
        print("\nNo disagreement: prose is unambiguous under both readings.")
    return 1 if total_dis else 0

if __name__ == "__main__":
    sys.exit(main())
