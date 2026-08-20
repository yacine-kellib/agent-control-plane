#!/usr/bin/env bash
# Mutation control for the EL-1 parser (crates/acp-el1).
#
# The Rust analogue of reference/suites/mutate_executor.py: delete or corrupt a
# named check, rebuild, and require the suite to go RED. A check that kills no
# mutant is not a control, and in this repository an unproven check is worse
# than no check because it is published as evidence.
#
# WHY THIS EXISTS RATHER THAN "the tests pass".
#
# It has already earned its keep. The first version of the Z1 witness test used
# the assignment `action = 'allow'`, asserted `true`, and PASSED -- while
# surviving mutant 1 below, which collapses the parser to the exact flat
# production that permitted Z1. The witness only separates the two readings
# when `action` is neither 'deny' nor 'allow'; two of the three assignments
# agree, so a witness picked without checking which one distinguishes usually
# passes for the wrong reason. Review did not catch that. Running the mutant
# did, immediately.
#
# EACH MUTANT MUST BE *KILLED*, NEVER MERELY "not built". A mutant whose crate
# fails to compile for an unrelated reason reports nothing, and reporting it as
# a kill is the defect tools/selftest.sh asserts against for the Python suites
# (an unrun mutant is not a caught one). So a build failure here is ERROR, and
# ERROR is a failure of this script.
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { printf '  \033[32mKILL\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31m%s\033[0m %s\n' "$2" "$1"; FAIL=$((FAIL+1)); }

command -v cargo >/dev/null 2>&1 || { echo "  SKIP  no cargo"; exit 0; }

printf '\n\033[1m== EL-1 parser mutants ==\033[0m\n'

# Run one mutant: apply a python3 edit to a COPY of the crate, build, test.
# The real crate is never written to -- a restore step that fails would leave
# the parser corrupted, and this script would then be mutating a mutant.
run_mutant() {
  local name="$1" script="$2"
  local dir; dir=$(mktemp -d)
  cp -R crates/acp-el1 "$dir/" || { bad "$name (could not copy the crate)" ERROR; rm -rf "$dir"; return; }

  # Standalone package: the copy is outside the workspace, so the inherited
  # `*.workspace = true` keys would not resolve.
  ( cd "$dir/acp-el1" \
    && sed -i '' 's|^\[package\]|[workspace]\n[package]|' Cargo.toml \
    && sed -i '' 's|version.workspace = true|version = "0.0.0"|; s|edition.workspace = true|edition = "2024"|; s|license.workspace = true|license = "Apache-2.0"|; s|publish.workspace = true|publish = false|' Cargo.toml ) \
    || { bad "$name (could not detach the copy from the workspace)" ERROR; rm -rf "$dir"; return; }

  if ! ( cd "$dir/acp-el1" && python3 -c "$script" ); then
    bad "$name (the mutation did not apply — its anchor moved)" ERROR
    rm -rf "$dir"; return
  fi

  # BUILD FIRST, SEPARATELY. If the mutant does not compile we have learned
  # nothing about the suite, and calling that a kill would be the false green
  # this whole file exists to prevent.
  if ! ( cd "$dir/acp-el1" && cargo build --tests >/dev/null 2>&1 ); then
    bad "$name (mutant does not COMPILE — nothing was tested)" ERROR
    rm -rf "$dir"; return
  fi

  if ( cd "$dir/acp-el1" && cargo test >/dev/null 2>&1 ); then
    bad "$name SURVIVED — the suite passes with this check broken" FAIL
  else
    ok "$name"
  fi
  rm -rf "$dir"
}

# --- mutant 1: Z1 itself -------------------------------------------------------
# Collapse Expr/AndExpr into the flat v1.3.3 production, one level, no
# precedence. Kills: the tree-shape test AND the Z1 witness.
run_mutant "el1-precedence (flat v1.3.3 production)" '
import io
p="src/parse.rs"; s=io.open(p,encoding="utf-8").read()
old = """    fn expr(&mut self) -> Result<Expr, El1Error> {
        let mut n = self.and_expr()?;
        while self.peek_sym(\"||\") {
            self.i += 1;"""
new = """    fn expr(&mut self) -> Result<Expr, El1Error> {
        let mut n = self.term()?;
        while self.peek_sym(\"||\") || self.peek_sym(\"&&\") {
            if self.peek_sym(\"&&\") { self.i += 1; n = Expr::And(Box::new(n), Box::new(self.term()?)); continue; }
            self.i += 1;"""
assert s.count(old)==1, "anchor moved"
s=s.replace(old,new).replace("n = Expr::Or(Box::new(n), Box::new(self.and_expr()?));","n = Expr::Or(Box::new(n), Box::new(self.term()?));")
io.open(p,"w",encoding="utf-8").write(s)
'

# --- mutant 2: cmp-mismatch-false ----------------------------------------------
# Derive != from == instead of from the ordering, so a type mismatch makes `!=`
# TRUE. That is the permissive direction: every mistyped `!=` clause in a signed
# bundle would start firing and raising risk on a policy nobody wrote.
run_mutant "cmp-mismatch-false (!= derived from ==)" '
import io
p="src/eval.rs"; s=io.open(p,encoding="utf-8").read()
old = """            let Some(ord) = compare(&l, &r) else {
                return false;
            };"""
new = """            let Some(ord) = compare(&l, &r) else {
                return matches!(op, CmpOp::Ne);
            };"""
assert s.count(old)==1, "anchor moved"
io.open(p,"w",encoding="utf-8").write(s.replace(old,new))
'

# --- mutant 3: in-absent-lhs ---------------------------------------------------
# Drop the early return, so an absent left-hand side is compared elementwise and
# "this unknown field equals that unknown field" reads as true.
run_mutant "in-absent-lhs (absent compared elementwise)" '
import io
p="src/eval.rs"; s=io.open(p,encoding="utf-8").read()
old = """            if a == Value::Absent {
                return false;
            }"""
assert s.count(old)==1, "anchor moved"
io.open(p,"w",encoding="utf-8").write(s.replace(old,""))
'

# --- mutant 4: trailing tokens --------------------------------------------------
# Accept a prefix parse, so `a == 'x' garbage` grades as `a == 'x'` -- the parser
# deciding on its own that part of a signed policy did not matter.
run_mutant "parse-trailing-tokens (prefix parse accepted)" '
import io
p="src/parse.rs"; s=io.open(p,encoding="utf-8").read()
old = """    if p.i != p.t.len() {
        return Err(El1Error::new(\"trailing tokens\"));
    }"""
assert s.count(old)==1, "anchor moved"
io.open(p,"w",encoding="utf-8").write(s.replace(old,""))
'

printf '\n\033[1m== Result ==\033[0m\n'
if [ $FAIL -eq 0 ]; then
  printf '  %d/%d EL-1 mutants killed.\n' "$PASS" "$PASS"
else
  printf '  \033[31m%d mutant(s) survived or errored\033[0m (%d killed).\n' "$FAIL" "$PASS"
  printf '  A SURVIVE means the suite passes with that check broken.\n'
  printf '  An ERROR means the mutant never ran, which is not a kill.\n'
fi
exit $FAIL
