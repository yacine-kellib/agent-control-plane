#!/usr/bin/env bash
# Mutation control for the Rust decision path (ACP-45).
#
# The Rust analogue of reference/suites/mutate_executor.py: break one named
# check, rebuild, and require the suite to go RED. A check that kills no mutant
# is not a control, and in this repository an unproven check is worse than no
# check because it is published as evidence.
#
# WHY THIS EXISTS RATHER THAN "the tests pass". It has already earned its keep
# twice. The first Z1 witness test used an assignment under which BOTH readings
# agree, asserted the right answer, passed -- and survived the mutant that
# collapses the parser to the flat v1.3.3 production. Review did not catch it;
# the mutant did, immediately.
#
# EACH MUTANT MUST BE *KILLED*, NEVER MERELY "not built". A mutant whose crate
# fails to compile reports nothing, and calling that a kill is the defect
# tools/selftest.sh already asserts against for the Python suites: an unrun
# mutant is not a caught one. So a build failure is ERROR, and ERROR fails this
# script.
#
# THE COPY IS THE WHOLE WORKSPACE, deliberately. acp-decision depends on
# acp-core and acp-el1 through workspace paths, so a single-crate copy would
# either fail to resolve or -- worse -- silently resolve against the REAL
# crates and mutate nothing. The real tree is never written to.
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { printf '  \033[32mKILL\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31m%s\033[0m %s\n' "$2" "$1"; FAIL=$((FAIL+1)); }

command -v cargo >/dev/null 2>&1 || { echo "  SKIP  no cargo"; exit 0; }

printf '\n\033[1m== Rust decision-path mutants ==\033[0m\n'

# run_mutant <label> <cargo -p package> <python3 edit script>
run_mutant() {
  local name="$1" pkg="$2" script="$3"
  local dir; dir=$(mktemp -d)

  cp -R crates "$dir/" 2>/dev/null && cp Cargo.toml "$dir/" 2>/dev/null \
    || { bad "$name (could not copy the workspace)" ERROR; rm -rf "$dir"; return; }
  [ -f Cargo.lock ] && cp Cargo.lock "$dir/" 2>/dev/null

  if ! ( cd "$dir" && python3 -c "$script" ); then
    bad "$name (the mutation did not apply — its anchor moved)" ERROR
    rm -rf "$dir"; return
  fi

  # BUILD FIRST, SEPARATELY, so "does not compile" cannot be reported as a kill.
  if ! ( cd "$dir" && cargo build -q --tests -p "$pkg" >/dev/null 2>&1 ); then
    bad "$name (mutant does not COMPILE — nothing was tested)" ERROR
    rm -rf "$dir"; return
  fi

  if ( cd "$dir" && cargo test -q -p "$pkg" >/dev/null 2>&1 ); then
    bad "$name SURVIVED — the suite passes with this check broken" FAIL
  else
    ok "$name"
  fi
  rm -rf "$dir"
}

sub() {  # file, exact-old, exact-new  -> a python3 one-liner for run_mutant
  printf 'import io\np=%s\ns=io.open(p,encoding="utf-8").read()\nold=%s\nnew=%s\nassert s.count(old)==1, "anchor moved"\nio.open(p,"w",encoding="utf-8").write(s.replace(old,new))\n' \
    "$(python3 -c 'import sys,json;print(json.dumps(sys.argv[1]))' "$1")" \
    "$(python3 -c 'import sys,json;print(json.dumps(sys.argv[1]))' "$2")" \
    "$(python3 -c 'import sys,json;print(json.dumps(sys.argv[1]))' "$3")"
}

# ============================================================ acp-el1 (parser)

# Z1 itself: collapse Expr/AndExpr into the flat v1.3.3 production.
run_mutant "el1-precedence (flat v1.3.3 production)" acp-el1 '
import io
p="crates/acp-el1/src/parse.rs"; s=io.open(p,encoding="utf-8").read()
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

run_mutant "cmp-mismatch-false (!= derived from ==)" acp-el1 "$(sub \
  crates/acp-el1/src/eval.rs \
  '            let Some(ord) = compare(&l, &r) else {
                return false;
            };' \
  '            let Some(ord) = compare(&l, &r) else {
                return matches!(op, CmpOp::Ne);
            };')"

run_mutant "in-absent-lhs (absent compared elementwise)" acp-el1 "$(sub \
  crates/acp-el1/src/eval.rs \
  '            if a == Value::Absent {
                return false;
            }' '')"

run_mutant "parse-trailing-tokens (prefix parse accepted)" acp-el1 "$(sub \
  crates/acp-el1/src/parse.rs \
  '    if p.i != p.t.len() {
        return Err(El1Error::new("trailing tokens"));
    }' '')"

# ACP-45 slice 2: an out-of-range integer literal must REFUSE, not become a
# field reference that resolves absent and evaluates false -- lower risk in
# Rust than in Python, silently, in the fold that decides whether a human is
# needed. This is the mutant for the defect the differential found.
run_mutant "int-width-refuse (out-of-range literal becomes a field)" acp-el1 "$(sub \
  crates/acp-el1/src/parse.rs \
  '        Err(_) => Err(El1Error::new(format!(
            "integer literal {tok} is outside the representable range"
        ))),' \
  '        Err(_) => Ok(None),')"

# ======================================================= acp-decision (§8.4)

# The aggregate tier for an EMPTY target list. Python says T3; T0 grades a
# target-less proposal as the least sensitive thing in the deployment.
run_mutant "empty-targets-T3 (empty aggregates to T0)" acp-decision "$(sub \
  crates/acp-decision/src/lib.rs \
  '        .unwrap_or_else(|| tier_ord(Tier::T3));' \
  '        .unwrap_or_else(|| tier_ord(Tier::T0));')"

# RK-3: the fold must be a monotone max. Assignment lets a later, lower clause
# walk a HIGH grade back down -- the "lowering clause" the type deliberately
# cannot express.
run_mutant "rk3-monotone-max (max replaced by assignment)" acp-decision "$(sub \
  crates/acp-decision/src/grade.rs \
  '            level = level.max(risk_ord(clause.then));' \
  '            level = risk_ord(clause.then);')"

# DR-13: an entry that EXISTS but is empty must refuse too. The generated
# accessor only refuses on an absent key, so this is the arm a Rust
# implementation can get wrong while looking correct.
run_mutant "dr13-empty-recipients (empty list executes unwatched)" acp-decision "$(sub \
  crates/acp-decision/src/grade.rs \
  '    if targets.is_empty() {
        return Err(Refusal::new(
            "DR-13",
            format!(
                "{} is IRREVERSIBLE at risk {risk:?} and its notice_targets \
                 entry is empty, which is not a detection channel",
                p.task_type
            ),
        ));
    }' '')"

# 8.4-3: an action with no risk function is REFUSED, never graded HIGH. This is
# the "helpful" relaxation someone reading P-4 as "unknown is always worst
# case" would make, so it gets a mutant rather than only a comment.
run_mutant "8.4-3-refuse (unknown action graded HIGH instead)" acp-decision "$(sub \
  crates/acp-decision/src/grade.rs \
  '    let rf = pol.risk_functions.get(&p.task_type).map_err(|a| {
        Refusal::new(
            "8.4-3",
            format!("no risk function for task_type {:?} ({})", p.task_type, a.table),
        )
    })?;' \
  '    let Ok(rf) = pol.risk_functions.get(&p.task_type) else { return Ok(Risk::High) };')"

# A malformed raise_to clause must refuse, never be skipped. Skipping is the
# permissive direction: the clause silently stops being able to raise.
run_mutant "raise-clause-refuse (malformed clause skipped)" acp-decision "$(sub \
  crates/acp-decision/src/grade.rs \
  '        let holds = acp_el1::evaluate(&clause.r#if, &env)
            .map_err(|e| Refusal::new("8.3.1", e.message))?;' \
  '        let holds = acp_el1::evaluate(&clause.r#if, &env).unwrap_or(false);')"

# TR-8: an unregistered schema_id must refuse, never default. `fidelity` is
# readable by any raise_to clause, so a default is a policy value the
# implementation invented.
run_mutant "tr8-adapter-refuse (unregistered schema_id defaulted)" acp-decision "$(sub \
  crates/acp-decision/src/lib.rs \
  '    let Some(fidelity) = pol.adapters.get(sid) else {
        return Err(Refusal::new("TR-8", "schema_id not bound to a registered adapter"));
    };
    env.insert("fidelity".into(), Value::Str(fidelity.clone()));' \
  '    let fidelity = pol.adapters.get(sid).cloned().unwrap_or_default();
    env.insert("fidelity".into(), Value::Str(fidelity));')"

# ACP-74, the §8.3.1 parameter domain. The mutation is the reference's own
# defect, transplanted: a float falls through to the STRING arm, a string never
# compares equal to a number, and every numeric clause mentioning that parameter
# stops firing. It is a RESTORE mutant rather than a deletion one -- there was no
# check to delete, which is why no mutation run of any kind found this and a
# hand probe of an input the corpus never spells did.
run_mutant "8.3.1-param-domain (float becomes a string again)" acp-decision "$(sub \
  crates/acp-decision/src/lib.rs \
  '            fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<ParamValue, E> {
                Err(E::custom(PARAM_DOMAIN_MSG))
            }' \
  '            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<ParamValue, E> {
                Ok(ParamValue::Str(v.to_string()))
            }')"

printf '\n\033[1m== Result ==\033[0m\n'
if [ $FAIL -eq 0 ]; then
  printf '  %d/%d Rust decision-path mutants killed.\n' "$PASS" "$PASS"
else
  printf '  \033[31m%d mutant(s) survived or errored\033[0m (%d killed).\n' "$FAIL" "$PASS"
  printf '  A SURVIVE means the suite passes with that check broken.\n'
  printf '  An ERROR means the mutant never ran, which is not a kill.\n'
fi
exit $FAIL
