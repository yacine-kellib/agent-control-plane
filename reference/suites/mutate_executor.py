#!/usr/bin/env python3
"""
mutate_executor.py — mutation testing of the reference Executor.

WHY. A conformance suite that passes proves nothing on its own: an Executor
that refuses everything passes all 14 attack tests, and a suite whose
assertions are vacuous passes against any implementation. The question that
matters is whether each CHECK is load-bearing for the attack it is supposed to
stop.

METHOD. For each security check, delete it from the Executor source, re-run the
suite, and require that (a) the corresponding attack now SUCCEEDS -- i.e. the
test detects the missing check -- and (b) the honest path still executes, so
the mutant is a real weakening rather than a syntactic break.

A mutant that changes nothing means the check is dead code or the test is
vacuous. Either is a finding.
"""
import importlib, subprocess, sys, tempfile, os, shutil, re

# The implementation lives in reference/src/, the suites in reference/suites/.
# Mutation testing reads the real source text, deletes one check and re-runs it,
# so it needs that path explicitly rather than by import.
_HERE = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(_HERE, os.pardir, "src")

SRC = open(os.path.join(SRC_DIR, "acp_executor.py")).read()

# (label, fragment-to-delete OR (old, replacement), attack that must now succeed)
MUTANTS = [
    ("binding check (ii) [Y1]",
     '''            if obj["proposal_hash"] != phash:
                raise CriticalAlert("9.3-7b-ii",
                                    "attestation bound to a DIFFERENT proposal")
''', "a_Y1_misbinding"),

    ("id recomputation [Y1b]",
     '''            if e.get("attestation_id") not in (None, aid):
                raise CriticalAlert("Y1b", "transmitted attestation_id != derived id")
''', "a_Y1b_garbage_id"),

    ("window length [Y2]",
     '''        if exp - iat > 120:
            raise CriticalAlert("L-14", f"validity window {exp-iat}s exceeds 120s")
''', "a_Y2_long_window"),

    ("closed schema [Z4]",
     '''            if set(obj.keys()) != set(AT1_FIELDS):
                missing = set(AT1_FIELDS) - set(obj)
                extra = set(obj) - set(AT1_FIELDS)
                raise CriticalAlert("AT-8b",
                                    f"object schema violation missing={missing} extra={extra}")
''', "a_Z4_optional_field"),

    ("risk RECOMPUTATION [X1/TR-8]",
     ("        risk = self.recompute_floor_risk(proposal)",
      "        risk = receipt.get('risk_level_floor_only') or self.recompute_floor_risk(proposal)"),
     "a_X1_risk_downgrade"),

    # Restores the v1.3.14 line verbatim. If this ever SURVIVEs, the threshold
    # has stopped being load-bearing somewhere else and a quorum of one is back.
    ("quorum threshold RECOMPUTATION [AT-3]",
     ("        need_roles = b.quorum_k",
      '        need_roles = entries[0]["obj"]["required_count"]'),
     "a_AT3_quorum_threshold_from_attestation"),

    ("attester key distinctness [PB-DISTINCT]",
     ("""        if len(set(fingerprints)) != len(fingerprints):
            raise CriticalAlert("PB-DISTINCT",
                                "two attester identities share one verification key")""",
      "        pass"),
     "a_PBDISTINCT_one_key_two_identities"),

    ("operator distinctness [AT-2]",
     '''        if operator in approvals:                       # AT-2 distinctness
            raise CriticalAlert("AT-2", "operator counted toward own quorum")
''', "a_AT2_self_approval"),

    ("live capability recheck [T10]",
     ("""            caps = self.context.get(operator, set())
            need = f"{proposal['task_type']}:{proposal.get('targets',[''])[0]}"
            if need not in caps:
                raise CriticalAlert("9.3-9", f"operator {operator} lacks {need}")""",
      "            pass"),
     "a_capability_revoked"),

    ("proposal rehash [B-1a]",
     ("""        if receipt.get("proposal_hash") != phash:
            raise CriticalAlert("9.3-3", "receipt not bound to this proposal")""",
      ""),
     "a_tampered_proposal_low"),
    ("notification path independence [DR-2]",
     ("""        if note.source_path == approval_summary.source_path:
            raise CriticalAlert("DR-2", "notification shares the approval render path")""",
      "        pass"),
     "a_DR_shared_render_library"),

    ("hold window enforcement [DR-1]",
     ("""        if now < pr.release_at:
            raise FailClosed("DR-1", "hold window has not elapsed")""",
      "        pass"),
     "a_DR_release_before_window"),

    ("delivery completeness [DR-8]",
     ("""        if set(delivered) != set(recipients):""",
      "        if False:"),
     "a_DR_notification_undeliverable"),

    ("receipt-outlives-hold [DR-6]",
     ("""        if now > pr.receipt["expires_at"]:
            raise CriticalAlert("DR-6", "receipt expired during hold window")""",
      "        pass"),
     "a_DR_hold_outlives_receipt"),
    ("confirmation requirement [DR-9]",
     ("""        needs_confirmation = pr.reversibility == "IRREVERSIBLE" or pr.sampled""",
      "        needs_confirmation = False"),
     "a_DR9_irreversible_silent_release"),

    ("reversibility RECOMPUTATION [RV-3]",
     ("        reversibility = self.recompute_reversibility(proposal)",
      "        reversibility = receipt.get('reversibility') or self.recompute_reversibility(proposal)"),
     "a_RV3_receipt_claims_reversible"),

    ("fail-safe default [RV-1]",
     ('        return self.reversibility.get(task_type, "IRREVERSIBLE")',
      '        return self.reversibility.get(task_type, "REVERSIBLE")'),
     "a_RV1_unclassified_action_defaults_irreversible"),

    ("operator self-confirm bar [DR-9]",
     ("""        if who == pr.operator:
            # The operator initiated the action; their acknowledgement carries
            # no independent information. AT-2 distinctness, restated.
            raise FailClosed("DR-9", "operator cannot confirm their own action")""",
      "        pass"),
     "a_DR9_operator_confirms_own_action"),
    ("hybrid AND composition [CR-3]",
     ("    return all(verify_prim(pub, payload.encode(), sig[p], p) for p in required)",
      "    return any(verify_prim(pub, payload.encode(), sig[p], p) for p in required)"),
     "a_CR3_pq_forged_classical_genuine"),

    ("suite completeness [CR-3]",
     ("    if set(sig.keys()) != required:        # no extra, no missing primitives\n        return False",
      "    if False:\n        return False"),
     "a_CR3_extra_primitive"),

    ("suite floor [CR-4]",
     ("        return SUITE_RANK[alg] >= SUITE_RANK[self.min_suite]",
      "        return True"),
     "a_CR4_receipt_suite_downgrade"),

    ("key registry in bundle hash [PB-KEY]",
     ("""                  "attesters": {who: k.fingerprint()
                                for who, k in sorted(self.attester_keys.items())},
                  "receipt_key": self.receipt_key.fingerprint()})""",
      "                  })"),
     "a_PBKEY_swapped_attester_registry"),
]

RUNNER = """
import sys
sys.path.insert(0, {d!r})
import conformance as C
ok_honest = True
try:
    C.t_honest_high()
    C.t_deferred_holds_then_releases()
    C.t_irreversible_requires_confirmation()
except Exception:
    ok_honest = False
attack_succeeded = False
try:
    getattr(C, {atk!r})()
    attack_succeeded = True
except Exception:
    pass
print(f"{{int(ok_honest)}},{{int(attack_succeeded)}}")
"""


def run_mutant(tmpdir, atk):
    script = os.path.join(tmpdir, "_run.py")
    open(script, "w").write(RUNNER.format(d=tmpdir, atk=atk))
    # PYTHONPATH is stripped deliberately. verify.sh exports reference/src, and
    # if that leaked in here a failed copy would silently import the REAL
    # executor: the mutant would report SURVIVE and a load-bearing check would
    # be recorded as redundant. Absence must break the run, not quieten it.
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    r = subprocess.run([sys.executable, script], capture_output=True, text=True,
                       cwd=tmpdir, timeout=60, env=env)
    out = r.stdout.strip().splitlines()
    if not out or "," not in out[-1]:
        return None, r.stderr.strip()[:200]
    a, b = out[-1].split(",")
    return (a == "1", b == "1"), None


def main():
    print("=" * 74)
    print("EXECUTOR MUTATION TESTING — each check must be load-bearing")
    print("=" * 74)
    fails = 0
    for label, frag, atk in MUTANTS:
        old, new = frag if isinstance(frag, tuple) else (frag, "")
        if SRC.count(old) != 1:
            print(f"  ERROR  {label:<32} anchor not found ({SRC.count(old)})")
            fails += 1
            continue
        with tempfile.TemporaryDirectory() as td:
            open(os.path.join(td, "acp_executor.py"), "w").write(
                SRC.replace(old, new))
            # acp_crypto is a hard import of the mutant since v1.3.14. If it is
            # missing the mutant dies at import, stdout is empty, and run_mutant
            # returns None -> ERROR. It does NOT print KILL: a mutant that never
            # ran must never be scored as one that was caught.
            shutil.copy(os.path.join(SRC_DIR, "acp_crypto.py"), td)
            shutil.copy(os.path.join(_HERE, "conformance.py"), td)
            res, err = run_mutant(td, atk)
            if res is None:
                print(f"  ERROR  {label:<32} {err}")
                fails += 1
                continue
            honest_ok, attack_ok = res
            if attack_ok and honest_ok:
                print(f"  KILL   {label:<32} attack succeeds without it "
                      f"(honest path still works)")
            elif attack_ok and not honest_ok:
                print(f"  WEAK   {label:<32} attack succeeds but honest path "
                      f"broke — mutant not clean")
                fails += 1
            else:
                print(f"  SURVIVE{label:<32} attack STILL blocked — check is "
                      f"redundant or test is vacuous")
                fails += 1
    print("=" * 74)
    if fails:
        print(f"RESULT: {len(MUTANTS)-fails}/{len(MUTANTS)} killed — REVIEW REQUIRED")
    else:
        print(f"RESULT: {len(MUTANTS)}/{len(MUTANTS)} killed — every check is "
              f"load-bearing and every test is non-vacuous")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
