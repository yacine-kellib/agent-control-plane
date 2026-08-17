#!/usr/bin/env python3
"""
bundle.py — the signed policy bundle (brief §3).

THIS TABLE IS THE POLICY. Nothing outside it is expressible by the agent: the
action classes are a closed set, each target set is closed, and an action type
nobody has graded yet is refused outright rather than graded — there is no risk
function to apply, so it fails at 8.4-3, and RV-1 independently defaults its
reversibility to IRREVERSIBLE so no later path can release it on silence.

THE GRADING AXIS, stated because it is the part people get wrong: actions are
graded by WHAT AN INCORRECT ACTION CONSUMES AND WHETHER IT CAN BE TAKEN BACK,
never by how technically difficult the science is. A reviewer who cannot judge a
binding affinity can still judge whether material was spent. That legibility is
what makes a risk floor authorable at all.

Run:  python3 -m sim.bundle          # the grading table
      python3 -m sim.bundle --check  # assert every row computes as specified
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field, fields as dc_fields

import sim  # noqa: F401  — puts ../reference/src on sys.path
from acp_executor import Bundle, Executor, Ledger, FailClosed, h

from sim.receipts import RECEIPT_SIGNER
from sim.world import ATTESTER_KEYS, DISCLOSURE_ROLE, PROGRAMS

# --------------------------------------------------------------- resources
#
# Tiers are a claim about consequence, not about difficulty. A-7 applies in
# full and is conceded unprovable: nothing here proves a resource labelled T0
# really is a scratch environment. RK-5 two-person offline control on any
# downgrade is the only available answer, and label drift — not a clever
# adversary — is the realistic failure in a lab where instrumentation changes
# continuously.
FLOORS = {
    "compute-cluster":       "T0",   # rerunnable; costs only time
    "literature-store":      "T0",   # read-only public corpus
    "candidate-registry":    "T2",   # downstream teams read it as settled truth
    "assay-queue":           "T2",   # consumes scarce shared instrument time
    "reagent-inventory":     "T3",   # consumes physical material
    "synthesis-queue":       "T3",   # commits money, cannot be recalled
    "regulatory-submission": "T3",   # regulated record; integrity is legally material
}
#: One partner channel per program. Disclosure leaves the trust boundary and is
#: irreversible in the only sense that matters: it cannot be un-disclosed.
FLOORS.update({f"partner-channel:{p}": "T3" for p in PROGRAMS})

#: Which program owns each resource. Only the partner channels are owned — the
#: rest are shared infrastructure whose program comes from the *data*.
RESOURCE_PROGRAM = {f"partner-channel:{p}": p for p in PROGRAMS}

#: Which program owns each dataset. THIS IS IN THE SIGNED BUNDLE ON PURPOSE and
#: it is the entry the 11:30 attack turns on.
#:
#: The obvious implementation reads the source program out of the Proposal —
#: the agent knows which dataset it is exporting, so why not let it say so? —
#: and that implementation is broken. A compromised agent writes the whole
#: Proposal, so it would simply assert `source_program: prog-beta` for
#: prog-alpha data and the cross-program check would agree with itself. That is
#: RES-8 exactly: a verifier accepting a derived security value from the party
#: it is verifying.
#:
#: So ownership is recomputed here, from bytes the model never sees and cannot
#: influence. The Proposal's own `source_program` is diagnostic only; where it
#: disagrees with this table the disagreement is a critical alert, which is the
#: same treatment TR-8 gives a receipt that misstates its own risk.
#:
#: An unknown dataset resolves to None and DENIES (P-4: unknown is never LOW).
DATASET_PROGRAM = {
    "ds-alpha-binding-001": "prog-alpha",
    "ds-alpha-binding-002": "prog-alpha",
    "ds-beta-pk-003":       "prog-beta",
    "ds-gamma-adme-011":    "prog-gamma",
    "ds-internal-tox-007":  "prog-internal",
}

# ------------------------------------------------------------ action classes
#
# base risk + monotone raises (RK-3: conditions may only escalate, so rule order
# cannot matter). Expressions are EL-1: && binds tighter than ||, both
# left-associative.
RISK_FUNCTIONS = [
    # ---- the fast path. This is B-5, and it is not a concession: a control
    # plane that taxes exploration gets routed around, and a control that is
    # routed around provides nothing. Unbounded proposing is the POINT of
    # putting a model in the loop.
    {"applies_to": "read_literature",  "base": "LOW",    "raise_to": []},
    {"applies_to": "run_simulation",   "base": "LOW",    "raise_to": []},
    {"applies_to": "predict_structure", "base": "LOW",   "raise_to": []},

    # ---- audited, but not held. A wrong entry propagates because downstream
    # teams treat the registry as settled; that is worth a record, not a human.
    {"applies_to": "register_candidate", "base": "MEDIUM", "raise_to": [
        {"if": "resource.effective_tier >= T2", "then": "MEDIUM"}]},

    # ---- HIGH but REVERSIBLE. Cancellable up to a cutoff, so silence may
    # release it — and the release is counted as unverified (DR-12).
    {"applies_to": "schedule_assay", "base": "MEDIUM", "raise_to": [
        {"if": "resource.effective_tier >= T2", "then": "HIGH"}]},

    # ---- HIGH and IRREVERSIBLE. Physical material leaves the shelf.
    {"applies_to": "consume_reagent", "base": "MEDIUM", "raise_to": [
        {"if": "resource.effective_tier == T3", "then": "HIGH"}]},

    # ---- always HIGH: money leaves, disclosure cannot be recalled, a
    # regulated record acquires legal weight. No parameter makes these cheap.
    {"applies_to": "order_synthesis",    "base": "HIGH", "raise_to": []},
    {"applies_to": "release_to_partner", "base": "HIGH", "raise_to": []},
    {"applies_to": "submit_regulatory",  "base": "HIGH", "raise_to": []},
]

#: RV-1: absent ⇒ IRREVERSIBLE. The fail-safe direction matters more than any
#: individual entry, because the table will always be incomplete.
REVERSIBILITY = {
    "read_literature":    "REVERSIBLE",
    "run_simulation":     "REVERSIBLE",
    "predict_structure":  "REVERSIBLE",
    "register_candidate": "REVERSIBLE",
    "schedule_assay":     "REVERSIBLE",     # cancellable up to cutoff
    "consume_reagent":    "IRREVERSIBLE",
    "order_synthesis":    "IRREVERSIBLE",
    "release_to_partner": "IRREVERSIBLE",
    "submit_regulatory":  "IRREVERSIBLE",
}

#: One typed schema per action class, every one F-HIGH (no free text reaches a
#: Proposal). The agent writes prose all day; none of it arrives here.
ADAPTERS = {
    "lit.v1": "F-HIGH", "sim.v1": "F-HIGH", "pred.v1": "F-HIGH",
    "reg.v1": "F-HIGH", "assay.v1": "F-HIGH", "reagent.v1": "F-HIGH",
    "synth.v1": "F-HIGH", "release.v1": "F-HIGH", "regsub.v1": "F-HIGH",
}
SCHEMA_OF = {
    "read_literature": "lit.v1", "run_simulation": "sim.v1",
    "predict_structure": "pred.v1", "register_candidate": "reg.v1",
    "schedule_assay": "assay.v1", "consume_reagent": "reagent.v1",
    "order_synthesis": "synth.v1", "release_to_partner": "release.v1",
    "submit_regulatory": "regsub.v1",
}

#: Closed world on targets. `run_simulation` cannot name `synthesis-queue`
#: because the grammar does not admit it — the constraint lives at ingress,
#: where it is a shape question, rather than in a risk function, where it would
#: be a judgement. This is what stops an action-type mislabel from becoming the
#: cheap version of the A-7 attack.
PERMITTED_TARGETS = {
    "read_literature":    {"literature-store"},
    "run_simulation":     {"compute-cluster"},
    "predict_structure":  {"compute-cluster"},
    "register_candidate": {"candidate-registry"},
    "schedule_assay":     {"assay-queue"},
    "consume_reagent":    {"reagent-inventory"},
    "order_synthesis":    {"synthesis-queue"},
    "release_to_partner": {f"partner-channel:{p}" for p in PROGRAMS},
    "submit_regulatory":  {"regulatory-submission"},
}

#: Roles a quorum MUST contain, over and above AT-2 distinctness and count.
#: Disclosure leaving the trust boundary needs contracts in the room.
REQUIRED_ROLES = {"release_to_partner": {DISCLOSURE_ROLE}}


# ------------------------------------------------------------------- bundle
@dataclass
class ResearchBundle(Bundle):
    """
    The reference `Bundle` plus the three domain facts this business needs.

    All three are inside `hash()`. That is the whole point of putting them here
    rather than in a config file: `policy_bundle_hash` appears in every receipt
    and every Attestation Object, so a party that alters program ownership or a
    permitted target set invalidates every signature that depended on it. A
    policy input that is not covered by the bundle signature is a transmitted
    value wearing a policy costume — RES-8, one layer out.
    """
    resource_program: dict = field(default_factory=dict)
    dataset_program: dict = field(default_factory=dict)
    permitted_targets: dict = field(default_factory=dict)
    required_roles: dict = field(default_factory=dict)

    def hash(self) -> str:
        return h({
            "epoch": self.epoch, "floors": self.floors,
            "risk_functions": self.risk_functions, "adapters": self.adapters,
            "schemas": self.schemas, "reversibility": self.reversibility,
            "min_suite": self.min_suite,
            # AT-3 threshold — same reason as the attesters below. A subclass
            # that widened the hash but dropped quorum_k would let the
            # simulation's own bundle run a threshold nothing signed.
            "quorum_k": self.quorum_k,
            # DR-13 notice recipients. THIRD field to arrive in the base class
            # and need adding here by hand — after quorum_k and the attester
            # registry. That is a defect the shape of this method invites: it
            # RESTATES the parent's dict instead of extending it, so every new
            # base-class field is silently dropped until somebody notices, and
            # nothing fails when it is. Kept as a restatement anyway, because
            # the alternative — inheriting a dict and adding to it — makes the
            # signed field set depend on a superclass the reader cannot see,
            # and this file's whole argument is that a policy input not covered
            # by the signature is a transmitted value in a policy costume. The
            # cost is this comment and the discipline it asks for.
            "notice_targets": self.notice_targets,
            # PB-KEY: the key registry, same reason as the base class — see
            # acp_executor.Bundle.hash. A subclass that widened the hash with
            # domain fields but not with the attesters would reintroduce the
            # gap for exactly the bundle the simulation actually runs.
            "attesters": {who: k.fingerprint()
                          for who, k in sorted(self.attester_keys.items())},
            "receipt_key": self.receipt_key.fingerprint(),
            # the domain fields, signature-covered along with everything else
            "resource_program": self.resource_program,
            "dataset_program": self.dataset_program,
            "permitted_targets": {k: sorted(v)
                                  for k, v in self.permitted_targets.items()},
            "required_roles": {k: sorted(v)
                               for k, v in self.required_roles.items()},
        })

    # -- domain lookups, all read-only to the runtime by PB-4 ---------------
    def program_of(self, resource: str) -> str | None:
        return self.resource_program.get(resource)

    def program_of_dataset(self, dataset: str) -> str | None:
        """Owning program, recomputed from signed policy. None ⇒ unknown ⇒ DENY."""
        return self.dataset_program.get(dataset)

    def targets_allowed(self, task_type: str) -> set:
        # Unknown action ⇒ no permitted target. Same fail-safe direction as
        # RK-1's absent⇒T3 and RV-1's absent⇒IRREVERSIBLE.
        return self.permitted_targets.get(task_type, set())

    def roles_required(self, task_type: str) -> set:
        return self.required_roles.get(task_type, set())


def make_bundle(epoch: int = 1) -> ResearchBundle:
    return ResearchBundle(
        epoch=epoch,
        quorum_k=2,                   # AT-3: signed, never read from an attestation
        floors=dict(FLOORS),
        risk_functions=[dict(r) for r in RISK_FUNCTIONS],
        adapters=dict(ADAPTERS),
        attester_keys=dict(ATTESTER_KEYS),
        receipt_key=RECEIPT_SIGNER.public(),
        schemas={sid: f"sha256:{sid}" for sid in ADAPTERS},
        reversibility=dict(REVERSIBILITY),
        resource_program=dict(RESOURCE_PROGRAM),
        dataset_program=dict(DATASET_PROGRAM),
        permitted_targets={k: set(v) for k, v in PERMITTED_TARGETS.items()},
        required_roles={k: set(v) for k, v in REQUIRED_ROLES.items()},
    )


# ------------------------------------------------------------ grading table
def proposal(task_type: str, target: str, *, operator: str = "sci-01",
             program: str = "prog-internal", **params) -> dict:
    """A canonical Proposal. Closed shape: the agent may fill fields, never add them."""
    return {"task_type": task_type, "schema_id": SCHEMA_OF.get(task_type, "unknown.v1"),
            "tenant_id": "t1", "targets": [target], "operator": operator,
            "program": program, "params": params or {}}


def demands_of(risk: str, reversible: str) -> str:
    if risk == "HIGH" and reversible == "IRREVERSIBLE":
        return "quorum + POSITIVE acknowledgement (DR-9)"
    if risk == "HIGH":
        return "quorum + hold; releases on silence, counted unverified"
    if risk == "MEDIUM":
        return "policy only, audited — no hold"
    return "none — fast path"


def grade(bundle: ResearchBundle, task_type: str, target: str) -> tuple[str, str, str]:
    """
    Floor-only risk and reversibility, recomputed exactly as the Executor does.

    An ungraded action does not come back HIGH — it comes back DENY. The
    reference Executor has no risk function to apply and refuses at 8.4-3,
    which is P-4's "unknown is never LOW" taken to its conclusion. That is
    stricter than grading it HIGH and is reported as what it is, because a
    simulation that rounded it to HIGH would be describing a weaker system than
    the one actually running.
    """
    ex = Executor(bundle=bundle, ledger=Ledger(), context={})
    p = proposal(task_type, target)
    rev = ex.recompute_reversibility(p)
    try:
        risk = ex.recompute_floor_risk(p)
    except FailClosed as e:
        return "DENY", rev, f"refused at policy evaluation [{e.rule}]"
    return risk, rev, demands_of(risk, rev)


#: (action, target, expected floor risk, expected reversibility)
#: This is brief §3's table, restated as assertions. If a row here disagrees
#: with the bundle, the bundle is wrong — not the row.
EXPECTED = [
    ("read_literature",    "literature-store",       "LOW",    "REVERSIBLE"),
    ("run_simulation",     "compute-cluster",        "LOW",    "REVERSIBLE"),
    ("predict_structure",  "compute-cluster",        "LOW",    "REVERSIBLE"),
    ("register_candidate", "candidate-registry",     "MEDIUM", "REVERSIBLE"),
    ("schedule_assay",     "assay-queue",            "HIGH",   "REVERSIBLE"),
    ("consume_reagent",    "reagent-inventory",      "HIGH",   "IRREVERSIBLE"),
    ("order_synthesis",    "synthesis-queue",        "HIGH",   "IRREVERSIBLE"),
    ("release_to_partner", "partner-channel:prog-alpha", "HIGH", "IRREVERSIBLE"),
    ("submit_regulatory",  "regulatory-submission",  "HIGH",   "IRREVERSIBLE"),
]


def show_table() -> None:
    b = make_bundle()
    print("=" * 92)
    print("ACTION GRADING — what an incorrect action consumes, and whether it comes back")
    print("=" * 92)
    print(f"{'action':<20}{'target':<28}{'floor':<8}{'reversible':<12}demands")
    print("-" * 92)
    for task, target, _, _ in EXPECTED:
        risk, rev, demands = grade(b, task, target)
        print(f"{task:<20}{target:<28}{risk:<8}"
              f"{('yes' if rev == 'REVERSIBLE' else 'NO'):<12}{demands}")
    print("-" * 92)
    risk, rev, demands = grade(b, "dispose_of_sample", "reagent-inventory")
    print(f"{'(unclassified)':<20}{'—':<28}{risk:<8}"
          f"{('yes' if rev == 'REVERSIBLE' else 'NO'):<12}{demands}")
    print("\nAn action nobody has graded yet cannot be proposed at all: there is no")
    print("risk function to apply, so it is refused at policy evaluation rather than")
    print("graded HIGH, and its reversibility defaults to IRREVERSIBLE (RV-1) so no")
    print("later code path can find a reason to release it on silence. The fail-safe")
    print("direction matters more than any individual row above, because the table")
    print("will always be incomplete.")


def _perturb(b: ResearchBundle, name: str) -> bool:
    """
    Change one field in a way `hash()` must notice. Returns False for a field
    this helper cannot meaningfully alter, so a new field of an unhandled type
    is SKIPPED rather than silently passing — and the skip is visible here
    rather than reported as coverage.
    """
    v = getattr(b, name)
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        setattr(b, name, v + 1)
    elif isinstance(v, str):
        setattr(b, name, v + "-probe")
    elif isinstance(v, dict):
        # An EMPTY dict is the case that matters: `notice_targets` is empty in
        # this bundle, so only an insertion probes it. A pop-only helper would
        # have skipped the exact field that motivated this check.
        if v:
            v.pop(next(iter(v)))
        else:
            v["__probe__"] = ["__probe__"]
    elif isinstance(v, list):
        v.append({"applies_to": "__probe__", "base": "LOW", "raise_to": []})
    elif name == "receipt_key":
        setattr(b, name, next(iter(ATTESTER_KEYS.values())))
    else:
        return False
    return True


def check() -> int:
    """Prove the action classes compute correctly before anything else exists."""
    b = make_bundle()
    bad = 0
    print("=" * 92)
    print("GRADING TABLE — CHECK")
    print("=" * 92)
    for task, target, want_risk, want_rev in EXPECTED:
        risk, rev, _ = grade(b, task, target)
        ok = (risk == want_risk and rev == want_rev)
        bad += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {task:<20}{target:<28}"
              f"{risk:<8}{rev}")
        if not ok:
            print(f"        expected {want_risk}/{want_rev}")

    # RV-1 / RK-1: the fail-safe defaults, which are the rows that matter most.
    ex = Executor(bundle=b, ledger=Ledger(), context={})
    rev = ex.recompute_reversibility(proposal("dispose_of_sample", "reagent-inventory"))
    ok = rev == "IRREVERSIBLE"
    bad += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {'(ungraded action)':<20}"
          f"{'—':<28}{'—':<8}{rev}  [RV-1 absent ⇒ IRREVERSIBLE]")

    # ... and the risk side refuses outright rather than grading it. Asserted
    # explicitly so that a future bundle silently acquiring a catch-all risk
    # function shows up here as a failure rather than as a quiet downgrade.
    risk, _, _ = grade(b, "dispose_of_sample", "reagent-inventory")
    ok = risk == "DENY"
    bad += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {'(ungraded risk)':<20}"
          f"{'—':<28}{risk:<8}—  [8.4-3 refused, not graded HIGH]")

    ok = b.floor_of("resource-nobody-classified") == "T3"
    bad += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {'(unclassified res)':<20}"
          f"{'—':<28}{b.floor_of('resource-nobody-classified'):<8}"
          f"—  [RK-1 absent ⇒ T3]")

    # An unknown action type has no permitted target set, so ingress refuses it
    # before risk is ever computed.
    ok = b.targets_allowed("dispose_of_sample") == set()
    bad += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {'(ungraded targets)':<20}"
          f"{'—':<28}{'—':<8}—  [closed world: no permitted target]")

    # The domain fields must be signature-covered, or they are policy in name
    # only. Mutate one and the bundle hash must move.
    h0 = b.hash()
    b2 = make_bundle()
    b2.resource_program["partner-channel:prog-alpha"] = "prog-beta"
    ok = b2.hash() != h0
    bad += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {'(program ownership)':<20}"
          f"{'—':<28}{'—':<8}—  [covered by policy_bundle_hash]")

    # EVERY signed-policy field must move the hash — not just the one above.
    #
    # This check exists because it did not, three times. `ResearchBundle.hash()`
    # RESTATES the parent's dict rather than extending it, so a field added to
    # `Bundle.hash()` is silently dropped here until somebody notices: it
    # happened to `quorum_k`, to the attester registry, and again to DR-13's
    # `notice_targets`. Nothing failed on any of the three. The subclass hash is
    # self-consistent whatever it covers, and no line of the `--suites` gate
    # runs this file, so the omission is invisible from every direction that
    # normally reports.
    #
    # Enumerated from `dataclasses.fields` rather than from a list written here,
    # so a field added tomorrow joins this check without anyone remembering to
    # add it. A hand-written list of field names would be a second definition of
    # the class's own field set — the encoding-split defect, one level up, in
    # the very check meant to catch it.
    uncovered = []
    for f in dc_fields(make_bundle()):
        probe = make_bundle()
        if not _perturb(probe, f.name):
            continue
        if probe.hash() == h0:
            uncovered.append(f.name)
    ok = not uncovered
    bad += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {'(hash covers all)':<20}"
          f"{'—':<28}{'—':<8}—  [every signed field moves policy_bundle_hash]")
    if uncovered:
        print(f"        NOT covered by ResearchBundle.hash(): {', '.join(uncovered)}")

    print("=" * 92)
    print(f"RESULT: {len(EXPECTED) + 6 - bad}/{len(EXPECTED) + 6}"
          f"{'' if not bad else '  — REVIEW REQUIRED'}")
    return 1 if bad else 0


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(check())
    show_table()
