#!/usr/bin/env python3
"""
policy.py — the deterministic policy engine (brief §6.1, `policy` service).

Responsibility: recompute risk and reversibility from the SIGNED BUNDLE and
decide a disposition. Never read a derived security value from the Proposal.

The evaluation order below is §8.4's, with one domain step inserted. That step —
XPROG-1, the cross-program rule — is the single most important rule in this
simulation, and it fires at step 5, BEFORE quorum is even considered. A
cross-program disclosure is not a thing that needs more approvers; it is a thing
that must not be expressible. Sending it to a quorum would already be the bug,
because a quorum is a mechanism for authorising things that MAY happen.

Run:  python3 -m sim.policy   # the rule table, and XPROG-1 demonstrated
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field

import sim  # noqa: F401
from acp_executor import Executor, Ledger, FailClosed

from sim.bundle import ResearchBundle, SCHEMA_OF, make_bundle, proposal
from sim.world import PEOPLE, capabilities

# V-1: the Proposal schema is CLOSED. An unknown field is a hard error, never
# ignored — "ignore unknown fields" is how a control plane acquires a channel
# nobody audited.
PROPOSAL_FIELDS = {"task_type", "schema_id", "tenant_id", "targets",
                   "operator", "program", "params"}

#: Per-action parameter schemas, also closed. Bounds are what make an action
#: class enumerable, and enumerable is what makes it decidable.
PARAM_FIELDS = {
    "read_literature":    {"query"},
    "run_simulation":     {"candidate", "cycles"},
    "predict_structure":  {"candidate"},
    "register_candidate": {"candidate", "score"},
    "schedule_assay":     {"candidate", "assay_type"},
    "consume_reagent":    {"reagent", "quantity_mg"},
    "order_synthesis":    {"candidate", "cost_eur"},
    "release_to_partner": {"dataset", "source_program"},
    "submit_regulatory":  {"dossier", "milestone"},
}

ALLOW, ATTEST, DENY = "ALLOW", "ATTEST", "DENY"


@dataclass
class Decision:
    disposition: str
    risk: str = "—"
    reversibility: str = "—"
    rule: str = ""
    reason: str = ""
    required_count: int = 0
    required_roles: set = field(default_factory=set)
    #: Recomputed, never transmitted. Kept for audit and for the notifier's
    #: independent render.
    program: str | None = None

    @property
    def refused(self) -> bool:
        return self.disposition == DENY


class PolicyEngine:
    """
    `Evaluate(Proposal, Bundle, Context) → Decision`, a pure function of its
    three arguments (P-1). No model, no randomness, no clock read inside
    evaluation.
    """

    def __init__(self, bundle: ResearchBundle, context: dict | None = None):
        self.bundle = bundle
        self.context = context if context is not None else \
            capabilities(bundle.permitted_targets)
        # The Executor's own recomputation path, reused rather than reimplemented
        # so that the Policy Engine and the Executor cannot drift. Evaluator
        # drift between the two is precisely what §9.3 step 7a cannot
        # distinguish from a compromised signing substrate (P-5).
        self._ex = Executor(bundle=bundle, ledger=Ledger(), context=self.context)

    # ------------------------------------------------------------------
    def evaluate(self, p: dict) -> Decision:
        b = self.bundle

        # -- step 0: closed schema (V-1). Unknown fields are a hard error. ---
        if not isinstance(p, dict):
            return Decision(DENY, rule="V-1", reason="proposal is not an object")
        extra = set(p) - PROPOSAL_FIELDS
        missing = PROPOSAL_FIELDS - set(p)
        if extra or missing:
            return Decision(DENY, rule="V-1",
                            reason=f"proposal schema violation "
                                   f"missing={sorted(missing)} extra={sorted(extra)}")

        task = p["task_type"]

        # -- step 1: schema attestation ------------------------------------
        if SCHEMA_OF.get(task) != p["schema_id"] or p["schema_id"] not in b.schemas:
            return Decision(DENY, rule="V-11",
                            reason="schema_id does not match task_type")

        # -- step 2: fidelity admission ------------------------------------
        try:
            fidelity = self._ex.recompute_fidelity(p)
        except FailClosed as e:
            return Decision(DENY, rule=e.rule, reason=e.detail)

        # -- step 3: action rule lookup ------------------------------------
        # An ungraded action has no risk function and is refused here. Note the
        # direction: it is not graded HIGH and sent to a quorum, it is refused.
        if not any(r["applies_to"] == task for r in b.risk_functions):
            return Decision(DENY, rule="8.4-3",
                            reason=f"no risk function for {task!r} — ungraded "
                                   f"action classes are refused, never assumed")

        # -- step 4: target admission (closed world) ------------------------
        targets = p.get("targets") or []
        allowed = b.targets_allowed(task)
        if len(targets) != 1 or targets[0] not in allowed:
            return Decision(DENY, rule="CW-1",
                            reason=f"{task} may not target {targets}")
        target = targets[0]

        # -- step 5: THE CROSS-PROGRAM RULE (XPROG-1) -----------------------
        # Fires before quorum. See the module docstring for why that ordering
        # is the whole point.
        params = p.get("params") or {}
        pextra = set(params) - PARAM_FIELDS.get(task, set())
        pmissing = PARAM_FIELDS.get(task, set()) - set(params)
        if pextra or pmissing:
            return Decision(DENY, rule="V-1",
                            reason=f"params schema violation "
                                   f"missing={sorted(pmissing)} extra={sorted(pextra)}")

        program = p.get("program")
        if task == "release_to_partner":
            d = self._cross_program(b, target, params)
            if d is not None:
                return d
            program = b.program_of(target)

        # -- step 6: identity & capability ---------------------------------
        operator = p.get("operator")
        person = PEOPLE.get(operator)
        if person is None or person.key is None:
            # The agent is not a principal. It cannot be the operator of
            # anything, and an unknown identity is never resolved generously.
            return Decision(DENY, rule="8.4-4",
                            reason=f"{operator!r} is not an operating principal")
        need = f"{task}:{target}"
        if need not in self.context.get(operator, set()):
            return Decision(DENY, rule="8.4-4",
                            reason=f"{operator} lacks capability {need}")

        # -- steps 7-9: tier resolution, risk, reversibility ---------------
        # Both recomputed from the signed bundle. Neither is read from the
        # Proposal, and there is nowhere in this function that could.
        try:
            risk = self._ex.recompute_floor_risk(p)
            reversibility = self._ex.recompute_reversibility(p)
        except FailClosed as e:
            return Decision(DENY, rule=e.rule, reason=e.detail)

        # -- step 11: disposition -------------------------------------------
        roles = b.roles_required(task)
        if risk == "HIGH":
            # EO-1: there is no configuration that makes this ALLOW.
            return Decision(ATTEST, risk, reversibility, rule="8.4-11",
                            reason="floor-HIGH always attests",
                            required_count=2, required_roles=set(roles),
                            program=program)
        if risk == "MEDIUM":
            return Decision(ALLOW, risk, reversibility, rule="8.4-11",
                            reason="medium: audited, no hold", program=program)
        return Decision(ALLOW, risk, reversibility, rule="B-5",
                        reason="fast path: no control interaction", program=program)

    # ------------------------------------------------------------------
    @staticmethod
    def _cross_program(b: ResearchBundle, target: str, params: dict) -> Decision | None:
        """
        XPROG-1. Data owned by one program may not leave through another
        program's channel.

        Both sides of the comparison come from the signed bundle:

          destination  ← bundle.program_of(target)          (which channel)
          source       ← bundle.program_of_dataset(dataset) (whose data)

        Neither is read from the Proposal. That is the difference between a
        rule and a suggestion here: the agent composes the entire Proposal, so
        a check that compared two agent-supplied strings would compare the
        attacker's claim against itself and always agree.
        """
        dataset = params.get("dataset")
        dest = b.program_of(target)
        src = b.program_of_dataset(dataset)

        if dest is None:
            return Decision(DENY, rule="XPROG-1",
                            reason=f"{target} is not a registered partner channel")
        if src is None:
            # P-4: unknown is never permissive. An unregistered dataset has no
            # owner, so there is no program boundary to check it against.
            return Decision(DENY, rule="XPROG-1",
                            reason=f"dataset {dataset!r} has no registered owning "
                                   f"program — refused rather than assumed")
        if src != dest:
            return Decision(DENY, rule="XPROG-1",
                            reason=f"cross-program disclosure refused: {dataset} "
                                   f"is owned by {src}, channel belongs to {dest}")

        # The Proposal's own claim is diagnostic. Where it disagrees with signed
        # policy that is a critical alert, exactly as TR-8 treats a receipt that
        # misstates its own risk — the party under verification has asserted
        # something the bundle does not support.
        claimed = params.get("source_program")
        if claimed is not None and claimed != src:
            return Decision(DENY, rule="XPROG-1/TR-8",
                            reason=f"CRITICAL: proposal claims source {claimed}, "
                                   f"signed policy says {src}")
        return None


# ---------------------------------------------------------------------- demo
def _show() -> int:
    b = make_bundle()
    pe = PolicyEngine(b)
    print("=" * 96)
    print("POLICY EVALUATION — dispositions, and the cross-program rule")
    print("=" * 96)

    cases = [
        ("fast path",
         proposal("run_simulation", "compute-cluster", operator="sci-01",
                  candidate="cand-8841", cycles=500)),
        ("audited, no hold",
         proposal("register_candidate", "candidate-registry", operator="sci-01",
                  candidate="cand-8841", score=0.82)),
        ("HIGH but reversible",
         proposal("schedule_assay", "assay-queue", operator="sci-01",
                  candidate="cand-8841", assay_type="binding")),
        ("HIGH + irreversible",
         proposal("order_synthesis", "synthesis-queue", operator="sci-01",
                  candidate="cand-8841", cost_eur=40000)),
        ("legitimate release (alpha data → alpha channel)",
         proposal("release_to_partner", "partner-channel:prog-alpha",
                  operator="sci-01", dataset="ds-alpha-binding-001",
                  source_program="prog-alpha")),
        ("THE ATTACK: alpha data → beta channel",
         proposal("release_to_partner", "partner-channel:prog-beta",
                  operator="sci-01", dataset="ds-alpha-binding-001",
                  source_program="prog-alpha")),
        ("the attack, lying about provenance",
         proposal("release_to_partner", "partner-channel:prog-beta",
                  operator="sci-01", dataset="ds-alpha-binding-001",
                  source_program="prog-beta")),
        ("unregistered dataset",
         proposal("release_to_partner", "partner-channel:prog-beta",
                  operator="sci-01", dataset="ds-who-knows",
                  source_program="prog-beta")),
        ("agent proposes as itself",
         proposal("run_simulation", "compute-cluster", operator="agent-01",
                  candidate="cand-1", cycles=1)),
    ]
    for label, p in cases:
        d = pe.evaluate(p)
        mark = {ALLOW: "ALLOW ", ATTEST: "ATTEST", DENY: "DENY  "}[d.disposition]
        print(f"  {mark} {label:<46} [{d.rule}] {d.reason}")

    print("=" * 96)
    print("Note the ordering: the cross-program refusals never reach a quorum.")
    print("A disclosure to a competitor is not something to ask two people about.")
    return 0


if __name__ == "__main__":
    sys.exit(_show())
