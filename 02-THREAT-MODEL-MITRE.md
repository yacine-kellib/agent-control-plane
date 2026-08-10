# 02 — Threat model and MITRE mapping

## ATLAS version pin and identifier verification

**Pinned release:** ATLAS content version **2026.07** (released 2026-07-31), data format version 6.0.0, obtained from the authoritative machine-readable source `github.com/mitre-atlas/atlas-data`, file `dist/v6/ATLAS-2026.07.yaml`. Verified 2026-08-10.

At that release ATLAS contains **16 tactics, 178 techniques (including sub-techniques), 37 mitigations and 68 case studies**.

**On the disagreement between secondary sources.** Earlier drafts of this section recorded that public sources variously reported 14 or 16 tactics and between 84 and 167 techniques. That disagreement is now explained rather than merely flagged:

- ATLAS ships **monthly content releases**; a count is only meaningful with a release attached. 84 techniques was v5.1.0 (November 2025).
- Since release 2026.05 / format 6.0.0, **content and format versions are numbered separately** (content `YYYY.MM`, format semver), so citations mixing "v5.x" with a 2026 date are comparing different things.
- **14 tactics is ATT&CK Enterprise, not ATLAS.** ATLAS has 16.
- Counts differ by whether sub-techniques are included.

**Method.** Every identifier below was checked directly against the pinned YAML, not against any secondary source. **Three identifiers used in earlier revisions of this dossier were wrong or stale and are corrected below.** This is the reason the rule exists.

| Earlier revision said | Status at 2026.07 | Correction |
|---|---|---|
| `AML.T0048` — contested between *ML Supply Chain Compromise* and *External Harms*; **excluded** pending verification | Resolved: `AML.T0048` **is** *External Harms* | The contest was an artefact of stale secondary sources. Supply chain is `AML.T0010` (*AI Supply Chain Compromise*). |
| `AML.T0054` — *Indirect Prompt Injection* | **Wrong.** `AML.T0054` is *LLM Jailbreak* | Indirect injection is `AML.T0051.001` (*Indirect*), a sub-technique of `AML.T0051`. |
| `AML.T0018` — *Backdoor ML Model* | **Renamed.** `AML.T0018` is now *Manipulate AI Model* | Poisoning the model is `AML.T0018.000`; backdoor-trigger insertion is `AML.T0043.004`. |
| `AML.T0110` — flagged as corroborated by a single source | **Confirmed** as *AI Agent Tool Poisoning* | The caveat can be removed. |
| `AML.T0020` — *Poison Training Data* | Current name *Training Data Poisoning* | Name only. |

**ATLAS is threat-side, not control-side.** It pairs with NIST AI RMF, ISO 42001 and the OWASP LLM Top 10 rather than replacing them. The mapping below answers "which techniques does this architecture constrain", not "which controls do we have".

**Revalidation is a release obligation, not a one-off.** ATLAS updates monthly. Any deployment or publication of this dossier MUST re-pin the release and re-verify identifiers against `atlas-data` before external use, and record the release and date in this section as done above.

---

## Positioning: what ACP constrains, and what it does not

ACP does not prevent a model from being manipulated. It prevents a successful manipulation from **becoming an action**. That distinction structures the mapping: input techniques stay open, impact techniques are constrained.

| Surface | ACP position |
|---------|----------------|
| Injection into the model's context | **Not addressed.** Assumption: the model is manipulable. |
| Model output → structured action | **Constrained.** The model emits only typed, schema-validated proposals (§6). |
| Proposal → decision | **Constrained.** Risk recomputed from signed policy. |
| Decision → execution | **Constrained.** This is INV-1-HIGH. |
| Trace erasure | **Constrained.** Audit chain anchored before release (AU-7). |

---

## ATLAS mapping (corroborated identifiers only)

| ATLAS technique | ACP position | Mechanism |
|-----------------|----------------|-----------|
| **AML.T0051** — LLM Prompt Injection | **Out of scope by design.** The architecture assumes injection succeeds and refuses to depend on it failing. | Model output never reaches an executor: it passes a schema validator then a policy engine (B-3, B-4). A successful injection yields at best a well-formed proposal, subject to the same evaluation as a legitimate one. |
| **AML.T0051.001** — LLM Prompt Injection: Indirect | **Same.** The provenance of injected content changes nothing on the execution path. | §6 closed grammar; conceded as *unnovel* (§2.2). |
| **AML.T0086** — Exfiltration via AI Agent Tool Invocation | **Partially constrained.** | The agent has no direct tool access (B-2: no network egress, no function calling, no channel other than text). Every action goes through a governed proposal. Exfiltration through an *authorised* action remains possible and is a matter of policy correctness, not architecture. |
| **AML.T0110** — AI Agent Tool Poisoning | **Partially constrained.** *(Verified against ATLAS 2026.07.)* | Adapter bindings are registered in the signed bundle and the fidelity class is adapter-stamped, never client-settable (B-6). Modifying a tool requires a bundle change under offline key (RK-5). |
| **AML.T0018** — Manipulate AI Model (incl. `.000` Poison AI Model) | **Not addressed, neutralised downstream.** | A backdoored model produces proposals, not executions. The risk floor comes from the signed bundle, never from the model. |
| **AML.T0020** — Training Data Poisoning | **Not addressed, same reasoning.** | Poisoning changes what the model proposes, not what policy authorises. |
| **AML.T0043** — Craft Adversarial Data | **Not addressed.** | Out of scope: ACP does not defend the model. |
| **AML.T0024** — Exfiltration via AI Inference API | **Out of scope.** | Concerns model access, not the action control plane. |

**Honest reading of this table:** ACP "covers" only three ATLAS techniques, and partially. That is correct and intended. An architecture claiming to cover the whole matrix would be lying. ACP's value sits on the **Impact** and **Defense Evasion** tactics, where the ATT&CK mapping below is the relevant one.

---

## ATT&CK Enterprise mapping (stable identifiers)

ACP's components are ordinary infrastructure services; ATT&CK is what describes their compromise.

| Technique | Internal ACP threat | Constraint |
|-----------|----------------------|-----------|
| **T1078** — Valid Accounts | T-24: display lie; the approver signs in good faith | DR-1..DR-12: deferred release, independent notification, mandatory acknowledgement for irreversible actions |
| **T1550** — Use Alternate Authentication Material | T-14, T-19: attestation reuse or misbinding | AT-8/TR-10: full object transmitted, binding verified from signed bytes; single-use ledger |
| **T1548** — Abuse Elevation Control Mechanism | X1, T-25: downgrade of declared risk or reversibility | TR-8 / RV-3: recomputed from the signed bundle, never read from the receipt |
| **T1562** — Impair Defenses | T-27: signature suite downgrade | CR-4: suite floor in the signed bundle, non-negotiable |
| **T1070** — Indicator Removal | T-29: audit rewrite before anchoring | AU-7: anchor before release, inside the existing hold window |
| **T1485 / T1565** — Data Destruction / Manipulation | T-22: origin substitution → duplicated action | DS-6f: ledger-pinned origin binding, two-phase |
| **T1195** — Supply Chain Compromise | Forged policy bundle | Offline Ed25519 signing, write-isolated repository, monotonic epoch (RAD-3) |
| **T1499** — Endpoint DoS | T-30: anchor denial → approver saturation | AU-6 revised: suspend sampling or fail closed during outage |
| **T1098** — Account Manipulation | T-28: accumulator inflation → operator lockout | AC-5: count at release, never at decision |
| **T1036** — Masquerading | Y4: unbound operator identity | `operator` is an AT-1 field, signature-covered |

---

## Threats neither framework covers

Some threats in this dossier have no clean equivalent in ATLAS or ATT&CK, which is itself a useful observation.

| Threat | Nature | Why it is absent from the frameworks |
|--------|--------|--------------------------------------|
| **T-26** — Notification habituation | System effect, not an attacker capability | A control whose default outcome equals its approved outcome teaches its users to skip it. No adversarial framework models a control degrading through its own use. |
| **A-7** — Label dishonesty | Governance defect | No adversarial technique: the label is wrong from the outset, no attack is required. |
| **W3 → erasable detection** | Composition | T1070 exists; what the framework lacks is that the *erasure* defeats a *detection* mechanism other disclosed residuals explicitly depend on. |

## OWASP LLM Top 10 correspondence

| OWASP | Position |
|-------|----------|
| LLM01 Prompt Injection | Assumed successful; neutralised downstream |
| LLM02 Insecure Output Handling | §7 output validation; raw output never transmitted anywhere but the validator (B-3) |
| LLM05 Supply Chain | Signed bundle, epochs, RK-5 |
| LLM06 Excessive Agency | **The core of the design.** The control plane *is* the answer to LLM06 |
| LLM08 Tool autonomy | B-2: no direct tool access |
