/**
 * The demo orchestrator: advances the clock, generates load, routes proposals,
 * records outcomes.
 *
 * **It never decides anything.** If the orchestrator can influence an
 * authorisation decision, it is a bypass — the same shape as T-32 one layer up,
 * and every number it produces afterwards is worthless.
 *
 * Two constraints for whoever implements it:
 *
 * 1. **No model-side defences.** No filtering, scoring or judging of model
 *    output, anywhere. The architecture assumes the model is manipulable and
 *    its guarantees do not depend on injection failing. In demos the model is
 *    shown complying fully; simulating a refusal misrepresents the claim (§5.1a).
 *
 * 2. **Determinism for replay.** If this drives a real model, model output
 *    becomes part of the replay and `verify.sh --suites` stops being
 *    reproducible. A recorded-transcript mode is required before any of this
 *    is wired into the gate.
 *
 * Scaffold — not implemented (build order step 7). The working reference is the
 * Python simulation in `sim/`, which runs the same day across seven real OS
 * processes.
 */

export const NOT_IMPLEMENTED = 'acp-orchestrator: scaffold only (build order step 7)';
