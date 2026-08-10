/**
 * Client for callers that propose actions, sign acknowledgements, and query
 * status.
 *
 * Scaffold — not implemented (build order step 6).
 *
 * One rule for whoever implements it: this client may never compute or assert
 * a security value on the control plane's behalf. It carries a proposal; it
 * does not carry a risk grade, a reversibility claim, or an authorisation
 * decision. Every one of those is recomputed by the Executor from the signed
 * bundle (RES-8), because a compromised client writes the whole message.
 */

export const NOT_IMPLEMENTED = 'acp-client: scaffold only (build order step 6)';
