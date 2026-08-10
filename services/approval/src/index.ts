/**
 * Approval surface — where a human sees what they are authorising.
 *
 * A-8 is conceded, not solved: authentication is not comprehension. A signed
 * acknowledgement proves a key was used, never that a person read and
 * understood the screen. Nothing built here may imply otherwise, and the
 * dossier states the limit before the strength.
 *
 * Scaffold — not implemented (build order step 5).
 */

import { renderPathId } from './render.js';

export function approvalPathId(): string {
  return renderPathId();
}
