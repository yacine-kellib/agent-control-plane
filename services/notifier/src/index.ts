/**
 * Independent notification path (DR-2, DR-8).
 *
 * Open finding **T-32**: today the notifier self-certifies its own
 * independence. `note.source_path`, `note.from_canonical` and `delivered` are
 * classified **T** in the classification table because the Executor reads them
 * from the notifier — the party it is verifying.
 *
 * Splitting this into its own service with its own dependency tree improves
 * BUILD-TIME provenance, which the residual document already credits. It does
 * NOT close T-32, and this service must not claim it does. Closing it means
 * the Executor establishing independence from two distinct signed service
 * identities named in the signed bundle — values this process does not mint.
 *
 * Scaffold — not implemented (build order step 5).
 */

import { renderPathId } from './render.js';

export function notifierPathId(): string {
  return renderPathId();
}
