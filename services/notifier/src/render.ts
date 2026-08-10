/**
 * The notifier's rendering path.
 *
 * THIS FILE MUST NEVER BE SHARED WITH services/approval. Not by import, not by
 * a common helper package, not by "extracting the duplication". The duplication
 * IS the control: DR-2 reduces the A-8 lying-screen attack to a two-compromise
 * problem only if an attacker who owns one rendering path does not thereby own
 * the other. Factoring these together is not a refactor, it is the vulnerability.
 *
 * The Python simulation enforces the same rule with `path_id()` over
 * `render.__code__.co_filename`, so that a re-export is caught rather than
 * merely discouraged.
 *
 * Scaffold — not implemented (build order step 5).
 */

export function renderPathId(): string {
  return import.meta.url;
}
