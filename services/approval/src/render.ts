/**
 * The approval UI's rendering path.
 *
 * THIS FILE MUST NEVER BE SHARED WITH services/notifier. See the twin comment
 * in that service. The two paths are deliberately separate implementations of
 * the same job, and the deliberate duplication is what DR-2 buys: an attacker
 * who controls the approval screen must ALSO control the notification to make
 * a display lie stick.
 *
 * If you are here because a linter flagged duplication between the two
 * services, the linter is wrong and the exclusion belongs in its config.
 *
 * Scaffold — not implemented (build order step 5).
 */

export function renderPathId(): string {
  return import.meta.url;
}
