/**
 * Wire types for ACP.
 *
 * These will be GENERATED from `spec/schemas/*.schema.json` by
 * `tools/codegen.sh`, and the generated output is committed so the repository
 * stays clonable and buildable without a codegen toolchain. CI regenerates and
 * diffs: a dirty diff fails the build.
 *
 * Do not hand-edit once codegen lands. A hand-written type is a second
 * definition of an object the spec already defines, and two definitions of one
 * object is the encoding-split defect at the source level.
 *
 * Note on DR-2 independence: `services/notifier` and `services/approval` are
 * both permitted to depend on this package, and on nothing else in common.
 * These are the wire format. Rendering is not — no shared template engine,
 * formatter, sanitiser or component library. Without that carve-out the first
 * shared `formatDate()` is technically compliant and voids the property.
 */

/** Risk tier. Unknown is never LOW (P-4). */
export type RiskTier = 'LOW' | 'MEDIUM' | 'HIGH';

/** RV-1: an action with no classification is IRREVERSIBLE. */
export type Reversibility = 'REVERSIBLE' | 'IRREVERSIBLE';

/**
 * The tier for a resource absent from the signed floors table.
 * RK-1: absent means unknown, and unknown is the highest tier.
 */
export const UNCLASSIFIED_RESOURCE_TIER: RiskTier = 'HIGH';

/** RV-1 default, stated as a value so a missing lookup cannot yield the permissive one. */
export const UNCLASSIFIED_ACTION_REVERSIBILITY: Reversibility = 'IRREVERSIBLE';
