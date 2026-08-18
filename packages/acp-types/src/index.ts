/**
 * Wire types for ACP.
 *
 * The types themselves are GENERATED from `spec/schemas/bundle/*.schema.json`
 * by `tools/codegen.sh` and live in `./generated.js`, which is re-exported
 * below. `spec/` is the only normative source, so a hand-written wire type is a
 * second definition of an object the specification already defines — and two
 * definitions of one object is the encoding-split defect at the source level.
 *
 * The generated output is committed so the repository stays clonable and
 * buildable without a codegen toolchain. `./tools/codegen.sh --check`
 * regenerates and compares, and runs from `tools/selftest.sh`: a generator
 * whose output nobody re-derives is a generator that has silently stopped
 * describing its source.
 *
 * **Do not hand-edit `generated.ts`.** The drift check exists to catch that
 * edit, and it will.
 *
 * This file is hand-written and holds only what is true of the PACKAGE rather
 * than of the schemas.
 *
 * Note on DR-2 independence: `services/notifier` and `services/approval` are
 * both permitted to depend on this package, and on nothing else in common.
 * These are the wire format. Rendering is not — no shared template engine,
 * formatter, sanitiser or component library. Without that carve-out the first
 * shared `formatDate()` is technically compliant and voids the property.
 *
 * ## What used to be here, and why it was wrong (ACP-51)
 *
 * A hand-written `RiskTier = 'LOW' | 'MEDIUM' | 'HIGH'`, and beside it
 *
 *     export const UNCLASSIFIED_RESOURCE_TIER: RiskTier = 'HIGH';
 *
 * RK-1 says a resource absent from the signed floors table is **T3**. `'HIGH'`
 * is a risk level, not a tier — the schemas define two ordered domains over
 * different subjects, and §8.4 composes both with `max`, which is exactly why
 * one type served for both until someone read the schemas as a producer of
 * types. The Python reference had it right all along
 * (`floors.get(resource, "T3")`).
 *
 * Both ladders are now generated, separately, from the `x-acp-absent` and
 * `x-acp-ordered` annotations on the schemas. The fail-safe value is not
 * restated here: `floorsLookup()` in `./generated.js` returns it, and there is
 * no other way to read a floor.
 */

export * from './generated.js';
