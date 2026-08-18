#!/usr/bin/env bash
# codegen.sh — generate the Rust and TypeScript wire types from spec/schemas/.
#
#   ./tools/codegen.sh            rewrite the generated files
#   ./tools/codegen.sh --check    assert the committed files are current
#
# The entry point is shell because every other tool here is (verify.sh,
# selftest.sh, sign-release.sh) and a reader looking for "the codegen command"
# should find it where the others live. The generator itself is
# tools/codegen.py, beside this file, and carries the reasoning.
#
# Exit codes are distinct on purpose:
#   0  generated, or up to date
#   1  DRIFT — the committed output no longer matches the schemas
#   2  HALT  — the schemas said something the generator will not guess about
#
# A drift and a halt are different failures and want different responses. Drift
# means "run this without --check". A halt means a schema is missing an
# x-acp-name, an x-acp-absent rule, or uses a construct nobody has taught this
# tool yet — and the answer is to state the intent in the schema, never to make
# the generator fall back to something plausible. The fallback for an absent
# rule is the permissive default, which is the whole thing this repository is
# built to prevent.
set -uo pipefail
cd "$(dirname "$0")/.."

exec python3 tools/codegen.py "$@"
