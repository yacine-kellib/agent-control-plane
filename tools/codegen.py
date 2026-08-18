#!/usr/bin/env python3
"""Generate the Rust and TypeScript wire types from `spec/schemas/bundle/`.

    ./tools/codegen.sh            # rewrite the generated files
    ./tools/codegen.sh --check    # assert the committed files are current

`spec/` is the only normative source, and `CLAUDE.md` has said since the
polyglot restructure that Rust and TypeScript types are *generated* from it,
never hand-written: a hand-written type is a second definition of an object the
spec already defines, and two definitions of one object is the encoding-split
defect at the source level. Until this tool existed that sentence described an
intention. `packages/acp-types/src/index.ts` said its types "will be GENERATED"
and nothing generated them.

WHY THIS IS HAND-ROLLED rather than typify / quicktype / json-schema-to-
typescript. Every off-the-shelf generator emits `Option<T>` for an absent value
and `#[derive(Default)]` for a missing one, and those two mechanisms are exactly
how "absent" becomes "permissive". This repository's fail-safe defaults are the
thing it exists to protect:

    resource absent from floors.json        => T3, never T1        (RK-1, P-4)
    action absent from reversibility.json   => IRREVERSIBLE        (RV-1)
    action with no risk function            => REFUSED at 8.4-3    (not HIGH)
    action absent from notice_targets.json  => REFUSED             (DR-13)
    quorum_k absent                         => refuse the bundle   (PB-6)

A generated `Option<Tier>` that a caller writes `unwrap_or(Tier::T0)` on is the
whole class of defect this specification exists to prevent. So the open maps are
emitted with a PRIVATE field and a single accessor that returns the fail-safe
value directly — the permissive answer is not reachable, rather than merely
discouraged.

WHERE THE DEFAULTS COME FROM. Not from a table in this file. That would be a
second definition of RK-1 living next to a generator, which is the same defect
one layer down. They are read from `x-acp-absent` on the schema itself, and this
tool HALTS on an open map that does not carry one — the same posture as
`tools/sign-release.sh` halting on an unrecognised file type rather than
silently signing or silently skipping it. A generator that guesses a default is
a generator that eventually guesses the permissive one.

Three more annotations, all read and none invented here:

    x-acp-name      the type name. Halts if absent; a generator that invents
                    names invents names that drift.
    x-acp-ordered   emit an ordering. ONLY where the schema says the values are
                    ordered: Tier and Risk are ladders that §8.4 composes with
                    max, while SuiteId is not, because CR-4's floor is satisfied
                    by CONTAINMENT of primitives and never by rank. A derived
                    `Ord` on a suite makes `declared >= floor` compile, and that
                    comparison is the downgrade.
    x-acp-keyed-by  an array whose items are identified by one field, so the
                    generated lookup and the duplicate-key refusal know which.

WHAT THIS DOES NOT DO, stated because a generator that looks like a validator is
worse than no validator. It does not validate any bundle against any schema.
`pattern`, `minLength`, `maxLength`, `format` and `uniqueItems` are carried into
doc comments and are NOT enforced by the generated types. PB-7 (attester key
distinctness) is not expressible in JSON Schema at all and lives in the loader,
where a live defect was found in exactly that gap (ACP-53). Nothing yet checks a
real bundle against these files; that is ACP-52 and it is open.

THE OUTPUT IS COMMITTED so the repository stays clonable and buildable with no
codegen toolchain, and `--check` is what stops a committed generator output from
quietly ceasing to describe its source. That check runs from `tools/selftest.sh`
rather than from the gate, because it is a claim about the tooling. It is
mirrored on `tools/gen-crypto-vectors.py --check`, for the reason that file
gives: a generator whose output nobody re-derives is a generator that has
silently stopped.
"""
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO / "spec" / "schemas" / "bundle"
RUST_OUT = REPO / "crates" / "acp-core" / "src" / "generated.rs"
TS_OUT = REPO / "packages" / "acp-types" / "src" / "generated.ts"

DOC_WIDTH = 74


class Halt(Exception):
    """The schemas said something this tool will not guess about.

    Raised rather than defaulted, everywhere. The alternative is a generator
    that produces plausible types from a schema it did not understand, and the
    failure mode of that is a permissive default nobody chose.
    """


# --------------------------------------------------------------------- the IR


class Named:
    def __init__(self, name, doc, origin):
        self.name, self.doc, self.origin = name, doc, origin


class EnumType(Named):
    def __init__(self, name, doc, origin, values, ordered):
        super().__init__(name, doc, origin)
        self.values, self.ordered = values, ordered


class NewtypeType(Named):
    """A constrained scalar with its own name, e.g. an Ed25519 public key.

    Emitted as a distinct type rather than an alias so that a classical key and
    a post-quantum key cannot be passed to each other's parameter. The pattern
    is documentation: see the module note on what this tool does not validate.
    """

    def __init__(self, name, doc, origin, pattern):
        super().__init__(name, doc, origin)
        self.pattern = pattern


class StructType(Named):
    def __init__(self, name, doc, origin, fields, closed):
        super().__init__(name, doc, origin)
        self.fields, self.closed = fields, closed


class Field:
    def __init__(self, json_name, ty, required, doc, const=None, minimum=None):
        self.json_name, self.ty, self.required = json_name, ty, required
        self.doc, self.const, self.minimum = doc, const, minimum


class Ref:
    """A reference to a named type."""

    def __init__(self, name):
        self.name = name


class Prim:
    def __init__(self, kind):          # 'string' | 'u64' | 'i64' | 'bool'
        self.kind = kind


class MapOf:
    """An open map: deployment-specific keys, closed values, an absent rule."""

    def __init__(self, value, absent, key_doc):
        self.value, self.absent, self.key_doc = value, absent, key_doc


class ListOf:
    def __init__(self, item, keyed_by=None, absent=None):
        self.item, self.keyed_by, self.absent = item, keyed_by, absent


class Absent:
    def __init__(self, clause, behaviour, why, value=None):
        self.clause, self.behaviour, self.why, self.value = clause, behaviour, why, value


# ------------------------------------------------------------------ the parse


def load_schemas(schema_dir):
    files = sorted(schema_dir.glob("*.schema.json"))
    if not files:
        raise Halt(f"no schemas under {schema_dir}")
    docs = {}
    for path in files:
        try:
            docs[path.name] = json.loads(path.read_text())
        except ValueError as e:
            raise Halt(f"{path.name} is not JSON: {e}") from None
    return docs


class Parser:
    def __init__(self, docs):
        self.docs = docs
        self.types = {}         # name -> Named
        self.roots = []         # names, in file order
        # $id -> filename, so a cross-file $ref resolves without a network
        # fetch. An offline generator that reaches for a URL is a generator
        # that behaves differently on a machine with no network.
        self.by_id = {}
        for fname, doc in docs.items():
            ident = doc.get("$id")
            if not ident:
                raise Halt(f"{fname} has no $id")
            self.by_id[ident] = fname

    def run(self):
        for fname in sorted(self.docs):
            doc = self.docs[fname]
            for key, sub in sorted(doc.get("$defs", {}).items()):
                self.declare(sub, f"{fname}#/$defs/{key}")
            self.roots.append(self.declare(doc, fname))
        return self

    def declare(self, node, origin):
        name = node.get("x-acp-name")
        if not name:
            raise Halt(
                f"{origin} has no x-acp-name. Every root and every $defs entry "
                "must name its type: a generator that invents a name invents a "
                "name that drifts.")
        if name in self.types and self.types[name].origin != origin:
            raise Halt(f"x-acp-name {name!r} is claimed by both "
                       f"{self.types[name].origin} and {origin}")
        doc = node.get("description", "")
        kind = node.get("type")
        if kind == "string" and "enum" in node:
            ty = EnumType(name, doc, origin, list(node["enum"]),
                          bool(node.get("x-acp-ordered", False)))
        elif kind == "string":
            ty = NewtypeType(name, doc, origin, node.get("pattern"))
        elif kind == "object" and "properties" in node:
            ty = StructType(name, doc, origin, None,
                            node.get("additionalProperties") is False)
            self.types[name] = ty          # declared before fields, for cycles
            ty.fields = self.fields_of(node, origin)
            return name
        else:
            raise Halt(f"{origin}: cannot generate a type for {kind!r}. Add "
                       "support deliberately rather than letting it default.")
        self.types[name] = ty
        return name

    def fields_of(self, node, origin):
        required = set(node.get("required", []))
        out = []
        for prop, sub in node["properties"].items():
            out.append(Field(
                prop,
                self.type_of(sub, f"{origin}.{prop}"),
                prop in required,
                sub.get("description", ""),
                const=sub.get("const"),
                minimum=sub.get("minimum"),
            ))
        return out

    def type_of(self, node, origin):
        if "$ref" in node:
            return Ref(self.resolve(node["$ref"], origin))
        kind = node.get("type")
        if kind == "object":
            if "additionalProperties" not in node:
                raise Halt(f"{origin}: an inline object with no "
                           "additionalProperties. Hoist it into $defs and give "
                           "it an x-acp-name.")
            value = node["additionalProperties"]
            if value is False:
                raise Halt(f"{origin}: an object with neither properties nor a "
                           "value schema is not a type this tool will guess at.")
            return MapOf(self.type_of(value, f"{origin}[*]"),
                         self.absent_of(node, origin),
                         node.get("propertyNames", {}).get("description", ""))
        if kind == "array":
            return ListOf(self.type_of(node["items"], f"{origin}[]"),
                          node.get("x-acp-keyed-by"),
                          self.absent_of(node, origin, required=False)
                          if "x-acp-keyed-by" in node else None)
        if kind == "string":
            return Prim("string")
        if kind == "integer":
            minimum = node.get("minimum")
            return Prim("u64" if minimum is not None and minimum >= 0 else "i64")
        if kind == "boolean":
            return Prim("bool")
        raise Halt(f"{origin}: unsupported schema type {kind!r}")

    def absent_of(self, node, origin, required=True):
        """Read the fail-safe absent rule, and HALT if a lookup has none.

        This is the control the whole tool is built around. An open map with no
        declared absent rule would be generated as a bare lookup, and a bare
        lookup returns `Option`, and an `Option` is unwrapped. Refusing to
        generate is the only answer that cannot become the permissive one.
        """
        rule = node.get("x-acp-absent")
        if rule is None:
            if not required:
                return None
            raise Halt(
                f"{origin} is a lookup table with no x-acp-absent rule.\n"
                "  Every table a caller can miss needs its absent case stated "
                "in the schema,\n"
                "  because the generated accessor has to return SOMETHING and "
                "the default\n"
                "  answer is the permissive one. Declare it:\n"
                '    "x-acp-absent": {"clause": "...", "behaviour": "value", '
                '"value": "...", "why": "..."}\n'
                '    "x-acp-absent": {"clause": "...", "behaviour": "refuse", '
                '"why": "..."}')
        for key in ("clause", "behaviour", "why"):
            if not rule.get(key):
                raise Halt(f"{origin}: x-acp-absent has no {key!r}")
        if rule["behaviour"] not in ("value", "refuse"):
            raise Halt(f"{origin}: x-acp-absent behaviour "
                       f"{rule['behaviour']!r} is not 'value' or 'refuse'")
        if rule["behaviour"] == "value" and "value" not in rule:
            raise Halt(f"{origin}: x-acp-absent behaviour 'value' with no value")
        return Absent(rule["clause"], rule["behaviour"], rule["why"],
                      rule.get("value"))

    def resolve(self, ref, origin):
        if ref.startswith("#/$defs/"):
            # A local $ref resolves against the file it appears in, which is
            # the leading path segment of `origin`.
            pointer = ref[len("#/$defs/"):]
            fname = origin.split("#")[0].split(".")[0]
            doc = self.docs.get(f"{fname}.schema.json")
            if doc is None:
                raise Halt(f"{origin}: cannot locate the file a local $ref "
                           "belongs to")
        elif "#/$defs/" in ref:
            base, pointer = ref.split("#/$defs/", 1)
            fname = self.by_id.get(base)
            if fname is None:
                raise Halt(f"{origin}: $ref {ref!r} names an unknown $id. This "
                           "tool never fetches over the network.")
            doc = self.docs[fname]
        else:
            raise Halt(f"{origin}: $ref {ref!r} is not a $defs pointer")
        target = doc.get("$defs", {}).get(pointer)
        if target is None:
            raise Halt(f"{origin}: $ref {ref!r} does not resolve")
        name = target.get("x-acp-name")
        if not name:
            raise Halt(f"{origin}: $ref {ref!r} resolves to a type with no "
                       "x-acp-name")
        return name


# ------------------------------------------------------------------- emitting


def wrap(text, width=DOC_WIDTH):
    """Deterministic paragraph wrapping. No locale, no textwrap tuning."""
    lines = []
    for para in text.split("\n"):
        if not para.strip():
            lines.append("")
            continue
        cur = ""
        for word in para.split(" "):
            if cur and len(cur) + 1 + len(word) > width:
                lines.append(cur)
                cur = word
            else:
                cur = f"{cur} {word}" if cur else word
        if cur:
            lines.append(cur)
    while lines and not lines[-1]:
        lines.pop()
    return lines


def doc_lines(text, prefix):
    if not text:
        return []
    if "```" in text:
        raise Halt("a schema description contains a fenced code block, which "
                   "would become a Rust doctest. Reword it.")
    return [f"{prefix} {ln}".rstrip() for ln in wrap(text)]


def rustfmt_clean(lines):
    """Emit output rustfmt already agrees with, rather than shelling out to it.

    Only one rule is needed so far: rustfmt deletes a blank line immediately
    before a closing brace, and the emitters below leave one after the last
    accessor in an `impl` block.

    Formatting the output by RUNNING rustfmt would be the obvious alternative
    and is worse here. `--check` compares bytes, so the committed file would
    then depend on the rustfmt version of whoever last regenerated it, and a
    toolchain upgrade would read as drift on a machine where nothing changed.
    Emitting text that is already canonical keeps the check about the SCHEMAS.
    """
    out = []
    for line in lines:
        if line.strip() == "}" and out and not out[-1].strip():
            out.pop()
        out.append(line)
    return "\n".join(out).rstrip("\n") + "\n"


def rust_str(text):
    """A Rust string literal.

    Not `json.dumps`: that escapes non-ASCII as `\\uXXXX`, which is JSON and
    JavaScript syntax and a compile error in Rust, whose escape is `\\u{XXXX}`.
    Rust source is UTF-8, so the characters go through as themselves.
    """
    body = (text.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t"))
    return f'"{body}"'


def pascal_to_snake(name):
    out = []
    for i, ch in enumerate(name):
        if ch.isupper() and i:
            out.append("_")
        out.append(ch.lower())
    return "".join(out)


def snake_to_camel(name):
    head, *rest = name.split("_")
    return head + "".join(p.capitalize() for p in rest)


def variant_of(value):
    """A wire value as a type-name-cased variant: `pq-slh` -> `PqSlh`."""
    parts = [p for p in value.replace("-", "_").replace(".", "_").split("_") if p]
    return "".join(p if p.isupper() and len(p) <= 2 else p.capitalize()
                   for p in parts)


class RustEmitter:
    def __init__(self, parser):
        self.p = parser
        self.out = []

    def w(self, line=""):
        self.out.append(line)

    def rust_ty(self, ty, raw=False):
        if isinstance(ty, Ref):
            target = self.p.types[ty.name]
            if raw and isinstance(target, StructType):
                return f"Raw{ty.name}"
            if raw:
                # At the Raw layer every enum and every constrained scalar
                # degrades to String. That is the point: an unknown suite name
                # must PARSE and then be refused under CR-1, not fail as a
                # deserialisation error indistinguishable from a corrupt file.
                return "String"
            return ty.name
        if isinstance(ty, Prim):
            return {"string": "String", "u64": "u64", "i64": "i64",
                    "bool": "bool"}[ty.kind]
        if isinstance(ty, MapOf):
            return f"BTreeMap<String, {self.rust_ty(ty.value, raw)}>"
        if isinstance(ty, ListOf):
            return f"Vec<{self.rust_ty(ty.item, raw)}>"
        raise Halt(f"no Rust type for {ty!r}")

    def emit(self):
        self.header()
        self.support()
        for name in sorted(self.p.types):
            ty = self.p.types[name]
            if isinstance(ty, EnumType):
                self.enum(ty)
            elif isinstance(ty, NewtypeType):
                self.newtype(ty)
        for name in sorted(self.p.types):
            ty = self.p.types[name]
            if isinstance(ty, StructType):
                self.struct(ty)
        return rustfmt_clean(self.out)

    def header(self):
        self.w("// @generated by tools/codegen.sh from spec/schemas/bundle/ "
               "— DO NOT EDIT.")
        self.w("//")
        self.w("// Regenerate with `./tools/codegen.sh`. `./tools/codegen.sh "
               "--check` asserts")
        self.w("// this file still matches the schemas and runs from "
               "tools/selftest.sh.")
        self.w("//")
        self.w("// Editing this file by hand creates a second definition of an "
               "object the")
        self.w("// specification already defines, which is the encoding-split "
               "defect at the")
        self.w("// source level. The drift check exists to catch exactly that "
               "edit.")
        self.w("#![allow(rustdoc::broken_intra_doc_links)]")
        self.w()
        self.w("use std::collections::BTreeMap;")
        self.w()
        self.w("use serde::{Deserialize, Serialize};")
        self.w()

    def support(self):
        self.w("/// A lookup that missed, in a table whose absent case is a "
               "REFUSAL rather")
        self.w("/// than a default value.")
        self.w("///")
        self.w("/// Returned instead of `Option` so that the fail-safe outcome "
               "is the one a")
        self.w("/// caller has to handle. `Option::unwrap_or` is a single "
               "idiom away from")
        self.w("/// the permissive answer; a `Result` carrying the clause that "
               "governs the")
        self.w("/// refusal is not.")
        self.w("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
        self.w("pub struct AbsentFromSignedPolicy {")
        self.w("    /// The signed table that was consulted.")
        self.w("    pub table: &'static str,")
        self.w("    /// The clause that says an absent entry is a refusal.")
        self.w("    pub clause: &'static str,")
        self.w("    /// Why absence fails closed here, in the schema's own "
               "words.")
        self.w("    pub why: &'static str,")
        self.w("}")
        self.w()
        self.w("/// Why a lenient `Raw*` value could not be promoted to its "
               "strict form.")
        self.w("///")
        self.w("/// The two layers exist because a verifier and a service want "
               "different")
        self.w("/// things from one schema. A service wants the whole object or "
               "nothing. A")
        self.w("/// verifier wants to know WHICH field was missing, because "
               "its refusals are")
        self.w("/// distinguishable by design — an absent `quorum_k` is "
               "`QuorumInvalid` and")
        self.w("/// not `Malformed`, and an operator paged at 03:00 needs the "
               "difference.")
        self.w("/// Collapsing every absence into one parse error would lose "
               "that, and the")
        self.w("/// cross-language differential asserts the refusal NAME.")
        self.w("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
        self.w("pub struct SchemaDefect {")
        self.w("    pub type_name: &'static str,")
        self.w("    pub field: &'static str,")
        self.w("    pub kind: DefectKind,")
        self.w("}")
        self.w()
        self.w("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
        self.w("pub enum DefectKind {")
        self.w("    /// The schema requires this field and it is not present.")
        self.w("    Missing,")
        self.w("    /// A `const` field carries a value the schema does not "
               "allow. Refused")
        self.w("    /// rather than ignored: the field exists so a decoder can "
               "reject a")
        self.w("    /// document it does not fully understand.")
        self.w("    UnexpectedConst,")
        self.w("    /// An integer below the schema's `minimum`.")
        self.w("    BelowMinimum,")
        self.w("    /// Two items in a keyed array claim the same key. Refused "
               "rather than")
        self.w("    /// merged or last-wins: two entries for one key is an "
               "ambiguity, and")
        self.w("    /// picking one is a guess.")
        self.w("    DuplicateKey,")
        self.w("}")
        self.w()

    def enum(self, ty):
        self.out.extend(doc_lines(ty.doc or f"`{ty.name}`.", "///"))
        self.w(f"/// Generated from {ty.origin}.")
        derives = ["Debug", "Clone", "Copy", "PartialEq", "Eq"]
        if ty.ordered:
            derives += ["PartialOrd", "Ord"]
        self.w(f"#[derive({', '.join(derives)}, Serialize, Deserialize)]")
        if ty.ordered:
            self.w("// Ordered because the schema declares x-acp-ordered: the "
                   "variants are")
            self.w("// written low to high, so the derived Ord composes with "
                   "`max` the way")
            self.w("// §8.4 requires. Reordering the variants changes the "
                   "meaning of every")
            self.w("// comparison in the system.")
        else:
            self.w("// NOT ordered. The schema does not declare "
                   "x-acp-ordered, and a derived")
            self.w("// `Ord` on a set with no order is a comparison that "
                   "compiles and means")
            self.w("// nothing — for SuiteId it would make `declared >= floor` "
                   "compile, and")
            self.w("// that comparison is the CR-4 downgrade.")
        self.w(f"pub enum {ty.name} {{")
        for value in ty.values:
            self.w(f'    #[serde(rename = "{value}")]')
            self.w(f"    {variant_of(value)},")
        self.w("}")
        self.w()
        self.w(f"impl {ty.name} {{")
        self.w("    /// The wire spelling, which is what a hash covers.")
        self.w("    pub const fn as_wire(self) -> &'static str {")
        self.w("        match self {")
        for value in ty.values:
            self.w(f'            {ty.name}::{variant_of(value)} => "{value}",')
        self.w("        }")
        self.w("    }")
        self.w()
        self.w("    /// Parse a wire spelling. An unknown value is `None` and "
               "MUST be")
        self.w("    /// refused by the caller, never resolved to a known one.")
        self.w("    pub fn from_wire(s: &str) -> Option<Self> {")
        self.w("        match s {")
        for value in ty.values:
            self.w(f'            "{value}" => Some({ty.name}::'
                   f"{variant_of(value)}),")
        self.w("            _ => None,")
        self.w("        }")
        self.w("    }")
        self.w("}")
        self.w()

    def newtype(self, ty):
        self.out.extend(doc_lines(ty.doc or f"`{ty.name}`.", "///"))
        self.w(f"/// Generated from {ty.origin}.")
        if ty.pattern:
            self.w("///")
            self.w(f"/// The schema constrains this to `{ty.pattern}`. That "
                   "pattern is NOT")
            self.w("/// enforced here — see the module note on what codegen "
                   "does not validate.")
        self.w("#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, "
               "Serialize, Deserialize)]")
        self.w("#[serde(transparent)]")
        self.w(f"pub struct {ty.name}(pub String);")
        self.w()

    # ---- structs, in two projections

    def struct(self, ty):
        maps = [f for f in ty.fields if isinstance(f.ty, (MapOf, ListOf))
                and getattr(f.ty, "absent", None) is not None]
        self.out.extend(doc_lines(ty.doc or f"`{ty.name}`.", "///"))
        self.w(f"/// Generated from {ty.origin}.")
        self.w("#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]")
        if ty.closed:
            self.w("#[serde(deny_unknown_fields)]")
        self.w(f"pub struct {ty.name} {{")
        for f in ty.fields:
            if f.doc:
                self.out.extend(doc_lines(f.doc, "    ///"))
            if f in maps:
                self.w("    /// PRIVATE, deliberately. Reached through the "
                       "accessor below, which")
                self.w("    /// carries the fail-safe absent rule the schema "
                       "declares. A public")
                self.w("    /// map is a `.get()` away from an `Option` and an "
                       "`Option` is one")
                self.w("    /// `unwrap_or` away from the permissive default.")
                self.w(f"    {self.field_name(f)}: {self.rust_ty(f.ty)},")
            else:
                self.w(f"    pub {self.field_name(f)}: {self.rust_ty(f.ty)},")
        self.w("}")
        self.w()
        consts = [f for f in ty.fields if f.const is not None]
        if consts or maps:
            self.w(f"impl {ty.name} {{")
            for f in consts:
                self.w(f"    /// The only `{f.json_name}` this build "
                       "understands.")
                self.w(f"    pub const {f.json_name.upper()}: &'static str = "
                       f'"{f.const}";')
                self.w()
            for f in maps:
                self.accessor(ty, f)
            self.w("}")
            self.w()
        self.raw_struct(ty, maps)

    def field_name(self, f):
        # `if` and `type` are Rust keywords and appear as schema property
        # names. Renamed with a raw identifier rather than mangled, so the
        # generated name still reads as the wire name.
        return f"r#{f.json_name}" if f.json_name in RUST_KEYWORDS else f.json_name

    def accessor(self, ty, f):
        absent = f.ty.absent
        table = f.json_name
        if isinstance(f.ty, MapOf):
            value_ty = self.rust_ty(f.ty.value)
            key_doc = "key"
        else:
            value_ty = self.rust_ty(f.ty.item)
            key_doc = f.ty.keyed_by
        self.out.extend(doc_lines(
            f"Look up one entry in `{table}`.\n\n{absent.clause}: "
            f"{absent.why}", "    ///"))
        self.w("    ///")
        self.w("    /// Generated from the schema's `x-acp-absent` rule. It "
               "is not restated")
        self.w("    /// here, and editing it there changes this.")
        if absent.behaviour == "value":
            default = self.default_expr(f, absent)
            if isinstance(f.ty, MapOf):
                self.w(f"    pub fn get(&self, {key_doc}: &str) -> "
                       f"{value_ty} {{")
                # Two statements rather than one chain: it separates what the
                # table holds from what ABSENCE means, which is the whole
                # subject here. It also keeps the line under rustfmt's width
                # for any field name a schema can carry, so the emitted text
                # is canonical without shelling out to rustfmt.
                self.w(f"        let found = self.{self.field_name(f)}"
                       f".get({key_doc}).copied();")
                self.w(f"        found.unwrap_or({default})")
            else:
                raise Halt(f"{ty.name}.{f.json_name}: a keyed array with a "
                           "value default is not supported")
            self.w("    }")
        else:
            self.w(f"    pub fn get(&self, {key_doc}: &str) "
                   f"-> Result<&{value_ty}, AbsentFromSignedPolicy> {{")
            if isinstance(f.ty, MapOf):
                self.w(f"        self.{self.field_name(f)}.get({key_doc})"
                       ".ok_or(AbsentFromSignedPolicy {")
            else:
                self.w(f"        self.{self.field_name(f)}")
                self.w("            .iter()")
                self.w(f"            .find(|item| item.{f.ty.keyed_by} == "
                       f"{key_doc})")
                self.w("            .ok_or(AbsentFromSignedPolicy {")
            self.w(f'            table: "{table}",')
            self.w(f'            clause: "{absent.clause}",')
            self.w(f"            why: {rust_str(absent.why)},")
            self.w("        })")
            self.w("    }")
        self.w()
        self.w("    /// Every entry, for callers that enumerate rather than "
               "look up — an")
        self.w("    /// auditor listing signed policy, not a decision path.")
        if isinstance(f.ty, MapOf):
            self.w(f"    pub fn entries(&self) -> impl Iterator<Item = "
                   f"(&String, &{value_ty})> {{")
            self.w(f"        self.{self.field_name(f)}.iter()")
        else:
            self.w(f"    pub fn entries(&self) -> impl Iterator<Item = "
                   f"&{value_ty}> {{")
            self.w(f"        self.{self.field_name(f)}.iter()")
        self.w("    }")
        self.w()

    def default_expr(self, f, absent):
        value_ty = f.ty.value if isinstance(f.ty, MapOf) else f.ty.item
        if not isinstance(value_ty, Ref):
            raise Halt("x-acp-absent 'value' on a map whose values are not a "
                       "named type")
        target = self.p.types[value_ty.name]
        if not isinstance(target, EnumType):
            raise Halt(f"x-acp-absent 'value' on non-enum {value_ty.name}")
        if absent.value not in target.values:
            raise Halt(
                f"x-acp-absent value {absent.value!r} is not one of "
                f"{value_ty.name}'s values {target.values}. The fail-safe "
                "default must be expressible in the type it defaults.")
        return f"{value_ty.name}::{variant_of(absent.value)}"

    def raw_struct(self, ty, maps):
        self.w(f"/// The lenient projection of [`{ty.name}`].")
        self.w("///")
        self.w("/// Every field optional, every enum degraded to `String`. "
               "This is what a")
        self.w("/// VERIFIER parses, and the leniency is deliberate: reading "
               "five named")
        self.w("/// security fields fail-closed is field access, and a strict "
               "parse would")
        self.w("/// collapse every distinct refusal into one "
               "`Malformed`. It also means a")
        self.w("/// field no verifier reads cannot cause a refusal by being "
               "the wrong shape.")
        self.w("///")
        self.w("/// **Never make a decision on a `Raw*` value.** Promote it "
               "with `try_from`,")
        self.w("/// or read one named field and apply the check that governs "
               "it. The")
        self.w("/// fail-safe accessors live on the strict type only, so a "
               "`Raw*` cannot")
        self.w("/// answer a policy question at all.")
        self.w("#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]")
        self.w(f"pub struct Raw{ty.name} {{")
        for f in ty.fields:
            self.w(f"    pub {self.field_name(f)}: "
                   f"Option<{self.rust_ty(f.ty, raw=True)}>,")
        self.w("}")
        self.w()


RUST_KEYWORDS = {"if", "else", "type", "match", "move", "ref", "box", "fn",
                 "let", "loop", "impl", "mod", "use", "where", "while", "for",
                 "in", "as", "const", "static", "struct", "enum", "trait"}


class TsEmitter:
    def __init__(self, parser):
        self.p = parser
        self.out = []

    def w(self, line=""):
        self.out.append(line)

    def ts_ty(self, ty, raw=False):
        if isinstance(ty, Ref):
            target = self.p.types[ty.name]
            if raw and isinstance(target, StructType):
                return f"Raw{ty.name}"
            if raw:
                return "string"
            return ty.name
        if isinstance(ty, Prim):
            return {"string": "string", "u64": "number", "i64": "number",
                    "bool": "boolean"}[ty.kind]
        if isinstance(ty, MapOf):
            return f"Readonly<Record<string, {self.ts_ty(ty.value, raw)}>>"
        if isinstance(ty, ListOf):
            return f"readonly {self.ts_ty(ty.item, raw)}[]"
        raise Halt(f"no TypeScript type for {ty!r}")

    def emit(self):
        self.w("// @generated by tools/codegen.sh from spec/schemas/bundle/ "
               "— DO NOT EDIT.")
        self.w("//")
        self.w("// Regenerate with `./tools/codegen.sh`. `./tools/codegen.sh "
               "--check` asserts")
        self.w("// this file still matches the schemas and runs from "
               "tools/selftest.sh.")
        self.w("//")
        self.w("// DR-2: services/notifier and services/approval may both "
               "depend on this")
        self.w("// package and on nothing else in common. These are the wire "
               "format.")
        self.w("// Rendering is not — no shared template engine, formatter, "
               "sanitiser or")
        self.w("// component library. Without that carve-out the first shared "
               "formatDate()")
        self.w("// is technically compliant and voids the property.")
        self.w("//")
        self.w("// ONE ASYMMETRY WITH THE RUST OUTPUT, stated rather than "
               "papered over. In")
        self.w("// Rust the map behind a fail-safe lookup is a PRIVATE field, "
               "so the")
        self.w("// permissive answer is unreachable. A TypeScript interface "
               "has no private")
        self.w("// members, so `table.floors[key]` is still writable by a "
               "caller who wants")
        self.w("// it. What holds here is weaker: `noUncheckedIndexedAccess` "
               "is on, so that")
        self.w("// access is typed `T | undefined` and the caller must handle "
               "the absent")
        self.w("// case explicitly — they cannot reach the permissive value "
               "by accident,")
        self.w("// only on purpose. The lookup functions below are the "
               "supported path.")
        self.w()
        for name in sorted(self.p.types):
            ty = self.p.types[name]
            if isinstance(ty, EnumType):
                self.enum(ty)
            elif isinstance(ty, NewtypeType):
                self.newtype(ty)
        for name in sorted(self.p.types):
            ty = self.p.types[name]
            if isinstance(ty, StructType):
                self.struct(ty)
        return "\n".join(self.out).rstrip("\n") + "\n"

    def enum(self, ty):
        self.w("/**")
        for ln in doc_lines(ty.doc or f"`{ty.name}`.", " *"):
            self.w(ln)
        self.w(f" * Generated from {ty.origin}.")
        self.w(" */")
        values = " | ".join(f"'{v}'" for v in ty.values)
        self.w(f"export type {ty.name} = {values};")
        self.w()
        if ty.ordered:
            self.w("/**")
            self.w(f" * {ty.name} low to high, from the schema's declared "
                   "order.")
            self.w(" *")
            self.w(" * TypeScript has no derived ordering, so the ladder is a "
                   "value and the")
            self.w(" * comparison is a function. §8.4 composes with max, so "
                   "`max` is what")
            self.w(" * callers need and index arithmetic is what they must not "
                   "write.")
            self.w(" */")
            self.w(f"export const {pascal_to_snake(ty.name).upper()}_ORDER: "
                   f"readonly {ty.name}[] = [")
            for value in ty.values:
                self.w(f"  '{value}',")
            self.w("];")
            self.w()
            order = f"{pascal_to_snake(ty.name).upper()}_ORDER"
            self.w(f"export function max{ty.name}(a: {ty.name}, b: {ty.name})"
                   f": {ty.name} {{")
            self.w(f"  return {order}.indexOf(a) >= {order}.indexOf(b) "
                   "? a : b;")
            self.w("}")
            self.w()

    def newtype(self, ty):
        self.w("/**")
        for ln in doc_lines(ty.doc or f"`{ty.name}`.", " *"):
            self.w(ln)
        self.w(f" * Generated from {ty.origin}.")
        if ty.pattern:
            self.w(" *")
            self.w(f" * The schema constrains this to `{ty.pattern}`, which is "
                   "NOT enforced here.")
        self.w(" */")
        self.w(f"export type {ty.name} = string;")
        self.w()

    def struct(self, ty):
        maps = [f for f in ty.fields if isinstance(f.ty, (MapOf, ListOf))
                and getattr(f.ty, "absent", None) is not None]
        self.w("/**")
        for ln in doc_lines(ty.doc or f"`{ty.name}`.", " *"):
            self.w(ln)
        self.w(f" * Generated from {ty.origin}.")
        self.w(" */")
        self.w(f"export interface {ty.name} {{")
        for f in ty.fields:
            if f.doc:
                self.w("  /**")
                for ln in doc_lines(f.doc, "   *"):
                    self.w(ln)
                self.w("   */")
            self.w(f"  readonly {snake_to_camel(f.json_name)}: "
                   f"{self.ts_ty(f.ty)};")
        self.w("}")
        self.w()
        for f in maps:
            self.ts_accessor(ty, f)
        self.w("/**")
        self.w(f" * The lenient projection of {ty.name}: every field optional, "
               "every enum")
        self.w(" * degraded to `string`. What a verifier parses. Never make a "
               "decision on")
        self.w(" * one — the fail-safe lookups live on the strict type only.")
        self.w(" */")
        self.w(f"export interface Raw{ty.name} {{")
        for f in ty.fields:
            self.w(f"  readonly {snake_to_camel(f.json_name)}?: "
                   f"{self.ts_ty(f.ty, raw=True)};")
        self.w("}")
        self.w()

    def ts_accessor(self, ty, f):
        absent = f.ty.absent
        fn = f"{snake_to_camel(ty.name[0].lower() + ty.name[1:])}Lookup"
        if isinstance(f.ty, MapOf):
            value_ty = self.ts_ty(f.ty.value)
        else:
            value_ty = self.ts_ty(f.ty.item)
        self.w("/**")
        for ln in doc_lines(
                f"Look up one entry in {ty.name}.{f.json_name}.\n\n"
                f"{absent.clause}: {absent.why}", " *"):
            self.w(ln)
        self.w(" *")
        self.w(" * Generated from the schema's `x-acp-absent` rule. It is not "
               "restated here.")
        self.w(" */")
        field = snake_to_camel(f.json_name)
        if absent.behaviour == "value":
            self.w(f"export function {fn}(table: {ty.name}, key: string): "
                   f"{value_ty} {{")
            self.w(f"  return table.{field}[key] ?? "
                   f"'{absent.value}';")
            self.w("}")
        else:
            self.w(f"export type {ty.name}Lookup =")
            self.w(f"  | {{ readonly present: true; readonly value: "
                   f"{value_ty} }}")
            self.w("  | { readonly present: false; readonly clause: string; "
                   "readonly why: string };")
            self.w()
            self.w(f"export function {fn}(table: {ty.name}, key: string): "
                   f"{ty.name}Lookup {{")
            if isinstance(f.ty, MapOf):
                self.w(f"  const found = table.{field}[key];")
            else:
                self.w(f"  const found = table.{field}"
                       f".find((item) => item.{snake_to_camel(f.ty.keyed_by)}"
                       " === key);")
            self.w("  return found === undefined")
            self.w(f"    ? {{ present: false, clause: "
                   f"{json.dumps(absent.clause)}, why: "
                   f"{json.dumps(absent.why)} }}")
            self.w("    : { present: true, value: found };")
            self.w("}")
        self.w()


# ----------------------------------------------------------------------- main


def build(schema_dir):
    parser = Parser(load_schemas(schema_dir)).run()
    return {RUST_OUT: RustEmitter(parser).emit(),
            TS_OUT: TsEmitter(parser).emit()}


def main(argv):
    check = "--check" in argv
    schema_dir = SCHEMA_DIR
    if "--schemas" in argv:
        schema_dir = pathlib.Path(argv[argv.index("--schemas") + 1])

    try:
        generated = build(schema_dir)
    except Halt as e:
        # HALT, not a warning and not a default. Exit 2 so a caller can tell a
        # refusal to generate from a drift.
        print(f"HALT  {e}", file=sys.stderr)
        return 2

    if check:
        bad = 0
        for path, want in generated.items():
            rel = path.relative_to(REPO)
            if not path.exists():
                print(f"FAIL  {rel} does not exist")
                bad += 1
            elif path.read_text() != want:
                print(f"FAIL  {rel} has drifted from the schemas")
                bad += 1
        if bad:
            print(f"{bad} generated file(s) do not match spec/schemas/bundle/ "
                  "— run ./tools/codegen.sh")
            return 1
        print(f"generated types are current ({len(generated)} files)")
        return 0

    for path, text in generated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
