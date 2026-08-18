"""
The policy bundle, in Python: the canonical walk, the tree hash, and
verify-on-read.

WHY THIS EXISTS ALONGSIDE `crates/acp-bundle`. `reference/` is permanent and is
the differential partner for Rust. The first divergence between the two on a
shared input is a SPECIFICATION AMBIGUITY rather than a bug to patch around --
that is how Z1 was found, and it is the mechanism, not a nice-to-have. Two
implementations that never meet on the same input are two codebases; two that
do are evidence.

Read that with its limit, which the spec now states in §15: a second reading
written by consulting the first inherits the first's errors. Agreement is
evidence about CONSISTENCY and never about correctness. Both of PB-8's halves
below were settled by reasoning about the attack, not by copying Rust, and the
places where the two implementations were made to agree by construction are
named as such.

NOTHING HERE IS FORKED. `canon_cbor` and the hybrid primitives are imported
from `acp_crypto`; the suite table is imported from `acp_executor`. Those
modules carry mutation-test markers that `mutate_executor.py`, `ack_suite.py
--mutate` and `audit_suite.py --mutate` locate by reading source text, and a
copied-and-edited copy would silently void the repository's own evidence.

Run `reference/suites/bundle_suite.py` for the behaviour, and
`tools/check-bundle-differential.py` for the cross-language half.
"""
import hashlib
import json
import os

from acp_crypto import canon_cbor, verify_prim, HybridPub
from acp_executor import SUITES

# ------------------------------------------------------------------ constants

SCHEMA_VERSION = "1"

# Extensions a bundle member may have. An ALLOWLIST, mirroring
# tools/sign-release.sh, and for the reason that script records: its
# halt-on-unknown assertion surfaced a file the previous allowlist would have
# skipped while the manifest still looked complete. A skipped file in a signed
# tree is an unsigned file inside a signed bundle.
BUNDLE_EXTS = ("json", "md", "txt", "cddl")

# The detached signature, EXCLUDED from the tree it covers (PB-8): a signature
# cannot cover itself, and as a member its digest would have to be known before
# the file existed. Excluded by name AT THE ROOT only, so `attesters/SIGNATURE`
# does not inherit the exclusion and become a hole to park uncovered content in.
SIGNATURE_FILE = "SIGNATURE"


class WalkError(Exception):
    """A bundle directory that cannot be turned into a tree."""

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind, self.detail = kind, detail


# ---------------------------------------------------------------------- tree

def _member_path_ok(path: str) -> bool:
    """
    Reject anything that is not a plain relative path.

    Checked on COMPONENTS rather than on the raw string, so `a/../b`, `..` and
    `a/..` are caught by one rule instead of three string patterns that each
    miss a case. A traversal in an index is a file-read primitive handed to
    whoever wrote the index.
    """
    if not path or path.startswith("/") or "\\" in path:
        return False
    return all(c and c not in (".", "..") for c in path.split("/"))


def tree_bytes(suite: str, members: list[tuple[str, bytes]]) -> bytes:
    """
    The canonical encoding of the tree: `[schema_version, suite, [[path,
    digest], ...]]`, bytewise-sorted by path.

    THE HEADER IS INSIDE THE HASH, and that is a correction rather than an
    obvious choice. Hashing `members` alone leaves `suite` -- the field naming
    which primitives a verifier must require -- outside the signature it is part
    of. An attacker who can rewrite the index relabels a
    `hybrid-ed25519-mldsa65` bundle as `ed25519`, the verifier obligingly checks
    one primitive, and the post-quantum leg is gone without a byte of the member
    list changing. That is CR-3 downgrade reintroduced by the code written to
    prevent it. `schema_version` goes in for the same reason one version out.

    Encoded through `acp_crypto.canon_cbor`, never a second canonicaliser: two
    encodings of one object is the encoding-split defect at source level, and
    Suite 5's eight cases exist because a permissive decoder silently
    normalises.
    """
    if not members:
        # An empty tree hashes to a fixed value any signer could produce, so
        # accepting it would make "signed empty bundle" a valid input.
        raise WalkError("Empty")
    paths = [p for p, _ in members]
    if len(set(paths)) != len(paths):
        # Refused rather than de-duplicated: two entries carry different
        # digests and picking one is a guess.
        raise WalkError("DuplicatePath")
    for p in paths:
        if not _member_path_ok(p):
            raise WalkError("UnsafePath", p)

    ordered = sorted(members, key=lambda m: m[0].encode())
    return canon_cbor([SCHEMA_VERSION, suite,
                       [[p, hashlib.sha256(b).digest()] for p, b in ordered]])


def tree_hash(suite: str, members: list[tuple[str, bytes]]) -> str:
    """SHA-256 over the canonical encoding. This is what gets signed."""
    return "sha256:" + hashlib.sha256(tree_bytes(suite, members)).hexdigest()


def walk_bundle(root: str) -> list[tuple[str, bytes]]:
    """
    Turn a directory into a member list.

    This is where an attacker's influence lands -- it is decided by what is on
    disk rather than by what a caller passed -- so all three refusals here are
    refusals rather than accommodations.
    """
    members: list[tuple[str, bytes]] = []

    def visit(directory: str) -> None:
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            # islink BEFORE isdir: isdir follows the link and would report the
            # TARGET's type, so a symlink to a directory would be walked as one
            # and this check would never fire.
            if os.path.islink(full):
                # Following makes the tree hash depend on state outside the
                # bundle, so two hosts holding identical bundles disagree -- or
                # one reads a file it was never given. Skipping hides content
                # the author believes is covered. Both are worse than refusing.
                raise WalkError("Symlink", os.path.relpath(full, root))
            if os.path.isdir(full):
                visit(full)
                continue

            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if rel == SIGNATURE_FILE:
                continue
            ext = name.rsplit(".", 1)[-1] if "." in name else ""
            if ext not in BUNDLE_EXTS:
                raise WalkError("UnrecognisedFileType", rel)
            with open(full, "rb") as fh:
                members.append((rel, fh.read()))

    visit(root)
    return members


# ----------------------------------------------------------------- timestamps

class Timestamp:
    """
    An RFC 3339 UTC instant, to one second.

    STRICT, not permissive: exactly `YYYY-MM-DDTHH:MM:SSZ`. Offsets, fractional
    seconds and lowercase `z` are refused rather than normalised, because two
    spellings of one instant is the encoding split deciding when a bundle stops
    being valid.

    The day is checked against the ACTUAL length of the month. A range check of
    1..31 lets `2026-02-31` through, and the day arithmetic then rolls it
    forward to `2026-03-03` -- three days of validity nobody granted. That was a
    live defect in the Rust implementation, found and fixed before this file
    existed; it is written down here because the same range check is the
    obvious thing to write in either language.

    No leap second: `datetime` refuses `23:59:60`, so accepting it would be a
    divergence between the two implementations by construction.
    """

    __slots__ = ("unix",)

    def __init__(self, unix: int):
        self.unix = unix

    @staticmethod
    def parse(s: str) -> "Timestamp | None":
        if len(s) != 20 or s[4] != "-" or s[7] != "-" or s[10] != "T" \
                or s[13] != ":" or s[16] != ":" or s[19] != "Z":
            return None
        parts = (s[0:4], s[5:7], s[8:10], s[11:13], s[14:16], s[17:19])
        if not all(p.isdigit() and p.isascii() for p in parts):
            return None
        y, mo, d, h, mi, sec = (int(p) for p in parts)
        if not 1 <= mo <= 12 or not 1 <= d <= _days_in_month(y, mo):
            return None
        if h > 23 or mi > 59 or sec > 59:
            return None
        return Timestamp(_days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec)


def _days_in_month(y: int, m: int) -> int:
    # The century rule is the part that gets written wrong: 2000 is a leap year
    # (divisible by 400) and 2100 is not (divisible by 100, not by 400).
    # "Divisible by four" passes every casual check for seventy-five years.
    if m in (1, 3, 5, 7, 8, 10, 12):
        return 31
    if m in (4, 6, 9, 11):
        return 30
    if m == 2:
        return 29 if (y % 4 == 0 and y % 100 != 0) or y % 400 == 0 else 28
    return 0


def _days_from_civil(y: int, m: int, d: int) -> int:
    """Howard Hinnant's algorithm, matching `verify.rs`'s."""
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    mp = (m + 9) % 12
    doy = (153 * mp + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


# ------------------------------------------------------------------- verifier

class Refused(Exception):
    """
    A refusal, carrying the NAME the Rust implementation uses.

    Names rather than a single `Invalid`, because ACP-39's acceptance is that
    the two implementations agree on WHICH refusal fires, and because an
    operator paged at 03:00 needs to know whether the bundle is forged, stale,
    or simply older than the one already running.
    """

    def __init__(self, name: str):
        super().__init__(name)
        self.name = name


def suite_ok(declared: str, floor: str) -> bool:
    """
    CR-4 by CONTAINMENT, not by rank.

    The floor is satisfied iff every primitive it names is present. Extra
    primitives are fine; a missing one never is, whatever is offered in its
    place. A rank table made `hybrid` outrank `slhdsa128s` while carrying no
    SLH-DSA at all.
    """
    return set(SUITES[floor]).issubset(set(SUITES[declared]))


class BundleHost:
    """
    Holds EXACTLY ONE active bundle (PB-3) and a durable epoch high-water mark
    (PB-5, CL-4).

    Verification happens on EVERY READ, not at load. A bundle verified once and
    trusted afterwards protects the bytes as they were at load, not the bytes
    being returned now -- and the store behind it is exactly what a signature is
    for.
    """

    def __init__(self, signing_key: HybridPub, suite_floor: str,
                 grace_seconds: int = 0, high_water: int | None = None):
        # The signing key and the floor are CONFIGURED, never read from the
        # bundle. A bundle vouching for its own key is a self-signed assertion
        # wearing a registry's clothes, and a floor a bundle can lower is not a
        # floor (RES-8).
        self.signing_key = signing_key
        self.suite_floor = suite_floor
        self.grace_seconds = grace_seconds
        self.high_water = high_water
        self._active: tuple[list[tuple[str, bytes]], str, dict, int] | None = None

    # -- internals ---------------------------------------------------------

    def _check_signature(self, members, suite, signature) -> None:
        if suite not in SUITES:
            raise Refused("Malformed")
        # CR-4 first: a suite below the floor is refused even if its signature
        # is impeccable. The floor rules out primitives, not forgeries.
        if not suite_ok(suite, self.suite_floor):
            raise Refused("SuiteBelowFloor")

        try:
            digest = bytes.fromhex(tree_hash(suite, members).removeprefix("sha256:"))
        except WalkError:
            raise Refused("Malformed") from None

        # CONJUNCTIVE over the DECLARED suite (CR-3): the parts present must be
        # exactly those the suite requires, and every one must verify. An
        # `any`-shaped check here is the downgrade the hybrid suite exists to
        # prevent, and "exactly" is what stops one leg presented twice from
        # standing in for a leg not presented at all.
        required = set(SUITES[suite])
        if set(signature.keys()) != required:
            raise Refused("SignatureInvalid")
        for prim in sorted(required):
            if not verify_prim(self.signing_key, digest, signature[prim], prim):
                raise Refused("SignatureInvalid")

    @staticmethod
    def _member(members, path):
        for p, b in members:
            if p == path:
                return b
        return None

    @classmethod
    def _manifest(cls, members) -> dict:
        raw = cls._member(members, "manifest.json")
        if raw is None:
            raise Refused("Malformed")
        try:
            return json.loads(raw)
        except ValueError:
            raise Refused("Malformed") from None

    @staticmethod
    def _expiry(manifest) -> Timestamp:
        raw = manifest.get("expires_at")
        if not isinstance(raw, str):
            raise Refused("Malformed")
        ts = Timestamp.parse(raw)
        if ts is None:
            raise Refused("Malformed")
        return ts

    def _serving(self, expiry: Timestamp, now: Timestamp) -> str:
        if now.unix <= expiry.unix:
            return "Normal"
        if now.unix <= expiry.unix + self.grace_seconds:
            # PB-1's window: served, but every Decision capped at ATTEST. A
            # hard stop turns a policy-refresh failure into an outage; a silent
            # full-strength extension turns it into nothing.
            return "CappedAtAttest"
        raise Refused("Expired")

    @classmethod
    def _check_registry(cls, members) -> None:
        raw = cls._member(members, "attesters/registry.json")
        if raw is None:
            raise Refused("Malformed")
        try:
            registry = json.loads(raw)
        except ValueError:
            raise Refused("Malformed") from None

        # PB-6. Absent is refused, never defaulted: a default threshold is a
        # threshold nobody chose, and the permissive one (k=1) collapses
        # INV-1-HIGH to single compromise.
        k = registry.get("quorum_k")
        if not isinstance(k, int) or isinstance(k, bool) or k < 1:
            raise Refused("QuorumInvalid")

        attesters = registry.get("attesters")
        if not isinstance(attesters, dict):
            raise Refused("Malformed")

        # PB-7, compared PER LEG across identities -- never over the whole
        # entry.
        #
        # Comparing whole entries is what this did until ACP-53, and it caught
        # only BYTE-IDENTICAL ones. `role` is part of the entry, so a single
        # key holder enrolled twice --
        #
        #     "alice": {"role": "approver",  "classical": K, "pq": K}
        #     "bob":   {"role": "confirmer", "classical": K, "pq": K}
        #
        # -- was accepted, and satisfied quorum_k = 2 alone. That pairing is
        # exactly what DR-9 demands for an irreversible action at floor-HIGH,
        # so the registry handed over the case the threshold exists to prevent.
        # A role is not a verification key and must never distinguish two
        # identities.
        #
        # EITHER leg colliding is a collision, not both: PB-7 says two
        # identities differing in their classical key but SHARING a
        # post-quantum key are not distinct. Requiring the pair to match is
        # CR-3's conjunctive guarantee undone at the registry instead of at
        # the verifier.
        #
        # Not expressible in JSON Schema -- `uniqueItems` is for arrays and
        # there is no keyword for uniqueness across a map's values -- so it
        # lives in the loader, and the loader is what has to be right.
        for leg in ("classical", "pq"):
            seen = []
            for entry in attesters.values():
                # A key that is absent cannot be shown distinct from anything,
                # and an entry that is not an object has no keys at all.
                # Refusing is the only fail-safe reading of either.
                if not isinstance(entry, dict) or leg not in entry:
                    raise Refused("Malformed")
                if entry[leg] in seen:
                    raise Refused("RegistryKeysNotDistinct")
                seen.append(entry[leg])

    @staticmethod
    def _check_two_person_integrity(manifest) -> None:
        # PB-2, compared on `id`. Never on `display_name`: two people can share
        # one, and two-person integrity compared on a mutable label is
        # one-person integrity with extra steps.
        ids = []
        for who in ("author", "reviewer"):
            party = manifest.get(who)
            if not isinstance(party, dict) or not isinstance(party.get("id"), str):
                raise Refused("Malformed")
            ids.append(party["id"])
        if ids[0] == ids[1]:
            raise Refused("AuthorIsReviewer")

    # -- API ---------------------------------------------------------------

    def activate(self, members, suite, signature, now: Timestamp) -> None:
        """
        ATOMIC (PB-3): either every check passes and this becomes the only
        active bundle, or nothing changes and whatever was serving keeps
        serving. Written as validate-fully-then-assign for that reason --
        mutating first and rolling back on error is the same logic with a window
        in which a rejected bundle is live.
        """
        # SIGNATURE FIRST. Everything after this reads verified bytes. A
        # verifier that parses `expires_at` before checking the signature is
        # asking an attacker when the attacker's bundle expires.
        self._check_signature(members, suite, signature)

        manifest = self._manifest(members)
        epoch = manifest.get("bundle_epoch")
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            raise Refused("Malformed")
        self._check_two_person_integrity(manifest)
        self._check_registry(members)

        # PB-5, STRICTLY greater. Equal is refused: a bundle whose content
        # changed under an unchanged epoch is exactly what PB-5 forbids, and
        # re-serving the current epoch is how a rollback is dressed as a no-op.
        if self.high_water is not None and epoch <= self.high_water:
            raise Refused("EpochRollback")

        # Refuse activating something already dead on arrival. Serve-time
        # freshness is rechecked on every read, so this is not the only check.
        self._serving(self._expiry(manifest), now)

        self.high_water = epoch
        self._active = (members, suite, signature, epoch)

    def read(self, path: str, now: Timestamp) -> tuple[bytes, str]:
        """Read one member, re-verifying the whole bundle first."""
        if self._active is None:
            raise Refused("NoActiveBundle")
        members, suite, signature, _ = self._active

        self._check_signature(members, suite, signature)
        serving = self._serving(self._expiry(self._manifest(members)), now)

        value = self._member(members, path)
        if value is None:
            raise Refused("Malformed")
        return value, serving

    @property
    def active_epoch(self) -> int | None:
        """
        The epoch currently serving, which is NOT the same value as
        `high_water`. The mark is durable and survives a restart with no active
        bundle; that window is the cheapest moment to serve a superseded bundle,
        so a host deriving its mark from what is serving has no mark at all.
        """
        return self._active[3] if self._active else None
