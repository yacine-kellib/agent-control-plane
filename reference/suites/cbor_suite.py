#!/usr/bin/env python3
"""
cbor_suite.py — Suite 5: canonical CBOR encoding (AT-8a), the eight cases.

§05 claimed this suite; the tests did not ship (finding F1 of the internal
replay). They now do. Target: acp_crypto.decode_canonical, which must REFUSE
any input that is not byte-identical to the canonical encoding of its value —
a permissive decoder silently normalises and reopens Z4.
"""
import sys
from acp_crypto import canon_cbor, decode_canonical, CanonError


def refuse(buf: bytes):
    try:
        decode_canonical(buf)
        return False, "accepted"
    except CanonError as e:
        return True, str(e)


def t1_canonical_roundtrip_accepted():
    """Positive path: the canonical encoding of a value is accepted and
    decodes to that value. (B without A is an encoder that refuses all.)"""
    v = {"b": 2, "a": [1, "x", b"\x00", True, None], "c": {"k": -5}}
    buf = canon_cbor(v)
    return decode_canonical(buf) == v, f"{len(buf)} bytes round-trip"


def t2_key_order():
    """Map keys not sorted by encoded bytes -> refuse."""
    # {"b":1, "a":2} in that order: a3? no -- a2 62 62 01 61 61 ... wrong order
    buf = bytes.fromhex("a2 62 61 62 01 61 61 02".replace(" ", ""))  # {"ab":1,"a":2}
    ok, why = refuse(buf)
    return ok, why


def t3_non_shortest_argument():
    """Integer 5 encoded with a one-byte argument (0x18 0x05) -> refuse."""
    return refuse(bytes([0x18, 0x05]))


def t4_indefinite_length():
    """Indefinite-length array 0x9f ... 0xff -> refuse."""
    return refuse(bytes([0x9F, 0x01, 0x02, 0xFF]))


def t5_trailing_bytes():
    """A valid item followed by trailing garbage -> refuse."""
    return refuse(canon_cbor(7) + b"\x00")


def t6_duplicate_keys():
    """Two identical keys in one map -> refuse."""
    # {"a":1, "a":2} : a2 61 61 01 61 61 02
    return refuse(bytes.fromhex("a2 61 61 01 61 61 02".replace(" ", "")))


def t7_floats_refused_both_ways():
    """WE-1: floats are excluded from signed structures — the encoder refuses
    to produce them and the decoder refuses to accept them."""
    try:
        canon_cbor({"x": 1.5})
        return False, "encoder accepted a float"
    except CanonError:
        pass
    # 0xFB + IEEE-754 double for 1.5 = the CBOR encoding a permissive decoder
    # would accept; AT-8a's decoder must refuse major-7 float simple values.
    ok, why = refuse(bytes([0xFB, 0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    return ok, f"encoder and decoder both refuse ({why})"


def t8_two_encodings_one_value():
    """The Z4 case: two byte strings decoding to the same value must not both
    be accepted — exactly one (the canonical one) passes."""
    v = {1: "a"}
    canonical = canon_cbor(v)                       # key 1 as 0x01
    variant = bytes.fromhex("a1 18 01 61 61".replace(" ", ""))  # key as 0x18 0x01
    a = True
    try:
        decode_canonical(canonical)
    except CanonError:
        a = False
    b, _ = refuse(variant)
    return a and b, "canonical accepted, non-canonical twin refused"


TESTS = [
    ("canonical round-trip accepted", t1_canonical_roundtrip_accepted),
    ("map keys out of canonical order", t2_key_order),
    ("non-shortest integer argument", t3_non_shortest_argument),
    ("indefinite length", t4_indefinite_length),
    ("trailing bytes", t5_trailing_bytes),
    ("duplicate map keys", t6_duplicate_keys),
    ("floats refused, encode and decode", t7_floats_refused_both_ways),
    ("two encodings, one value (Z4)", t8_two_encodings_one_value),
]


def main():
    print("=" * 74)
    print("SUITE 5 — CANONICAL CBOR (AT-8a): REJECT, NEVER NORMALISE")
    print("=" * 74)
    fails = 0
    for name, fn in TESTS:
        try:
            ok, detail = fn()
        except Exception as ex:
            ok, detail = False, f"unexpected {type(ex).__name__}: {ex}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<40} {detail}")
        fails += not ok
    print("=" * 74)
    print(f"RESULT: {len(TESTS)-fails}/{len(TESTS)}"
          f"{' — AT-8a HOLDS' if not fails else ' — REVIEW REQUIRED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
