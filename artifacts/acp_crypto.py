#!/usr/bin/env python3
"""
acp_crypto.py — real cryptography and canonical encoding for ACP v1.3.8.

Closes two CRYPTO-SWAP / encoding gaps that the reference Executor previously
modelled:

  1. HYBRID SIGNATURES (CR-1..CR-3) with real primitives:
       classical -> Ed25519 (RFC 8032, via `cryptography`)
       pq        -> ML-DSA-65 (FIPS 204, via `dilithium-py`)
     Composition remains conjunctive; only the primitives changed.

  2. CANONICAL CBOR (AT-8a) per RFC 8949 §4.2.1 deterministic encoding, with a
     VALIDATING decoder. AT-8a requires that a non-canonical encoding be
     REJECTED rather than re-serialised and accepted; a permissive decoder
     silently normalises and reopens Z4. The decoder here therefore re-encodes
     what it parsed and refuses any input that is not byte-identical.

MEASUREMENT NOTE. Sizes and timings are reported by `bench()` rather than
asserted from memory: ML-DSA-65 signatures are ~3.3 kB against Ed25519's 64 B,
which is the fact §9.7's performance note requires deployments to re-measure.
"""
from __future__ import annotations
import hashlib, io, time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature
from dilithium_py.ml_dsa import ML_DSA_65


class CanonError(Exception):
    """Encoding is not the canonical one. AT-8a: reject, never normalise."""


# =============================================================== canonical CBOR
def _enc_head(major: int, val: int, out: io.BytesIO):
    """RFC 8949 §4.2.1: the argument MUST use the shortest form that holds it."""
    if val < 24:
        out.write(bytes([(major << 5) | val]))
    elif val < 0x100:
        out.write(bytes([(major << 5) | 24, val]))
    elif val < 0x10000:
        out.write(bytes([(major << 5) | 25]) + val.to_bytes(2, "big"))
    elif val < 0x100000000:
        out.write(bytes([(major << 5) | 26]) + val.to_bytes(4, "big"))
    elif val < 0x10000000000000000:
        out.write(bytes([(major << 5) | 27]) + val.to_bytes(8, "big"))
    else:
        raise CanonError("integer exceeds 64-bit CBOR argument")


def _enc(obj: Any, out: io.BytesIO):
    if obj is True:
        out.write(b"\xf5"); return
    if obj is False:
        out.write(b"\xf4"); return
    if obj is None:
        out.write(b"\xf6"); return
    if isinstance(obj, float):
        # WE-1/AT-8a: floats have multiple representations of one value and no
        # deterministic ordering story. Excluded from signed structures.
        raise CanonError("float in a canonical structure")
    if isinstance(obj, int):
        if obj >= 0:
            _enc_head(0, obj, out)
        else:
            _enc_head(1, -obj - 1, out)
        return
    if isinstance(obj, bytes):
        _enc_head(2, len(obj), out); out.write(obj); return
    if isinstance(obj, str):
        b = obj.encode("utf-8"); _enc_head(3, len(b), out); out.write(b); return
    if isinstance(obj, (list, tuple)):
        _enc_head(4, len(obj), out)
        for x in obj:
            _enc(x, out)
        return
    if isinstance(obj, dict):
        # RFC 8949 §4.2.1: map keys sorted by their ENCODED bytes, bytewise
        # lexicographic. Sorting by the Python value would differ for e.g.
        # integer vs string keys and for non-ASCII.
        items = []
        for k, v in obj.items():
            kb = io.BytesIO(); _enc(k, kb); items.append((kb.getvalue(), v))
        items.sort(key=lambda kv: kv[0])
        if len({k for k, _ in items}) != len(items):
            raise CanonError("duplicate map key")
        _enc_head(5, len(items), out)
        for kb, v in items:
            out.write(kb); _enc(v, out)
        return
    raise CanonError(f"type {type(obj).__name__} not encodable")


def canon_cbor(obj: Any) -> bytes:
    out = io.BytesIO(); _enc(obj, out); return out.getvalue()


def _dec(buf: bytes, i: int):
    if i >= len(buf):
        raise CanonError("truncated")
    ib = buf[i]; major, ai = ib >> 5, ib & 0x1F; i += 1
    if ai < 24:
        val = ai
    elif ai == 24:
        val = buf[i]; i += 1
        if major not in (7,) and val < 24:
            raise CanonError("non-shortest argument")
    elif ai == 25:
        val = int.from_bytes(buf[i:i+2], "big"); i += 2
        if val < 0x100: raise CanonError("non-shortest argument")
    elif ai == 26:
        val = int.from_bytes(buf[i:i+4], "big"); i += 4
        if val < 0x10000: raise CanonError("non-shortest argument")
    elif ai == 27:
        val = int.from_bytes(buf[i:i+8], "big"); i += 8
        if val < 0x100000000: raise CanonError("non-shortest argument")
    elif ai == 31:
        raise CanonError("indefinite length forbidden in canonical CBOR")
    else:
        raise CanonError(f"reserved additional information {ai}")

    if major == 0: return val, i
    if major == 1: return -val - 1, i
    if major == 2: return buf[i:i+val], i + val
    if major == 3: return buf[i:i+val].decode("utf-8"), i + val
    if major == 4:
        out = []
        for _ in range(val):
            x, i = _dec(buf, i); out.append(x)
        return out, i
    if major == 5:
        out, prev = {}, None
        for _ in range(val):
            kstart = i
            k, i = _dec(buf, i)
            kb = buf[kstart:i]
            if prev is not None and kb <= prev:
                raise CanonError("map keys not in canonical order")
            prev = kb
            v, i = _dec(buf, i)
            out[k] = v
        return out, i
    if major == 7:
        if val == 20: return False, i
        if val == 21: return True, i
        if val == 22: return None, i
        raise CanonError("float or unsupported simple value")
    raise CanonError("unreachable")


def decode_canonical(buf: bytes) -> Any:
    """
    AT-8a: parse AND verify canonicity. Any input that is not byte-identical to
    the canonical encoding of what it decodes to is REFUSED, never normalised.
    """
    obj, i = _dec(buf, 0)
    if i != len(buf):
        raise CanonError("trailing bytes")
    if canon_cbor(obj) != buf:
        raise CanonError("input is not the canonical encoding of its value")
    return obj


def h_cbor(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canon_cbor(obj)).hexdigest()


# ============================================================ hybrid signatures
class HybridKey:
    """One identity, one key per primitive. Private halves stay together."""
    def __init__(self, seed: bytes):
        self.ed_sk = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(seed + b"ed").digest())
        self.ed_pk = self.ed_sk.public_key()
        self.ml_pk, self.ml_sk = ML_DSA_65.keygen()

    def public(self) -> "HybridPub":
        return HybridPub(self.ed_pk, self.ml_pk)


class HybridPub:
    def __init__(self, ed_pk: Ed25519PublicKey, ml_pk: bytes):
        self.ed_pk, self.ml_pk = ed_pk, ml_pk


PRIMS = {"classical", "pq"}


def sign_hybrid(key: HybridKey, msg: bytes, alg: str) -> dict:
    """CR-2: one signature value per primitive in the suite."""
    sig = {}
    if alg in ("ed25519", "hybrid-ed25519-mldsa65"):
        sig["classical"] = key.ed_sk.sign(msg)
    if alg in ("mldsa65", "hybrid-ed25519-mldsa65"):
        sig["pq"] = ML_DSA_65.sign(key.ml_sk, msg)
    if not sig:
        raise CanonError(f"unknown suite {alg}")
    return sig


def verify_hybrid(pub: HybridPub, msg: bytes, sig: Any, alg: str) -> bool:
    """
    CR-3: conjunctive. Every primitive in the suite must verify, and the set of
    supplied primitives must match the suite exactly.
    """
    expected = set()
    if alg in ("ed25519", "hybrid-ed25519-mldsa65"): expected.add("classical")
    if alg in ("mldsa65", "hybrid-ed25519-mldsa65"): expected.add("pq")
    if not expected or not isinstance(sig, dict) or set(sig) != expected:
        return False
    if "classical" in expected:
        try:
            pub.ed_pk.verify(sig["classical"], msg)
        except (InvalidSignature, Exception):
            return False
    if "pq" in expected:
        try:
            if not ML_DSA_65.verify(pub.ml_pk, msg, sig["pq"]):
                return False
        except Exception:
            return False
    return True


# ==================================================================== benchmark
SIGS_PER_HIGH_RECEIPT = 4   # 1 receipt signature + 3 attestations (quorum k=3)


def bench(n: int = 200) -> dict:
    """§9.7 requires deployments to MEASURE against EO-2, not assume."""
    k = HybridKey(b"bench"); pub = k.public()
    msg = canon_cbor({"proposal_hash": "sha256:" + "ab" * 32, "epoch": 47,
                      "targets": ["prod-db"], "action": "allow", "port": 22})
    out = {"payload_bytes": len(msg)}
    for alg in ("ed25519", "hybrid-ed25519-mldsa65"):
        t0 = time.perf_counter()
        for _ in range(n):
            s = sign_hybrid(k, msg, alg)
        t1 = time.perf_counter()
        for _ in range(n):
            verify_hybrid(pub, msg, s, alg)
        t2 = time.perf_counter()
        # true p99 over per-verification samples, not a mean
        samples = []
        for _ in range(n):
            a = time.perf_counter(); verify_hybrid(pub, msg, s, alg)
            samples.append((time.perf_counter() - a) * 1000)
        samples.sort()
        p99 = samples[min(len(samples) - 1, int(0.99 * len(samples)))]
        per_sig = sum(len(v) for v in s.values())
        out[alg] = {
            "sig_bytes": per_sig,
            "receipt_bytes": per_sig * SIGS_PER_HIGH_RECEIPT,
            "sign_ms": (t1 - t0) / n * 1000,
            "verify_ms": (t2 - t1) / n * 1000,
            "verify_p99_ms": p99,
            "receipt_verify_p99_ms": p99 * SIGS_PER_HIGH_RECEIPT,
        }
    return out


if __name__ == "__main__":
    import json
    r = bench()
    print(f"canonical CBOR payload: {r.pop('payload_bytes')} bytes\n")
    for alg, m in r.items():
        print(f"{alg:26s} sig={m['sig_bytes']:>5} B  "
              f"sign={m['sign_ms']:.3f} ms  verify={m['verify_ms']:.3f} ms  "
              f"p99={m['verify_p99_ms']:.3f} ms")
    print(f"\nPer floor-HIGH receipt ({SIGS_PER_HIGH_RECEIPT} signatures: "
          f"1 receipt + 3 attestations, quorum k=3):")
    for alg, m in r.items():
        print(f"  {alg:26s} {m['receipt_bytes']:>6} B on the wire, "
              f"verify p99 {m['receipt_verify_p99_ms']:.1f} ms")
    c, h = r["ed25519"], r["hybrid-ed25519-mldsa65"]
    print(f"\n  size factor  : {h['receipt_bytes']/c['receipt_bytes']:.1f}x "
          f"({c['receipt_bytes']} B -> {h['receipt_bytes']} B)  [algorithm-bound]")
    print(f"  latency factor: {h['receipt_verify_p99_ms']/c['receipt_verify_p99_ms']:.0f}x "
          f"[implementation-bound: pure-Python ML-DSA]")
