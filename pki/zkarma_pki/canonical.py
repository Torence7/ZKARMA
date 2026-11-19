"""Canonical encoding for everything that gets signed.

Every party (client, agent, website) MUST serialize signed objects with
`canonical_encode`, otherwise the same logical object produces different bytes
and signatures stop verifying.

This implements the subset of RFC 8785 (JSON Canonicalization Scheme, "JCS")
that ZKARMA needs:
  * object keys sorted by UTF-16 code units
  * no insignificant whitespace
  * UTF-8 output, minimal string escaping
  * allowed value types: dict, list, str, int, bool, None

Floats are rejected on purpose: JCS float formatting is subtle and easy to get
wrong across languages. Encode amounts as integer cents, times as integer
Unix seconds, etc.  Teammates in other languages can use any RFC 8785 library
and will get identical bytes for these value types.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalEncodingError(TypeError):
    pass


def _check(obj: Any, path: str = "$") -> None:
    if obj is None or isinstance(obj, (bool, str)):
        return
    if isinstance(obj, int):
        # JCS uses IEEE-754 doubles; keep ints in the exactly-representable range.
        if abs(obj) > 2**53 - 1:
            raise CanonicalEncodingError(f"{path}: integer {obj} outside safe range")
        return
    if isinstance(obj, float):
        raise CanonicalEncodingError(f"{path}: floats are not allowed (use ints)")
    if isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check(v, f"{path}[{i}]")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalEncodingError(f"{path}: object keys must be strings")
            _check(v, f"{path}.{k}")
        return
    raise CanonicalEncodingError(f"{path}: unsupported type {type(obj).__name__}")


def _sort(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sort(obj[k]) for k in sorted(obj, key=lambda s: s.encode("utf-16-be"))}
    if isinstance(obj, (list, tuple)):
        return [_sort(v) for v in obj]
    return obj


def canonical_encode(obj: Any) -> bytes:
    """Return the canonical UTF-8 bytes of `obj`."""
    _check(obj)
    # sort_keys=False because _sort already ordered keys by UTF-16 code units
    return json.dumps(_sort(obj), ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    """SHA-256 hex digest of the canonical encoding (handy as an object ID)."""
    return hashlib.sha256(canonical_encode(obj)).hexdigest()
