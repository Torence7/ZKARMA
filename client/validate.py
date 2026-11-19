"""Checks the client runs on what the agent hands it, before the user sees it.

The agent is untrusted, so everything here comes from it. A challenge must
look exactly like what the website issues; anything off is refused before the
user is asked, so the user only ever approves what the proof will be bound to.
"""
from __future__ import annotations

import calendar
import re
import time

from config import (DEV, MAX_CHALLENGE_TTL_S, MAX_CLOCK_SKEW_S, STATUS_MAX_AGE_S,
                    SUPPORTED_CLAIMS, spec)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ISO_Z = "%Y-%m-%dT%H:%M:%SZ"

# Fields each action must carry, with their types. Shown to the user in full.
ACTION_FIELDS = {
    "enter": {"duration_s": int},
    "checkout": {"item_id": str, "item_name": str, "quantity": int,
                 "amount_cents": int, "currency": str},
}


class Refused(Exception):
    """The request is refused before the user is asked. .reason is a short code."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _is_int(v) -> bool:
    return type(v) is int  # JSON true would pass isinstance(v, int)


def check_signature(message: dict) -> bool:
    """True if signed, False if unsigned and dev mode allows that. Raises otherwise.
    STUB: spec.stub_verify until the PKI gives us the website's key."""
    sig = message.get("signature")
    if sig is None:
        if DEV:
            return False
        raise Refused("unsigned")
    if not spec.stub_verify(message, sig):
        raise Refused("bad_website_signature")
    return True


def validate_challenge(ch, allowed_origins, now: float | None = None) -> bool:
    """Raise Refused unless the challenge is well formed and for an allowed
    site. Returns whether it carried a valid website signature."""
    now = time.time() if now is None else now
    if not isinstance(ch, dict):
        raise Refused("bad_challenge")

    for field, kind in (("op_id", str), ("operation", dict), ("operation_hash", str),
                        ("nonce", str), ("now", str), ("origin", str), ("claim", str)):
        if not isinstance(ch.get(field), kind):
            raise Refused("bad_challenge")
    if not (_is_int(ch.get("expires_in")) and 0 < ch["expires_in"] <= MAX_CHALLENGE_TTL_S):
        raise Refused("bad_challenge")
    if not HEX64.match(ch["nonce"]):
        raise Refused("bad_challenge")

    origin = ch["origin"]
    if origin not in allowed_origins:
        raise Refused("origin_not_allowed")
    if ch["claim"] not in SUPPORTED_CLAIMS:
        raise Refused("claim_not_supported")

    op = ch["operation"]
    if op.get("v") != spec.OP_VERSION or op.get("site") != origin or op.get("op_id") != ch["op_id"]:
        raise Refused("operation_mismatch")
    fields = ACTION_FIELDS.get(op.get("action"))
    if fields is None:
        raise Refused("unknown_action")
    for field, kind in fields.items():
        value = op.get(field)
        if not (_is_int(value) if kind is int else isinstance(value, kind)):
            raise Refused("bad_operation")
    # Anything not listed above is still hashed and still shown to the user.

    # The hash the proof will commit to is the one we compute from what the
    # user sees, never the one the agent sent. A mismatch means tampering.
    if spec.operation_hash(op).hex() != ch["operation_hash"]:
        raise Refused("operation_hash_mismatch")

    try:
        challenge_time = calendar.timegm(time.strptime(ch["now"], ISO_Z))
    except ValueError:
        raise Refused("bad_challenge") from None
    if abs(challenge_time - now) > MAX_CLOCK_SKEW_S:
        raise Refused("clock_skew")

    return check_signature(ch)


def check_status(status, origin: str, op_id: str, now: float | None = None) -> dict:
    """Check a website status message for an operation. Returns
    {"ok": bool, "signed": bool, "consumed": bool|None, "status": str|None,
     "problem": str|None}. Never raises: a bad status is shown, not hidden."""
    now = time.time() if now is None else now
    result = {"ok": False, "signed": False, "consumed": None, "status": None, "problem": None}
    if status is None:
        result["problem"] = "none provided"
        return result
    if not isinstance(status, dict):
        result["problem"] = "malformed"
        return result
    try:
        result["signed"] = check_signature(status)
    except Refused as e:
        result["problem"] = e.reason
        return result
    if (status.get("v") != spec.STATUS_VERSION or status.get("site") != origin
            or status.get("op_id") != op_id or not isinstance(status.get("consumed"), bool)
            or not isinstance(status.get("status"), str) or not _is_int(status.get("issued_at"))):
        result["problem"] = "not for this operation"
        return result
    if not 0 <= now - status["issued_at"] <= STATUS_MAX_AGE_S:
        result["problem"] = "stale"
        return result
    result.update(ok=True, consumed=status["consumed"], status=status["status"])
    return result
