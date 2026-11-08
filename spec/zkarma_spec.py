"""ZKARMA shared formats: the bytes every party must agree on.

PROPOSAL for the group (not wired into website/ yet). website/app.py has its
own copies of operation_hash() and build_transcript() next to a
"TODO: move into spec/". This module gives the same bytes (client/tests/
test_spec.py checks it against website/app.py), so the website can switch to
importing it once Torence agrees.

Also defines the website-signed messages the client checks. The signatures
are STUBS until the PKI work lands (see stub_sign / stub_verify below).
"""
from __future__ import annotations

import hashlib
import json

import cbor2

OP_VERSION = "zkarma-op-1"
TRANSCRIPT_TAG = "ZKARMAv1"
STATUS_VERSION = "zkarma-status-1"


# ----------------------------------------------------------------------------
# Operation and transcript (same bytes as website/app.py)
# ----------------------------------------------------------------------------
def canonical_json(obj) -> bytes:
    """Sorted keys, no spaces. Stand-in for RFC 8785, which gives the same
    bytes for what ZKARMA messages contain (ASCII keys, strings, integers)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def operation_hash(operation: dict) -> bytes:
    """SHA-256 of the operation as canonical JSON."""
    return hashlib.sha256(canonical_json(operation)).digest()


def build_transcript(origin: str, nonce: bytes, agent_jkt: str, op_hash: bytes) -> bytes:
    """SessionTranscript = [null, null, ["ZKARMAv1",
                                         SHA-256(CBOR([origin, nonce, agent_jkt, op_hash]))]]
    The device key signs over this, so the proof only works for this site,
    nonce, agent and operation."""
    inner = hashlib.sha256(cbor2.dumps([origin, nonce, agent_jkt, op_hash])).digest()
    return cbor2.dumps([None, None, [TRANSCRIPT_TAG, inner]])


# ----------------------------------------------------------------------------
# Website-signed messages (PROPOSAL)
#
# 1. Challenge: the 401 challenge body plus a "signature" field over every
#    other field. Lets the client trust the nonce, time and operation came
#    from the site, not the agent.
#
# 2. Operation status: what the website says about an operation, so the user
#    can see whether it already ran before approving a retry.
#       {"v": "zkarma-status-1", "site": <origin>, "op_id": ..,
#        "status": "pending" | "entered" | "placed", "consumed": bool,
#        "issued_at": <unix seconds>, "signature": ..}
#    Suggested home: in the /operations/<op_id>/challenge response, or a
#    GET /operations/<op_id>/status route.
# ----------------------------------------------------------------------------
def signed_payload(message: dict) -> bytes:
    """The bytes a website signature covers: the message without "signature"."""
    return canonical_json({k: v for k, v in message.items() if k != "signature"})


# STUB. A hash anyone can compute, so this checks plumbing and accidental
# changes only, not who sent the message. Replace both functions with the
# real website key from the PKI.
STUB_PREFIX = "stub-sig:"


def stub_sign(message: dict) -> str:
    return STUB_PREFIX + hashlib.sha256(signed_payload(message)).hexdigest()


def stub_verify(message: dict, signature: str) -> bool:
    return isinstance(signature, str) and signature == stub_sign(message)
