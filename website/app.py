"""ZKARMA shop: public catalog, age authorization at restricted checkout only.

Run: ZKARMA_DEV=1 python website/app.py
The dev identity header and literal dev-proof are workflow stubs, not security.
See agent/README.md for setup and the complete website/wallet/agent workflow.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
import uuid

import cbor2
from flask import Flask, g, jsonify, request

import proofs  # Longfellow verifier (website/proofs.py)

# ----------------------------------------------------------------------------
# Config and state
# ----------------------------------------------------------------------------
ORIGIN = os.environ.get("ZKARMA_ORIGIN", "http://localhost:5050")
PORT = int(os.environ.get("ZKARMA_PORT", "5050"))
CLAIM = "age_over_18"
NONCE_TTL_S = 120        # how long a challenge stays valid
MAX_QUANTITY = 10
# Dev mode fakes the agent signature with a header and also accepts the fake
# proof "dev-proof".
DEV = os.environ.get("ZKARMA_DEV") == "1"

# The website owns restriction policy and prices. Amounts are integer cents.
CATALOG = {
    "wine-001": {"name": "Red wine, 750 ml", "price_cents": 1999, "age_restricted": True},
    "water-001": {"name": "Sparkling water, 750 ml", "price_cents": 299, "age_restricted": False},
    "vape-001": {"name": "Vape starter kit", "price_cents": 2499, "age_restricted": True},
}

app = Flask(__name__)
# All in memory for now, so a restart forgets everything.
OPERATIONS: dict[str, dict] = {}  # op_id -> {"operation": {...}, "agent_jkt": str, "status": str}
NONCES: dict[str, dict] = {}      # nonce (hex) -> {"op_id": str, "now": str, "expires_at": float}
CONSUMED: set[str] = set()        # op_ids that already ran
_lock = threading.Lock()


def operation_hash(operation: dict) -> bytes:
    """SHA-256 of the operation as canonical JSON (sorted keys, no spaces).
    Stand-in for RFC 8785, which gives the same bytes for what an operation
    contains (ASCII keys, strings and integers)."""
    canonical = json.dumps(operation, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).digest()


def build_transcript(origin: str, nonce: bytes, agent_jkt: str, op_hash: bytes) -> bytes:
    """SessionTranscript = [null, null, ["ZKARMAv1",
                                         SHA-256(CBOR([origin, nonce, agent_jkt, op_hash]))]]"""
    inner = hashlib.sha256(cbor2.dumps([origin, nonce, agent_jkt, op_hash])).digest()
    return cbor2.dumps([None, None, ["ZKARMAv1", inner]])


# ----------------------------------------------------------------------------
# Stubs. 
# ----------------------------------------------------------------------------
def verify_agent_signature(req) -> str | None:
    if DEV:
        return req.headers.get("X-Dev-Agent-Thumbprint") or None
    return None


def consume(op_id: str) -> bool:

    with _lock:  # check and add as one step
        if op_id in CONSUMED:
            return False
        CONSUMED.add(op_id)
        return True


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def reject(reason: str, status: int = 403):
    return jsonify(error=reason), status


def new_operation(action: str, **details) -> dict:
    """Create an operation for the agent making this request."""
    op_id = uuid.uuid4().hex
    record = {
        "operation": {"v": "zkarma-op-1", "site": ORIGIN, "action": action, "op_id": op_id, **details},
        "agent_jkt": g.agent_jkt,
        "status": "pending",
    }
    OPERATIONS[op_id] = record
    return record


def challenge(record: dict):
    """A 401 with a fresh nonce for this operation."""
    operation = record["operation"]
    nonce = secrets.token_bytes(32).hex()
    # The proof must show the ID is valid at this exact time, so the wallet
    # proves for it and the site verifies with it.
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    NONCES[nonce] = {"op_id": operation["op_id"], "now": now, "expires_at": time.time() + NONCE_TTL_S}
    body = jsonify(error="age_check_required", challenge={
        "op_id": operation["op_id"],
        "operation": operation,
        "operation_hash": operation_hash(operation).hex(),
        "nonce": nonce,
        "now": now,
        "origin": ORIGIN,
        "claim": CLAIM,
        "expires_in": NONCE_TTL_S,
        "redeem": "/redeem",
    })
    return body, 401, {"WWW-Authenticate": f'ZKARMA realm="{operation["action"]}"'}


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.before_request
def gate():
    """Browsing is public; operations still require the agent's identity."""
    if request.endpoint is None or request.endpoint in ("health", "products"):
        return None
    g.agent_jkt = verify_agent_signature(request)
    if not g.agent_jkt:
        return reject("bad_signature", 401)
    return None


@app.get("/health")
def health():
    return jsonify(ok=True, origin=ORIGIN, dev=DEV)


@app.get("/products")
def products():
    """Public catalog, including the website's restriction policy."""
    return jsonify(products=[{"item_id": item_id, "currency": "USD", **item}
                             for item_id, item in CATALOG.items()], max_quantity=MAX_QUANTITY)


@app.post("/checkout")
def checkout():
    """Restricted items need a proof; unrestricted orders complete immediately."""
    body = request.get_json(silent=True)
    body = body if isinstance(body, dict) else {}
    item_id, quantity = body.get("item_id"), body.get("quantity")
    # type() instead of isinstance(), since JSON true would otherwise pass as 1.
    if not (isinstance(item_id, str) and item_id in CATALOG
            and type(quantity) is int and 1 <= quantity <= MAX_QUANTITY):
        return reject("bad_request", 400)
    # The site sets the name and price. The agent only picks the item and quantity.
    item = CATALOG[item_id]
    record = new_operation(
        "checkout", item_id=item_id, item_name=item["name"], quantity=quantity,
        amount_cents=item["price_cents"] * quantity, currency="USD")
    if item["age_restricted"]:
        return challenge(record)
    consume(record["operation"]["op_id"])
    record["status"] = "placed"
    return jsonify(status="placed", op_id=record["operation"]["op_id"])


@app.post("/redeem")
def redeem():
    """Check a proof and run the operation it's for. The same checks run for
    every action, cheapest first."""
    # 1. Who is asking. gate() already checked the signature.
    agent_jkt = g.agent_jkt

    body = request.get_json(silent=True)
    if not (isinstance(body, dict) and isinstance(body.get("nonce"), str)
            and isinstance(body.get("proof"), str)):
        return reject("bad_request", 400)

    # 2. A nonce this site issued, unexpired and unused. Burn it right away.
    #    pop() is atomic, so two requests can't both use one nonce.
    entry = NONCES.pop(body["nonce"], None)
    if entry is None or entry["expires_at"] < time.time():
        return reject("nonce_invalid_or_used")

    # 3. The operation this nonce is for, started by this same agent.
    record = OPERATIONS[entry["op_id"]]
    if record["agent_jkt"] != agent_jkt:
        return reject("wrong_agent")
    operation = record["operation"]

    # 4. Rebuild the transcript from what this site knows.
    #    Never accept a transcript from the client.
    transcript = build_transcript(ORIGIN, bytes.fromhex(body["nonce"]), agent_jkt,
                                  operation_hash(operation))

    # 5. Check the zero-knowledge proof against the rebuilt transcript and the
    #    challenge's time, with Longfellow. Dev mode also accepts "dev-proof".
    dev_pass = DEV and body["proof"] == "dev-proof"
    if not dev_pass and not proofs.verify(body["proof"], transcript, entry["now"]):
        return reject("proof_invalid")

    # 6. Consume the operation itself, so a fresh proof for it is still refused.
    if not consume(operation["op_id"]):
        return reject("already_consumed", 409)

    # 7. Do the action.
    record["status"] = "placed"  # a real shop would charge and ship here
    return jsonify(status="placed", op_id=operation["op_id"])


@app.post("/operations/<op_id>/challenge")
def rechallenge(op_id: str):
    """A fresh nonce for an existing operation, for example after a retry.
    It doesn't check whether the operation already ran. The ledger in /redeem
    is the check that matters, and the tests use this route to show it."""
    record = OPERATIONS.get(op_id)
    if record is None or record["agent_jkt"] != g.agent_jkt:
        return reject("unknown_operation", 404)
    return challenge(record)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PORT)