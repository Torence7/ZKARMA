"""Honest relay with process-local handles and one purchase per instance.

The model never sees proofs. This module is intentionally independent of the
LLM so protocol flows can be tested without an API key or paid requests.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import math
import re
import time
from urllib.parse import quote, urlsplit
import uuid

from spec.zkarma_spec import operation_hash
from .http import JsonHTTP, TransportError


class AgentError(Exception):
    pass


def origin(value):
    try:
        parsed = urlsplit(value)
        _ = parsed.port  # validate even though we preserve the supplied origin
    except (ValueError, TypeError) as error:
        raise AgentError("Invalid website or wallet origin") from error
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise AgentError("Use an HTTP(S) origin, for example http://localhost:5050")
    return value.rstrip("/")


class SafeAgent:
    def __init__(self, site, wallet="http://127.0.0.1:5060", agent_id="safe-agent",
                 *, http=None, approval_timeout=180, poll_interval=0.5,
                 max_refreshes=1, max_total_cents=None, emit=print):
        self.site, self.wallet, self.agent_id = origin(site), origin(wallet), agent_id
        if not isinstance(agent_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", agent_id):
            raise AgentError("Invalid agent identity")
        if (not math.isfinite(approval_timeout) or not math.isfinite(poll_interval)
                or approval_timeout <= 0 or poll_interval <= 0
                or type(max_refreshes) is not int or max_refreshes < 0):
            raise AgentError("Timeouts must be positive and refresh count nonnegative")
        if max_total_cents is not None and (type(max_total_cents) is not int or max_total_cents < 0):
            raise AgentError("Budget must be a nonnegative integer number of cents")
        self.http = http or JsonHTTP()
        self.approval_timeout, self.poll_interval = approval_timeout, poll_interval
        self.max_refreshes, self.max_total_cents, self.emit = max_refreshes, max_total_cents, emit
        self.catalog = {}
        self.max_quantity = 10
        self._challenges, self._proofs, self._operations = {}, {}, {}
        self._started = False

    def _call(self, method, base, path, body=None, *, public=False):
        headers = {} if public else {"X-Dev-Agent-Thumbprint": self.agent_id}
        try:
            code, result = self.http.request(method, base + path, body, headers)
        except TransportError as error:
            detail = " Outcome unknown; do not automatically repeat this operation." if method == "POST" else ""
            raise AgentError(f"Request to {path} failed.{detail}") from error
        if code >= 500:
            raise AgentError(f"Server error at {path}; outcome may be unknown. No automatic retry.")
        return code, result

    @staticmethod
    def _unexpected(code, result):
        reason = result.get("error", "unexpected_response")
        # Only display protocol error codes, never arbitrary server text.
        if not isinstance(reason, str) or not re.fullmatch(r"[a-z_]{1,80}", reason):
            reason = "unexpected_response"
        raise AgentError(f"HTTP {code}: {reason}")

    def browse_products(self):
        code, body = self._call("GET", self.site, "/products", public=True)
        if code != 200:
            self._unexpected(code, body)
        items, limit = body.get("products"), body.get("max_quantity", 10)
        if not isinstance(items, list) or type(limit) is not int or not 1 <= limit <= 10000:
            raise AgentError("Invalid catalog")
        catalog = {}
        for item in items:
            if (not isinstance(item, dict) or not isinstance(item.get("item_id"), str)
                    or not item["item_id"] or item["item_id"] in catalog
                    or not isinstance(item.get("name"), str)
                    or type(item.get("price_cents")) is not int or item["price_cents"] < 0
                    or type(item.get("age_restricted")) is not bool
                    or item.get("currency") != "USD"):
                raise AgentError("Invalid catalog item")
            catalog[item["item_id"]] = copy.deepcopy(item)
        self.catalog, self.max_quantity = catalog, limit
        return copy.deepcopy(list(catalog.values()))

    def validate_selection(self, item_id, quantity):
        if not isinstance(item_id, str) or item_id not in self.catalog:
            raise AgentError("Select an item from the current catalog")
        if type(quantity) is not int or not 1 <= quantity <= self.max_quantity:
            raise AgentError(f"Quantity must be an integer from 1 to {self.max_quantity}")
        total = self.catalog[item_id]["price_cents"] * quantity
        if self.max_total_cents is not None and total > self.max_total_cents:
            raise AgentError("Selection exceeds the configured budget")
        return total

    def _store_challenge(self, body, expected, op_id=None):
        ch = body.get("challenge")
        try:
            op = ch["operation"]
            valid = (isinstance(op, dict) and ch["origin"] == self.site
                     and op["site"] == self.site and op["v"] == "zkarma-op-1"
                     and op["action"] == "checkout" and ch["claim"] == "age_over_18"
                     and isinstance(ch["op_id"], str)
                     and re.fullmatch(r"[a-f0-9]{32}", ch["op_id"])
                     and op["op_id"] == ch["op_id"]
                     and (op_id is None or op_id == ch["op_id"])
                     and all(op.get(k) == v for k, v in expected.items())
                     and ch["operation_hash"] == operation_hash(op).hex()
                     and isinstance(ch["nonce"], str) and re.fullmatch(r"[a-f0-9]{64}", ch["nonce"])
                     and type(ch["expires_in"]) is int and 0 < ch["expires_in"] <= 600)
            issued = datetime.strptime(ch["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            valid = valid and abs(issued - time.time()) <= 300
        except (KeyError, TypeError, ValueError, AttributeError):
            valid = False
        if not valid:
            raise AgentError("Challenge does not match the selected website and purchase")
        previous = self._operations.get(ch["op_id"])
        if previous:
            if previous["operation"] != op:
                raise AgentError("Refreshed challenge changed the operation")
            self._challenges[previous["handle"]]["state"] = "superseded"
        handle = "challenge_" + uuid.uuid4().hex
        self._challenges[handle] = {"challenge": copy.deepcopy(ch), "expires_at": issued + ch["expires_in"],
                                    "state": "new"}
        self._operations[ch["op_id"]] = {"operation": copy.deepcopy(op), "handle": handle, "state": "pending"}
        return {"status": "challenge", "op_id": ch["op_id"], "challenge_handle": handle}

    def request_operation(self, item_id, quantity=1):
        total = self.validate_selection(item_id, quantity)
        if self._started:
            raise AgentError("This agent instance has already started a purchase")
        self._started = True  # A lost response must never cause another checkout.
        code, body = self._call("POST", self.site, "/checkout", {"item_id": item_id, "quantity": quantity})
        if code == 200 and body.get("status") == "placed" and isinstance(body.get("op_id"), str):
            if self.catalog[item_id]["age_restricted"]:
                raise AgentError("Website placed a restricted order without authorization; stopping")
            return {"status": "placed", "op_id": body["op_id"]}
        if code != 401 or body.get("error") != "age_check_required":
            self._unexpected(code, body)
        expected = {"item_id": item_id, "item_name": self.catalog[item_id]["name"], "quantity": quantity,
                    "amount_cents": total, "currency": "USD"}
        return self._store_challenge(body, expected)

    def request_fresh_challenge(self, op_id):
        rec = self._operations.get(op_id)
        if not rec or rec["state"] != "pending":
            raise AgentError("Cannot refresh an unknown, completed, or uncertain operation")
        old = self._challenges[rec["handle"]]
        if old["state"] != "expired":
            raise AgentError("Refresh requires an expired challenge, with no pending approval")
        code, body = self._call("POST", self.site, f"/operations/{quote(op_id, safe='')}/challenge")
        if code != 401 or body.get("error") != "age_check_required":
            self._unexpected(code, body)
        return self._store_challenge(body, rec["operation"], op_id)

    def request_wallet_authorization(self, challenge_handle):
        rec = self._challenges.get(challenge_handle)
        if not rec or rec["state"] != "new":
            raise AgentError("Unknown or previously submitted challenge handle")
        if time.time() >= rec["expires_at"]:
            rec["state"] = "expired"
            return {"status": "expired"}
        rec["state"] = "pending"
        ch = rec["challenge"]
        code, body = self._call("POST", self.wallet, "/authorize", {"challenge": copy.deepcopy(ch)})
        if code != 202 or body.get("status") != "pending":
            self._unexpected(code, body)
        rid = body.get("request_id")
        if not isinstance(rid, str) or not re.fullmatch(r"[a-f0-9]{32}", rid):
            raise AgentError("Wallet returned an invalid request ID")
        self.emit("Waiting for approval in the wallet terminal...")
        deadline = time.monotonic() + self.approval_timeout
        while time.monotonic() < deadline:
            code, answer = self._call("GET", self.wallet, f"/authorize/{rid}")
            if code != 200:
                self._unexpected(code, answer)
            status = answer.get("status")
            if status == "pending":
                time.sleep(min(self.poll_interval, max(0, deadline - time.monotonic())))
                continue
            if status in ("denied", "expired"):
                rec["state"] = status
                return {"status": status}
            if status == "error":
                rec["state"] = "error"
                raise AgentError("Wallet could not generate the proof; see the wallet terminal")
            if (status != "approved" or answer.get("op_id") != ch["op_id"]
                    or answer.get("nonce") != ch["nonce"]
                    or not isinstance(answer.get("proof"), str) or not answer["proof"]):
                raise AgentError("Wallet response does not match the challenge")
            rec["state"] = "approved"
            handle = "proof_" + uuid.uuid4().hex
            self._proofs[handle] = {"proof": answer["proof"], "challenge_handle": challenge_handle}
            return {"status": "approved", "op_id": ch["op_id"], "nonce": ch["nonce"], "proof_handle": handle}
        # The wallet prompt might still be open; do not refresh and create another.
        raise AgentError("Wallet approval timed out. No purchase was redeemed; the wallet prompt may still be open.")

    def redeem(self, nonce, proof_handle, agent_id=None, site_id=None):
        if agent_id not in (None, self.agent_id) or site_id not in (None, self.site):
            raise AgentError("Proof destination or agent identity mismatch")
        proof = self._proofs.get(proof_handle)
        if not proof:
            raise AgentError("Unknown or already used proof handle")
        rec = self._challenges[proof["challenge_handle"]]
        ch = rec["challenge"]
        if nonce != ch["nonce"] or rec["state"] != "approved":
            raise AgentError("Proof and nonce do not match an approved challenge")
        self._proofs.pop(proof_handle)
        if time.time() >= rec["expires_at"]:
            rec["state"] = "expired"
            return {"status": "expired"}
        op = self._operations[ch["op_id"]]
        rec["state"], op["state"] = "attempted", "uncertain"
        code, body = self._call("POST", self.site, "/redeem", {"nonce": nonce, "proof": proof["proof"]})
        if code != 200 or body.get("status") != "placed" or body.get("op_id") != ch["op_id"]:
            self._unexpected(code, body)
        op["state"] = "placed"
        return {"status": "placed", "op_id": body["op_id"]}

    def purchase(self, item_id, quantity=1):
        result = self.request_operation(item_id, quantity)
        for attempt in range(self.max_refreshes + 1):
            if result["status"] == "placed":
                return result
            auth = self.request_wallet_authorization(result["challenge_handle"])
            if auth["status"] == "denied":
                return auth
            if auth["status"] == "approved":
                outcome = self.redeem(auth["nonce"], auth["proof_handle"])
                if outcome["status"] == "placed":
                    return outcome
            if attempt == self.max_refreshes:
                raise AgentError("Challenge expired; refresh limit reached. No automatic new purchase.")
            self.emit("Challenge expired; requesting a fresh challenge for the same operation.")
            result = self.request_fresh_challenge(result["op_id"])
        raise AssertionError("Unreachable")
