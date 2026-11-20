"""Agent against real Flask apps, with scripted consent and mocked LLM HTTP."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "client" / "tests"))
import helpers  # noqa: E402,F401
import app as website  # noqa: E402
from consent import ScriptedConsent  # noqa: E402
from store import Store  # noqa: E402
from wallet import Wallet, create_app  # noqa: E402
from agent import AgentError, SafeAgent  # noqa: E402
from agent.http import TransportError  # noqa: E402
from agent.llm import DeepSeekSelector  # noqa: E402


class AppTransport:
    def __init__(self, approve=True):
        self.site = website.app.test_client()
        store = Store(None)
        store.allow_origin(website.ORIGIN)
        store.pair_agent("safe-agent", "Safe agent")
        self.wallet = Wallet(store)
        self.client = create_app(self.wallet).test_client()
        self.consent = ScriptedConsent(lambda req: approve)
        self.calls = []
        self.lost_redeem = False
        self.lost_checkout = False
        self.pending = False
        self.expire_first = False
        self.change_challenge = False
        self.change_wallet_nonce = False

    def request(self, method, url, body=None, headers=None):
        path = urlsplit(url).path
        self.calls.append((method, url, copy.deepcopy(body), headers))
        client = self.site if url.startswith(website.ORIGIN + "/") else self.client
        result = client.open(path, method=method, json=body, headers=headers)
        response = result.get_json()
        if path == "/authorize" and result.status_code == 202 and not self.pending:
            rid = self.wallet.next_request(0)
            if self.expire_first:
                self.wallet.requests[rid]["deadline"] = 0
                self.expire_first = False
            self.wallet.decide(rid, self.consent)
        if path == "/redeem" and self.lost_redeem:
            raise TransportError("Lost response after order placed")
        if path == "/checkout" and self.lost_checkout:
            raise TransportError("Lost checkout response")
        if path == "/checkout" and self.change_challenge:
            response["challenge"]["operation"]["quantity"] = 8
        if path.startswith("/authorize/") and self.change_wallet_nonce:
            response["nonce"] = "ff" * 32
        return result.status_code, response


class Relay(unittest.TestCase):
    def setUp(self):
        for table in (website.OPERATIONS, website.NONCES, website.CONSUMED):
            table.clear()
        self.transport = AppTransport()
        self.agent = SafeAgent(website.ORIGIN, http=self.transport, emit=lambda _: None,
                               approval_timeout=0.02, poll_interval=0.001)
        self.agent.browse_products()

    def test_restricted_flow_relays_exact_challenge_and_one_approval(self):
        result = self.agent.purchase("wine-001", 2)
        self.assertEqual(result["status"], "placed")
        self.assertEqual(len(self.transport.consent.seen), 1)
        self.assertEqual(self.transport.consent.seen[0].operation["amount_cents"], 3998)
        self.assertFalse(any("/enter" in url for _, url, _, _ in self.transport.calls))
        self.assertEqual(self.agent._proofs, {})
        self.assertEqual(len(website.CONSUMED), 1)

    def test_unrestricted_never_contacts_wallet(self):
        result = self.agent.purchase("water-001")
        self.assertEqual(result["status"], "placed")
        self.assertEqual(len(self.transport.calls), 2)
        self.assertEqual(self.transport.consent.seen, [])

    def test_denial_stops_before_redemption(self):
        self.transport.consent = ScriptedConsent(lambda _: False)
        self.assertEqual(self.agent.purchase("wine-001"), {"status": "denied"})
        self.assertEqual(website.CONSUMED, set())
        self.assertFalse(any(url.endswith("/redeem") for _, url, _, _ in self.transport.calls))

    def test_expiration_refreshes_same_operation(self):
        self.transport.expire_first = True
        result = self.agent.purchase("wine-001")
        self.assertEqual(result["status"], "placed")
        self.assertEqual(len(website.OPERATIONS), 1)
        requests = [body["challenge"] for _, url, body, _ in self.transport.calls if url.endswith("/authorize")]
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0]["op_id"], requests[1]["op_id"])
        self.assertNotEqual(requests[0]["nonce"], requests[1]["nonce"])

    def test_pending_timeout_does_not_refresh(self):
        self.transport.pending = True
        with self.assertRaisesRegex(AgentError, "timed out"):
            self.agent.purchase("wine-001")
        self.assertEqual(len(self.transport.wallet.requests), 1)
        self.assertEqual(len(website.NONCES), 1)
        self.assertEqual(website.CONSUMED, set())

    def test_lost_redeem_is_not_retried(self):
        self.transport.lost_redeem = True
        with self.assertRaisesRegex(AgentError, "Outcome unknown"):
            self.agent.purchase("wine-001")
        self.assertEqual(len(website.CONSUMED), 1)
        with self.assertRaises(AgentError):
            self.agent.request_operation("wine-001")
        self.assertEqual(sum(url.endswith("/redeem") for _, url, _, _ in self.transport.calls), 1)

    def test_lost_unrestricted_checkout_not_retried(self):
        self.transport.lost_checkout = True
        with self.assertRaisesRegex(AgentError, "Outcome unknown"):
            self.agent.purchase("water-001")
        with self.assertRaises(AgentError):
            self.agent.purchase("water-001")
        self.assertEqual(len(website.CONSUMED), 1)

    def test_handle_bindings_and_one_use(self):
        operation = self.agent.request_operation("wine-001")
        auth = self.agent.request_wallet_authorization(operation["challenge_handle"])
        self.assertNotIn("proof", auth)
        with self.assertRaises(AgentError):
            self.agent.redeem(auth["nonce"], auth["proof_handle"], "other")
        with self.assertRaises(AgentError):
            self.agent.redeem("ff" * 32, auth["proof_handle"])
        with self.assertRaises(AgentError):
            self.agent.redeem(auth["nonce"], auth["proof_handle"], site_id="https://other.example")
        self.agent.redeem(auth["nonce"], auth["proof_handle"])
        with self.assertRaises(AgentError):
            self.agent.redeem(auth["nonce"], auth["proof_handle"])

    def test_invalid_selection_has_no_checkout(self):
        for item, qty in (("invented", 1), ("wine-001", True), ("wine-001", 11)):
            with self.assertRaises(AgentError):
                self.agent.request_operation(item, qty)
        self.agent.max_total_cents = 100
        with self.assertRaisesRegex(AgentError, "budget"):
            self.agent.request_operation("wine-001")
        self.assertEqual(len(self.transport.calls), 1)

    def test_tampered_challenge_stops_before_wallet(self):
        self.transport.change_challenge = True
        with self.assertRaisesRegex(AgentError, "Challenge"):
            self.agent.purchase("wine-001")
        self.assertEqual(self.transport.wallet.requests, {})

    def test_mismatched_wallet_response_not_redeemed(self):
        self.transport.change_wallet_nonce = True
        with self.assertRaisesRegex(AgentError, "Wallet response"):
            self.agent.purchase("wine-001")
        self.assertEqual(website.CONSUMED, set())

    def test_refresh_cannot_replace_pending_prompt(self):
        op = self.agent.request_operation("wine-001")
        with self.assertRaises(AgentError):
            self.agent.request_fresh_challenge(op["op_id"])

    def test_refresh_limit_stops_without_new_checkout(self):
        self.transport.expire_first = True
        self.agent.max_refreshes = 0
        with self.assertRaisesRegex(AgentError, "refresh limit"):
            self.agent.purchase("wine-001")
        self.assertEqual(len(website.OPERATIONS), 1)
        self.assertEqual(website.CONSUMED, set())

    def test_deepseek_selection_through_cli_and_relay(self):
        from agent.__main__ import main
        selector = DeepSeekSelector("test-key", http=LLM().transport())
        self.agent.max_total_cents = 2500
        output = io.StringIO()
        with patch("sys.argv", ["agent", "--site", website.ORIGIN, "--task", "Buy wine under $20"]), \
                patch("agent.__main__.SafeAgent", return_value=self.agent), \
                patch("agent.__main__.DeepSeekSelector", return_value=selector), \
                patch.dict("os.environ", {"DEEPSEEK_API_KEY": "test-key"}), redirect_stdout(output):
            self.assertEqual(main(), 0)
        self.assertEqual(self.agent.max_total_cents, 2000)
        self.assertEqual(len(website.CONSUMED), 1)
        self.assertNotIn("dev-proof", output.getvalue())

    def test_model_cannot_raise_explicit_budget(self):
        from agent.__main__ import main
        selector = DeepSeekSelector("test-key", http=LLM().transport())
        self.agent.max_total_cents = 1000
        with patch("sys.argv", ["agent", "--site", website.ORIGIN, "--task", "Buy wine"]), \
                patch("agent.__main__.SafeAgent", return_value=self.agent), \
                patch("agent.__main__.DeepSeekSelector", return_value=selector), \
                patch.dict("os.environ", {"DEEPSEEK_API_KEY": "test-key"}), redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 1)
        self.assertEqual(website.OPERATIONS, {})


class LLM(unittest.TestCase):
    def transport(self, name="select_product", args=None, code=200):
        from unittest.mock import Mock
        http = Mock()
        http.request.return_value = code, {"choices": [{"message": {"tool_calls": [
            {"function": {"name": name, "arguments": json.dumps(args if args is not None else {
                "item_id": "wine-001", "quantity": 1, "max_total_cents": 2000})}}]}}]}
        return http

    def test_selection_and_minimal_context(self):
        http = self.transport()
        result = DeepSeekSelector("test-key", http=http).select("Buy wine under $20", [], 10)
        self.assertEqual(result["max_total_cents"], 2000)
        payload = http.request.call_args.args[2]
        self.assertNotIn("test-key", json.dumps(payload))
        self.assertNotIn("proof_handle", json.dumps(payload))

    def test_clarification(self):
        http = self.transport("clarify_task", {"question": "Which product?"})
        self.assertEqual(DeepSeekSelector("test-key", http=http).select("Buy something", [], 10)["status"], "clarify")

    def test_invalid_tool_and_boolean_quantity(self):
        for http in (self.transport("redeem"), self.transport(args={"item_id": "wine-001", "quantity": True,
                                                                 "max_total_cents": None})):
            with self.assertRaises(AgentError):
                DeepSeekSelector("test-key", http=http).select("Buy wine", [], 10)

    def test_api_error_contains_no_key(self):
        with self.assertRaises(AgentError) as raised:
            DeepSeekSelector("test-key", http=self.transport(code=401)).select("Buy wine", [], 10)
        self.assertNotIn("test-key", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
