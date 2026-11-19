"""End to end: the real website app (website/app.py, dev mode) and
the wallet, with the test acting as the agent and a scripted user."""
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from helpers import binding_proof

import app as website
from config import spec
from consent import ScriptedConsent, render
from store import Store
from wallet import Wallet, create_app

ORIGIN = website.ORIGIN


class FlowBase(unittest.TestCase):
    """Setup and the agent's moves. Tests live in the subclasses."""

    def setUp(self):
        for table in (website.OPERATIONS, website.NONCES, website.CONSUMED):
            table.clear()
        self.site = website.app.test_client()
        self.store = Store(None)
        self.store.allow_origin(ORIGIN)
        self.store.pair_agent("a1", "Agent one")
        self.store.pair_agent("a2", "Agent two")
        self.wallet = Wallet(self.store)
        self.client = create_app(self.wallet).test_client()
        self.consent = ScriptedConsent(lambda req: True)

    # The agent's side ---------------------------------------------------
    @staticmethod
    def h(agent):
        return {"X-Dev-Agent-Thumbprint": agent}

    def ask(self, agent, challenge, status=None):
        """Send a challenge to the wallet, let the scripted user answer, poll."""
        r = self.client.post("/authorize", headers=self.h(agent),
                             json={"challenge": challenge, "status": status})
        if r.status_code != 202:
            return r.status_code, r.get_json()
        self.wallet.decide(self.wallet.next_request(0), self.consent)
        return 200, self.client.get(r.get_json()["poll"], headers=self.h(agent)).get_json()

    def redeem(self, agent, answer):
        return self.site.post("/redeem", headers=self.h(agent),
                              json={"nonce": answer["nonce"], "proof": answer["proof"]})

    def checkout(self, agent, quantity=1):
        r = self.site.post("/checkout", headers=self.h(agent),
                           json={"item_id": "wine-001", "quantity": quantity})
        self.assertEqual(r.status_code, 401)
        return r.get_json()["challenge"]


class Flow(FlowBase):
    # Normal use ---------------------------------------------------------
    def test_buy_without_entry(self):
        ch = self.checkout("a1", quantity=2)
        code, answer = self.ask("a1", ch)
        self.assertEqual(answer["status"], "approved")
        self.assertIn("prove_ms", answer["metrics"])
        r = self.redeem("a1", answer)
        self.assertEqual(r.get_json(), {"status": "placed", "op_id": ch["op_id"]})
        shown = self.consent.seen[-1]
        self.assertEqual((shown.operation["quantity"], shown.operation["amount_cents"]), (2, 3998))
        self.assertIn("BUY 2 x Red wine", render(shown))
        self.assertIn("NOT signed", render(shown))  # website doesn't sign yet
        self.assertEqual([d["decision"] for d in self.store.decisions(ORIGIN, ch["op_id"])],
                         ["approved"])

    def test_user_denies(self):
        self.consent = ScriptedConsent(lambda req: False)
        ch = self.checkout("a1")
        _, answer = self.ask("a1", ch)
        self.assertEqual(answer, {"status": "denied"})

    # Refused before the user is asked -----------------------------------
    def test_unpaired_agent(self):
        ch = self.checkout("a3")
        self.assertEqual(self.ask("a3", ch), (403, {"error": "agent_not_paired"}))
        self.assertEqual(self.consent.seen, [])

    def test_no_agent_identity(self):
        self.assertEqual(self.client.post("/authorize", json={}).status_code, 401)

    def test_agent_changed_operation(self):
        ch = self.checkout("a1")
        ch["operation"]["quantity"] = 10
        self.assertEqual(self.ask("a1", ch), (422, {"error": "operation_hash_mismatch"}))

    def test_site_not_allowed(self):
        self.store.disallow_origin(ORIGIN)
        ch = self.checkout("a1")
        self.assertEqual(self.ask("a1", ch), (422, {"error": "origin_not_allowed"}))

    def test_one_prompt_per_operation(self):
        ch = self.checkout("a1")
        first = self.client.post("/authorize", headers=self.h("a1"), json={"challenge": ch})
        second = self.client.post("/authorize", headers=self.h("a1"), json={"challenge": ch})
        self.assertEqual((first.status_code, second.status_code), (202, 409))

    def test_other_agent_cannot_poll(self):
        ch = self.checkout("a1")
        poll = self.client.post("/authorize", headers=self.h("a1"),
                                json={"challenge": ch}).get_json()["poll"]
        self.assertEqual(self.client.get(poll, headers=self.h("a2")).status_code, 404)

    def test_expired_before_user_answers(self):
        ch = self.checkout("a1")
        self.client.post("/authorize", headers=self.h("a1"), json={"challenge": ch})
        rid = self.wallet.next_request(0)
        self.wallet.requests[rid]["deadline"] = time.time() - 1
        self.assertEqual(self.wallet.decide(rid, self.consent), "expired")
        self.assertEqual(self.consent.seen, [])

    # Retries (semantic replay) ------------------------------------------
    def test_retry_asks_again_and_site_refuses(self):
        ch = self.checkout("a1")
        _, answer = self.ask("a1", ch)
        self.assertEqual(self.redeem("a1", answer).status_code, 200)

        retry = self.site.post(f"/operations/{ch['op_id']}/challenge",
                               headers=self.h("a1")).get_json()["challenge"]
        _, answer = self.ask("a1", retry)
        shown = self.consent.seen[-1]
        self.assertTrue(shown.is_retry)
        self.assertIn("RETRY", render(shown))
        self.assertIn("Cannot confirm whether it already ran", render(shown))
        # Even if the user says yes, the website's ledger refuses the second run.
        r = self.redeem("a1", answer)
        self.assertEqual((r.status_code, r.get_json()), (409, {"error": "already_consumed"}))

    def test_retry_outside_dev_needs_signed_status(self):
        # Outside dev mode the agent-signature stub is off too, so stand in for it.
        with mock.patch("wallet.DEV", False), mock.patch("validate.DEV", False), \
                mock.patch("wallet.agent_identity",
                           lambda req: req.headers.get("X-Dev-Agent-Thumbprint")):
            ch = self.checkout("a1")
            ch["signature"] = spec.stub_sign(ch)  # stands in for the website signing
            self.assertEqual(self.ask("a1", ch)[1]["status"], "approved")

            retry = dict(ch, signature=None)
            retry["signature"] = spec.stub_sign(retry)
            self.assertEqual(self.ask("a1", retry), (422, {"error": "status_required"}))

            status = {"v": "zkarma-status-1", "site": ORIGIN, "op_id": ch["op_id"],
                      "status": "placed", "consumed": True, "issued_at": int(time.time())}
            status["signature"] = spec.stub_sign(status)
            self.consent = ScriptedConsent(lambda req: False)
            self.assertEqual(self.ask("a1", retry, status)[1], {"status": "denied"})
            text = render(self.consent.seen[-1])
            self.assertIn("Website status (signed): placed, ALREADY RAN", text)


class Binding(FlowBase):
    """Proofs that, unlike "dev-proof", are bound to the transcript, so these
    tests show what the real proofs will enforce."""

    def setUp(self):
        super().setUp()
        for p in (mock.patch("wallet.prove", lambda t, now, claim: binding_proof(t)),
                  mock.patch.object(website.proofs, "verify",
                                    lambda proof, t, now: proof == binding_proof(t))):
            p.start()
            self.addCleanup(p.stop)

    def test_stolen_proof_used_by_other_agent(self):
        ch = self.checkout("a1")
        _, answer = self.ask("a1", ch)
        r = self.redeem("a2", answer)
        self.assertEqual((r.status_code, r.get_json()), (403, {"error": "wrong_agent"}))

    def test_agent_asks_wallet_with_another_agents_challenge(self):
        ch = self.checkout("a1")
        _, answer = self.ask("a2", ch)  # the wallet binds the proof to a2
        r = self.redeem("a1", answer)
        self.assertEqual((r.status_code, r.get_json()), (403, {"error": "proof_invalid"}))

    def test_agent_rewrites_operation_and_hash(self):
        # The wallet can't spot this one, but the user sees quantity 10 and
        # the proof is bound to quantity 10, which the site never issued.
        ch = self.checkout("a1", quantity=1)
        ch["operation"]["quantity"] = 10
        ch["operation_hash"] = spec.operation_hash(ch["operation"]).hex()
        _, answer = self.ask("a1", ch)
        self.assertEqual(self.consent.seen[-1].operation["quantity"], 10)
        r = self.redeem("a1", answer)
        self.assertEqual((r.status_code, r.get_json()), (403, {"error": "proof_invalid"}))

    def test_proof_for_another_site(self):
        self.store.allow_origin("https://other.example")
        ch = self.checkout("a1")
        ch["origin"] = ch["operation"]["site"] = "https://other.example"
        ch["operation_hash"] = spec.operation_hash(ch["operation"]).hex()
        _, answer = self.ask("a1", ch)
        r = self.redeem("a1", answer)
        self.assertEqual((r.status_code, r.get_json()), (403, {"error": "proof_invalid"}))


class Persistence(unittest.TestCase):
    def test_state_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            s = Store(path)
            s.pair_agent("a1", "Agent one")
            s.allow_origin(ORIGIN)
            s.record_decision(ORIGIN, "op", {"decision": "approved", "at": 1,
                                             "agent_jkt": "a1", "action": "checkout"})
            again = Store(path)
            self.assertEqual(again.agent("a1")["name"], "Agent one")
            self.assertEqual(again.origins, [ORIGIN])
            self.assertEqual(again.decisions(ORIGIN, "op")[0]["decision"], "approved")


if __name__ == "__main__":
    unittest.main()
