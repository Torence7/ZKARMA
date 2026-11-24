"""The optional entry check (ZKARMA_ENTRY_CHECK=1), off and on.

Run: python -m unittest discover -s website/tests -v
"""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["ZKARMA_DEV"] = "1"
os.environ.pop("ZKARMA_ENTRY_CHECK", None)  # start from the default
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # website/

import app as website  # noqa: E402

A = {"X-Dev-Agent-Thumbprint": "agent-a"}
B = {"X-Dev-Agent-Thumbprint": "agent-b"}
WATER = {"item_id": "water-001", "quantity": 1}
WINE = {"item_id": "wine-001", "quantity": 1}


class EntryCheck(unittest.TestCase):
    def setUp(self):
        for table in (website.OPERATIONS, website.NONCES, website.CONSUMED, website.SESSIONS):
            table.clear()
        self.site = website.app.test_client()

    def redeem(self, nonce, agent=A, proof="dev-proof"):
        return self.site.post("/redeem", headers=agent, json={"nonce": nonce, "proof": proof})

    def enter(self, agent=A):
        """Pass the entry check. Returns headers that carry the session token."""
        r = self.redeem(self.site.post("/enter", headers=agent).json["challenge"]["nonce"], agent)
        self.assertEqual(r.json["status"], "entered")
        return {**agent, "Authorization": f"ZKARMA {r.json['session_token']}"}

    def test_off_by_default(self):
        self.assertFalse(website.ENTRY_CHECK)
        self.assertEqual(self.site.get("/products").status_code, 200)
        self.assertEqual(self.site.post("/enter").status_code, 404)
        self.assertEqual(self.site.post("/enter", headers=A).status_code, 404)
        self.assertEqual(website.OPERATIONS, {})

    @patch.object(website, "ENTRY_CHECK", True)
    def test_on_shop_is_closed_until_entered(self):
        self.assertEqual(self.site.get("/products").status_code, 401)  # unsigned
        for r in (self.site.get("/products", headers=A),
                  self.site.post("/checkout", headers=A, json=WATER)):
            self.assertEqual((r.status_code, r.json["error"]), (401, "entry_required"))
        self.assertEqual(website.OPERATIONS, {})  # no order was started

    @patch.object(website, "ENTRY_CHECK", True)
    def test_on_enter_then_shop(self):
        ch = self.site.post("/enter", headers=A).json["challenge"]
        self.assertEqual(ch["operation"]["action"], "enter")
        self.assertEqual(ch["operation"]["duration_s"], website.SESSION_TTL_S)
        auth = self.enter(A)
        self.assertEqual(self.site.get("/products", headers=auth).status_code, 200)
        self.assertEqual(self.site.post("/checkout", headers=auth, json=WATER).json["status"], "placed")
        # Restricted items still need their own proof, bound to that order.
        r = self.site.post("/checkout", headers=auth, json=WINE)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.redeem(r.json["challenge"]["nonce"]).json["status"], "placed")

    @patch.object(website, "ENTRY_CHECK", True)
    def test_on_token_only_works_for_its_agent_and_time(self):
        auth = self.enter(A)
        token = auth["Authorization"].split()[1]
        tries = {"other agent": {**B, "Authorization": f"ZKARMA {token}"},
                 "wrong scheme": {**A, "Authorization": f"Bearer {token}"},
                 "made-up token": {**A, "Authorization": "ZKARMA abc"}}
        for name, headers in tries.items():
            with self.subTest(name):
                self.assertEqual(self.site.get("/products", headers=headers).json["error"], "entry_required")
        website.SESSIONS[token]["expires_at"] = 0
        self.assertEqual(self.site.get("/products", headers=auth).json["error"], "entry_required")

    @patch.object(website, "ENTRY_CHECK", True)
    def test_on_bad_proof_or_reused_entry_gets_no_session(self):
        op_id = self.site.post("/enter", headers=A).json["challenge"]["op_id"]

        def fresh_nonce():
            return self.site.post(f"/operations/{op_id}/challenge", headers=A).json["challenge"]["nonce"]

        with patch.object(website.proofs, "verify", return_value=False):
            r = self.redeem(fresh_nonce(), proof="not-a-proof")
        self.assertEqual((r.status_code, r.json["error"]), (403, "proof_invalid"))
        self.assertEqual(website.SESSIONS, {})
        self.assertEqual(self.redeem(fresh_nonce()).json["status"], "entered")
        r = self.redeem(fresh_nonce())  # same entry again
        self.assertEqual((r.status_code, r.json["error"]), (409, "already_consumed"))
        self.assertEqual(len(website.SESSIONS), 1)


if __name__ == "__main__":
    unittest.main()
