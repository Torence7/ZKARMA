"""Checkout policy is owned by the website, independently of the agent."""
import unittest

import helpers  # noqa: F401
import app as website


class CheckoutPolicy(unittest.TestCase):
    def setUp(self):
        for table in (website.OPERATIONS, website.NONCES, website.CONSUMED):
            table.clear()
        self.site = website.app.test_client()
        self.headers = {"X-Dev-Agent-Thumbprint": "safe-agent"}

    def test_catalog_public_and_entry_removed(self):
        result = self.site.get("/products")
        self.assertEqual(result.status_code, 200)
        items = {p["item_id"]: p for p in result.json["products"]}
        self.assertTrue(items["wine-001"]["age_restricted"])
        self.assertFalse(items["water-001"]["age_restricted"])
        self.assertEqual(self.site.post("/enter").status_code, 404)
        self.assertEqual(website.OPERATIONS, {})
        self.assertEqual(website.NONCES, {})

    def test_catalog_public_outside_dev(self):
        from unittest.mock import patch
        with patch.object(website, "DEV", False):
            self.assertEqual(self.site.get("/products").status_code, 200)
            self.assertEqual(self.site.post("/checkout", headers=self.headers).status_code, 401)

    def test_restricted_cannot_override_policy_or_price(self):
        result = self.site.post("/checkout", headers=self.headers, json={
            "item_id": "wine-001", "quantity": 2, "age_restricted": False, "amount_cents": 1})
        self.assertEqual(result.status_code, 401)
        ch = result.json["challenge"]
        self.assertEqual(ch["operation"]["amount_cents"], 3998)
        self.assertNotIn(ch["op_id"], website.CONSUMED)

    def test_unrestricted_completes_without_proof(self):
        result = self.site.post("/checkout", headers=self.headers,
                                json={"item_id": "water-001", "quantity": 1})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json["status"], "placed")
        self.assertIn(result.json["op_id"], website.CONSUMED)
        self.assertEqual(website.NONCES, {})

    def test_protected_endpoints_require_identity(self):
        for endpoint in ("/checkout", "/redeem", "/operations/test/challenge"):
            self.assertEqual(self.site.post(endpoint).status_code, 401)

    def test_refresh_requires_owner(self):
        ch = self.site.post("/checkout", headers=self.headers,
                            json={"item_id": "wine-001", "quantity": 1}).json["challenge"]
        result = self.site.post(f"/operations/{ch['op_id']}/challenge",
                                headers={"X-Dev-Agent-Thumbprint": "other"})
        self.assertEqual(result.status_code, 404)

    def test_nonce_replay_and_expiration(self):
        ch = self.site.post("/checkout", headers=self.headers,
                            json={"item_id": "wine-001", "quantity": 1}).json["challenge"]
        body = {"nonce": ch["nonce"], "proof": "dev-proof"}
        self.assertEqual(self.site.post("/redeem", headers=self.headers, json=body).status_code, 200)
        self.assertEqual(self.site.post("/redeem", headers=self.headers, json=body).status_code, 403)
        ch = self.site.post("/checkout", headers=self.headers,
                            json={"item_id": "wine-001", "quantity": 1}).json["challenge"]
        website.NONCES[ch["nonce"]]["expires_at"] = 0
        self.assertEqual(self.site.post("/redeem", headers=self.headers,
            json={"nonce": ch["nonce"], "proof": "dev-proof"}).status_code, 403)
        self.assertNotIn(ch["op_id"], website.CONSUMED)

    def test_bad_quantities(self):
        for quantity in (True, 0, -1, 11, "1", 1.5):
            with self.subTest(quantity=quantity):
                self.assertEqual(self.site.post("/checkout", headers=self.headers,
                    json={"item_id": "wine-001", "quantity": quantity}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
