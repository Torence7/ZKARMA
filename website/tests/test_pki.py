"""The website with Kaustubh's PKI on (ZKARMA_PKI_DIR): agent signatures,
signed challenges and status, and the DMV key from its certificate.

Run: python -m unittest discover -s website/tests -v
"""
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import cryptography  # noqa: F401  (pip install -r website/requirements.txt)
except ImportError:
    raise unittest.SkipTest("the PKI tests need the cryptography package") from None

os.environ["ZKARMA_DEV"] = "1"
for var in ("ZKARMA_PKI_DIR", "ZKARMA_ENTRY_CHECK"):
    os.environ.pop(var, None)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # website/

import app as website  # noqa: E402
import site_pki  # noqa: E402  (also puts pki/ and spec/ on the path)
from spec.zkarma_spec import signed_payload  # noqa: E402
from zkarma_pki import PKI, Role, TrustStore, canonical_encode, sign, verify_with_cert  # noqa: E402
from zkarma_pki.keys import b64u, b64u_decode  # noqa: E402
from zkarma_pki.signing import PURPOSE_CHALLENGE  # noqa: E402

WINE = {"item_id": "wine-001", "quantity": 1}


def signature_header(agent, method, path, body=b"", created=None,
                     purpose=site_pki.PURPOSE_HTTP_REQUEST, target=None):
    """What a PKI agent sends (same format as Kaustubh's AgentRequestSigner)."""
    cert, key = agent
    payload = {"method": method, "target": target or website.ORIGIN + path,
               "body_sha256": hashlib.sha256(body).hexdigest(),
               "created": int(time.time()) if created is None else created, "nonce": os.urandom(16).hex()}
    return {site_pki.SIGNATURE_HEADER: b64u(canonical_encode(sign(key, purpose, payload, cert=cert)))}


class PKIMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name) / "pki_out"
        cls.pki = PKI.create(cls.dir)
        cls.web = cls.pki.issue(Role.WEBSITE, website.ORIGIN)
        cls.dmv_cert, _ = cls.pki.issue(Role.ISSUER, "test-dmv")
        cls.a1, cls.a2 = cls.pki.issue(Role.AGENT, "agent-1"), cls.pki.issue(Role.AGENT, "agent-2")
        cls.trust = TrustStore.from_bundle(cls.dir / "trust_bundle")  # what the wallet has

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        for table in (website.OPERATIONS, website.NONCES, website.CONSUMED, website.SESSIONS):
            table.clear()
        for name, value in (("SITE_PKI", site_pki.SitePKI(self.dir, website.ORIGIN)), ("DEV", False)):
            p = patch.object(website, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.site = website.app.test_client()

    def call(self, path, body=None, agent=None, headers=None, **sig):
        raw = b"" if body is None else json.dumps(body).encode()
        h = signature_header(agent or self.a1, "POST", path, raw, **sig) if headers is None else headers
        return self.site.post(path, data=raw, headers={**h, "Content-Type": "application/json"})

    def wallet_check(self, message):
        """What the wallet does with a website signature (Kaustubh's verify_website_message)."""
        env = json.loads(b64u_decode(message["signature"]))
        payload, _ = verify_with_cert(env, self.trust, Role.WEBSITE, PURPOSE_CHALLENGE,
                                      expected_name=website.ORIGIN)
        return payload["msg_sha256"] == hashlib.sha256(signed_payload(message)).hexdigest()

    def test_signed_order_goes_through(self):
        r = self.call("/checkout", WINE)
        self.assertEqual(r.status_code, 401)
        ch = r.json["challenge"]
        self.assertTrue(self.wallet_check(ch))
        changed = {**ch, "operation": {**ch["operation"], "quantity": 10}}
        self.assertFalse(self.wallet_check(changed))  # the agent can't edit a signed challenge
        self.assertEqual(website.OPERATIONS[ch["op_id"]]["agent_jkt"], site_pki.jwk_thumbprint(self.a1[0].public_key()))
        with patch.object(website.proofs, "verify", return_value=True) as zk:
            r = self.call("/redeem", {"nonce": ch["nonce"], "proof": "a-real-proof"})
        self.assertEqual(r.json["status"], "placed")
        n = self.dmv_cert.public_key().public_numbers()
        self.assertEqual(zk.call_args.args[3], {"pkx": "0x" + n.x.to_bytes(32, "big").hex(),
                                                "pky": "0x" + n.y.to_bytes(32, "big").hex()})

    def test_bad_signatures_are_refused(self):
        other_root = PKI.create(Path(self.tmp.name) / "rogue").issue(Role.AGENT, "agent-1")
        body = json.dumps(WINE).encode()
        cases = {
            "missing": {},
            "malformed": {site_pki.SIGNATURE_HEADER: "not-a-signature"},
            "wrong_target": signature_header(self.a1, "POST", "/products", body),
            "body_mismatch": signature_header(self.a1, "POST", "/checkout", b'{"item_id": "water-001"}'),
            "expired": signature_header(self.a1, "POST", "/checkout", body, created=int(time.time()) - 120),
            "bad_signature": signature_header(self.a1, "POST", "/checkout", body, purpose=PURPOSE_CHALLENGE),
            "wrong_role": signature_header(self.web, "POST", "/checkout", body),
            "bad_chain": signature_header(other_root, "POST", "/checkout", body),
        }
        cases["wrong_target (other site)"] = signature_header(
            self.a1, "POST", "/checkout", body, target="http://other.test/checkout")
        cases["missing (dev header, dev mode off)"] = {"X-Dev-Agent-Thumbprint": "agent-1"}
        for reason, headers in cases.items():
            with self.subTest(reason):
                r = self.call("/checkout", WINE, headers=headers)
                self.assertEqual((r.status_code, r.json["error"], r.json["reason"]),
                                 (401, "bad_signature", reason.split(" (")[0]))
        self.assertEqual(website.OPERATIONS, {})

    def test_same_signed_request_works_once(self):
        headers = signature_header(self.a1, "POST", "/checkout", json.dumps(WINE).encode())
        self.assertEqual(self.call("/checkout", WINE, headers=headers).status_code, 401)  # challenge
        self.assertEqual(self.call("/checkout", WINE, headers=headers).json["reason"], "replay")

    def test_bad_signature_never_falls_back_to_dev_header(self):
        with patch.object(website, "DEV", True):
            r = self.call("/checkout", WINE, headers={site_pki.SIGNATURE_HEADER: "junk",
                                                      "X-Dev-Agent-Thumbprint": "agent-1"})
            self.assertEqual(r.json["reason"], "malformed")
            r = self.call("/checkout", WINE, headers={"X-Dev-Agent-Thumbprint": "agent-1"})
            self.assertEqual(r.json["error"], "age_check_required")  # dev mode still works

    def test_other_agent_cannot_redeem(self):
        ch = self.call("/checkout", WINE).json["challenge"]
        r = self.call("/redeem", {"nonce": ch["nonce"], "proof": "x"}, agent=self.a2)
        self.assertEqual((r.status_code, r.json["error"]), (403, "wrong_agent"))

    def test_revoked_agent_is_refused_while_running(self):
        agent = self.pki.issue(Role.AGENT, "agent-revoked")
        self.assertEqual(self.call("/checkout", WINE, agent=agent).json["error"], "age_check_required")
        self.pki.revoke(Role.AGENT, agent[0])
        self.assertEqual(self.call("/checkout", WINE, agent=agent).json["reason"], "revoked")
        self.assertEqual(self.call("/checkout", WINE).json["error"], "age_check_required")  # agent-1 is fine

    def test_retry_status_is_signed(self):
        ch = self.call("/checkout", WINE).json["challenge"]
        with patch.object(website.proofs, "verify", return_value=True):
            self.call("/redeem", {"nonce": ch["nonce"], "proof": "a-real-proof"})
        status = self.call(f"/operations/{ch['op_id']}/challenge").json["status"]
        self.assertEqual((status["v"], status["op_id"], status["status"], status["consumed"]),
                         ("zkarma-status-1", ch["op_id"], "placed", True))
        self.assertTrue(self.wallet_check(status))

    def test_revoked_dmv_is_refused(self):
        dmv2, _ = self.pki.issue(Role.ISSUER, "dmv-2")
        with patch.object(website, "SITE_PKI", site_pki.SitePKI(self.dir, website.ORIGIN, dmv="dmv-2")):
            ch = self.call("/checkout", WINE).json["challenge"]
            self.pki.revoke(Role.ISSUER, dmv2)
            with patch.object(website.proofs, "verify", return_value=True) as zk:
                r = self.call("/redeem", {"nonce": ch["nonce"], "proof": "a-real-proof"})
        self.assertEqual((r.status_code, r.json["error"], r.json["reason"]), (403, "issuer_untrusted", "revoked"))
        zk.assert_not_called()

    def test_site_needs_its_own_certificate(self):
        with self.assertRaises(SystemExit) as e:
            site_pki.SitePKI(self.dir, "http://localhost:9999")
        self.assertIn("issue", str(e.exception))

    def test_pki_off_leaves_challenges_unsigned(self):
        with patch.object(website, "SITE_PKI", None), patch.object(website, "DEV", True):
            r = self.site.post("/checkout", json=WINE, headers={"X-Dev-Agent-Thumbprint": "agent-1"})
        self.assertNotIn("signature", r.json["challenge"])


if __name__ == "__main__":
    unittest.main()
