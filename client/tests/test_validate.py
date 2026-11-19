"""Challenge and status checks, with nothing running."""
import time
import unittest
from unittest import mock

import helpers  # noqa: F401

from config import spec
from validate import Refused, check_status, validate_challenge

ORIGIN = "http://localhost:5050"


def make_challenge(**op_changes):
    op = {"v": "zkarma-op-1", "site": ORIGIN, "action": "checkout", "op_id": "a" * 32,
          "item_id": "wine-001", "item_name": "Red wine, 750 ml", "quantity": 1,
          "amount_cents": 1999, "currency": "USD", **op_changes}
    return {"op_id": op["op_id"], "operation": op, "operation_hash": spec.operation_hash(op).hex(),
            "nonce": "11" * 32, "now": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "origin": ORIGIN, "claim": "age_over_18", "expires_in": 120, "redeem": "/redeem"}


class Challenge(unittest.TestCase):
    def refused(self, ch, reason, origins=(ORIGIN,)):
        with self.assertRaises(Refused) as cm:
            validate_challenge(ch, list(origins))
        self.assertEqual(cm.exception.reason, reason)

    def test_good_unsigned_in_dev(self):
        self.assertFalse(validate_challenge(make_challenge(), [ORIGIN]))

    def test_good_signed(self):
        ch = make_challenge()
        ch["signature"] = spec.stub_sign(ch)
        self.assertTrue(validate_challenge(ch, [ORIGIN]))

    def test_unsigned_outside_dev(self):
        with mock.patch("validate.DEV", False):
            self.refused(make_challenge(), "unsigned")

    def test_bad_signature(self):
        ch = make_challenge()
        ch["signature"] = spec.stub_sign(ch)
        ch["operation"]["quantity"] = 5
        ch["operation_hash"] = spec.operation_hash(ch["operation"]).hex()
        self.refused(ch, "bad_website_signature")

    def test_agent_changed_operation(self):
        ch = make_challenge()
        ch["operation"]["quantity"] = 10  # hash left as the site sent it
        self.refused(ch, "operation_hash_mismatch")

    def test_origin_not_allowed(self):
        self.refused(make_challenge(), "origin_not_allowed", origins=())

    def test_operation_for_other_site(self):
        self.refused(make_challenge(site="https://evil.example"), "operation_mismatch")

    def test_op_id_mismatch(self):
        ch = make_challenge()
        ch["op_id"] = "b" * 32
        self.refused(ch, "operation_mismatch")

    def test_unknown_action(self):
        self.refused(make_challenge(action="transfer"), "unknown_action")

    def test_bool_quantity(self):
        self.refused(make_challenge(quantity=True), "bad_operation")

    def test_bad_nonce(self):
        ch = make_challenge()
        ch["nonce"] = "xyz"
        self.refused(ch, "bad_challenge")

    def test_long_lived_challenge(self):
        ch = make_challenge()
        ch["expires_in"] = 10 ** 6
        self.refused(ch, "bad_challenge")

    def test_clock_skew(self):
        ch = make_challenge()
        ch["now"] = "2001-01-01T00:00:00Z"
        self.refused(ch, "clock_skew")

    def test_unsupported_claim(self):
        ch = make_challenge()
        ch["claim"] = "age_over_21"
        self.refused(ch, "claim_not_supported")

    def test_not_a_dict(self):
        self.refused(None, "bad_challenge")


def make_status(**changes):
    return {"v": "zkarma-status-1", "site": ORIGIN, "op_id": "a" * 32, "status": "placed",
            "consumed": True, "issued_at": int(time.time()), **changes}


class Status(unittest.TestCase):
    def test_signed(self):
        s = make_status()
        s["signature"] = spec.stub_sign(s)
        r = check_status(s, ORIGIN, "a" * 32)
        self.assertEqual((r["ok"], r["signed"], r["consumed"]), (True, True, True))

    def test_none(self):
        self.assertEqual(check_status(None, ORIGIN, "a" * 32)["problem"], "none provided")

    def test_other_operation(self):
        r = check_status(make_status(op_id="b" * 32), ORIGIN, "a" * 32)
        self.assertEqual(r["problem"], "not for this operation")

    def test_stale(self):
        r = check_status(make_status(issued_at=int(time.time()) - 3600), ORIGIN, "a" * 32)
        self.assertEqual(r["problem"], "stale")

    def test_forged(self):
        s = make_status(consumed=False)
        s["signature"] = spec.stub_sign(make_status())  # signature for consumed=True
        self.assertEqual(check_status(s, ORIGIN, "a" * 32)["problem"], "bad_website_signature")

    def test_unsigned_outside_dev(self):
        with mock.patch("validate.DEV", False):
            self.assertEqual(check_status(make_status(), ORIGIN, "a" * 32)["problem"], "unsigned")


if __name__ == "__main__":
    unittest.main()
