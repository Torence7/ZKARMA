"""spec/ must give exactly the bytes website/app.py uses (and the saved vectors)."""
import json
import unittest

from helpers import ROOT

import app as website  # website/app.py, read only
from config import spec


class SpecMatchesWebsite(unittest.TestCase):
    def setUp(self):
        self.vectors = json.loads((ROOT / "spec" / "test_vectors.json").read_text())

    def test_vectors(self):
        for v in self.vectors:
            op, nonce = v["operation"], bytes.fromhex(v["nonce"])
            for impl in (spec, website):
                h = impl.operation_hash(op)
                self.assertEqual(h.hex(), v["operation_hash"])
                self.assertEqual(impl.build_transcript(v["origin"], nonce, v["agent_jkt"], h).hex(),
                                 v["transcript"])

    def test_key_order_does_not_matter(self):
        op = self.vectors[1]["operation"]
        self.assertEqual(spec.operation_hash(dict(reversed(list(op.items())))),
                         spec.operation_hash(op))

    def test_stub_signature(self):
        msg = {"a": 1, "b": "x"}
        signed = {**msg, "signature": spec.stub_sign(msg)}
        self.assertTrue(spec.stub_verify(signed, signed["signature"]))
        self.assertFalse(spec.stub_verify({**signed, "a": 2}, signed["signature"]))


if __name__ == "__main__":
    unittest.main()
