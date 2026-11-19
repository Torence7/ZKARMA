"""Real Longfellow proofs: the wallet proves with client/zkage.py and the
website's own, unmodified verifier (website/proofs.py) checks them.

Uses Longfellow's test mDLs (zk/testdata/), whose device signatures cover
their own fixed transcripts. Skipped unless zkage is built (zk/README.md).
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401  (sets up the import paths)
import zkage

ROOT = Path(__file__).resolve().parents[2]
TESTDATA = ROOT / "zk" / "testdata"


def load(name: str) -> dict:
    return json.loads((TESTDATA / f"{name}.json").read_text())


@unittest.skipUnless(zkage.available(), "zkage not built; see zk/README.md")
class RealProofs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        sys.path.insert(0, str(ROOT / "website"))
        import proofs  # website/proofs.py
        cls.website_proofs = proofs
        cls.case = load("plus18_mdoc_0")
        cls.transcript = bytes.fromhex(cls.case["transcript_hex"])
        cls.proof, cls.metrics = zkage.prove(
            bytes.fromhex(cls.case["mdoc_hex"]), cls.case["issuer_pkx"], cls.case["issuer_pky"],
            cls.transcript, cls.case["now"])

    def website_verify(self, proof_hex, transcript, now, pkx=None):
        """website/proofs.verify, pointed at our binary and this case's issuer key."""
        with tempfile.TemporaryDirectory() as d:
            issuer = Path(d) / "issuer_pub.json"
            issuer.write_text(json.dumps({"pkx": pkx or self.case["issuer_pkx"],
                                          "pky": self.case["issuer_pky"]}))
            with mock.patch.object(self.website_proofs, "ZKAGE", zkage.ZKAGE), \
                    mock.patch.object(self.website_proofs, "CIRCUITS", zkage.CIRCUITS), \
                    mock.patch.object(self.website_proofs, "ISSUER_PUB", issuer):
                return self.website_proofs.verify(proof_hex, transcript, now)

    def test_website_accepts_wallet_proof(self):
        self.assertTrue(self.website_verify(self.proof, self.transcript, self.case["now"]))
        self.assertGreater(self.metrics["proof_bytes"], 0)

    def test_wallet_self_check(self):
        self.assertTrue(zkage.verify(self.proof, self.case["issuer_pkx"], self.case["issuer_pky"],
                                     self.transcript, self.case["now"]))

    def test_other_transcript_rejected(self):
        # A proof is bound to its transcript, so it can't be reused for another challenge.
        other = self.transcript[:-1] + bytes([self.transcript[-1] ^ 1])
        self.assertFalse(self.website_verify(self.proof, other, self.case["now"]))

    def test_tampered_proof_rejected(self):
        raw = bytearray.fromhex(self.proof)
        raw[len(raw) // 2] ^= 1
        self.assertFalse(self.website_verify(raw.hex(), self.transcript, self.case["now"]))

    def test_untrusted_issuer_rejected(self):
        pkx = load("plus18_mdoc_2")["issuer_pkx"]
        self.assertFalse(self.website_verify(self.proof, self.transcript, self.case["now"], pkx))

    def test_expired_credential_rejected(self):
        self.assertFalse(self.website_verify(self.proof, self.transcript, "2040-01-01T00:00:00Z"))

    def test_junk_proof_rejected(self):
        self.assertFalse(self.website_verify("00", self.transcript, self.case["now"]))

    def test_prove_with_wrong_transcript_fails(self):
        # The mdoc's device signature covers its own transcript only. This is
        # why the wallet must re-sign DeviceAuth for each ZKARMA challenge.
        with self.assertRaises(zkage.ZkageError):
            zkage.prove(bytes.fromhex(self.case["mdoc_hex"]), self.case["issuer_pkx"],
                        self.case["issuer_pky"], b"some other transcript", self.case["now"])


if __name__ == "__main__":
    unittest.main()
