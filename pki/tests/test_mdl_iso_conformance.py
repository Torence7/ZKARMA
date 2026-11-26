"""Independent ISO 18013-5 check of the PKI's test mDLs with pymdoccbor
(IdentityPython's mdoc parser/verifier, not written by us).

Optional: skipped unless `pip install pymdoccbor`. pymdoccbor checks the
issuer COSE_Sign1 signature, the element digests against the MSO and the
x5chain certificate chain (DS cert signed directly by a trusted root, so the
PKI's Issuer CA is passed as the root). It does not check the device
signature; Longfellow does that (integration/test_mdl_longfellow.py).
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import cbor2
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
pymdoc = pytest.importorskip("pymdoccbor.mdoc.verifier")

from zkarma_pki import PKI  # noqa: E402
from zkarma_pki.keys import load_cert  # noqa: E402
from zkarma_pki.mdl import NAMESPACE, MdlIssuer  # noqa: E402

TRANSCRIPT = cbor2.dumps([None, None, ["ZKARMAv1", b"\x11" * 32]])


@pytest.fixture(autouse=True)
def quiet():
    logging.disable(logging.ERROR)
    yield
    logging.disable(logging.NOTSET)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return PKI.create(tmp_path_factory.mktemp("pki"))


def issuer_ca(pki):
    return load_cert(pki.base / "ca" / "issuer" / "cert.pem")


def verify(data: bytes, roots):
    m = pymdoc.MdocCbor()
    m.loads(data)
    return m.verify(trusted_root_certs=roots), m


@pytest.mark.parametrize("reveal", [("age_over_18",), None], ids=["age_over_18", "all"])
def test_pymdoccbor_accepts_our_mdl(pki, reveal):
    mdl = MdlIssuer.from_pki(pki).issue_to_new_device()
    ok, m = verify(mdl.present(TRANSCRIPT, reveal=reveal), [issuer_ca(pki)])
    assert ok and len(m.documents) == 1
    disclosed = m.disclosure_map[NAMESPACE]
    assert disclosed["age_over_18"] is True
    assert set(disclosed) == ({"age_over_18"} if reveal else set(mdl.elements()[NAMESPACE]))


def test_pymdoccbor_rejects_other_trust_root(pki, tmp_path):
    mdl = MdlIssuer.from_pki(pki).issue_to_new_device()
    other = PKI.create(tmp_path / "other")
    ok, _ = verify(mdl.present(TRANSCRIPT), [issuer_ca(other)])
    assert not ok


def test_pymdoccbor_rejects_tampered_element(pki):
    mdl = MdlIssuer.from_pki(pki).issue_to_new_device()
    r = cbor2.loads(mdl.present(TRANSCRIPT))
    items = r["documents"][0]["issuerSigned"]["nameSpaces"][NAMESPACE]
    d = cbor2.loads(items[0].value)
    d["elementValue"] = False
    items[0] = cbor2.CBORTag(24, cbor2.dumps(d))
    ok, _ = verify(cbor2.dumps(r), [issuer_ca(pki)])
    assert not ok


def test_control_longfellow_vector(pki):
    """Sanity check of the tool itself on Longfellow's own test mDL."""
    v = json.loads((ROOT.parent / "zk" / "testdata" / "plus18_mdoc_0.json").read_text())
    ok, _ = verify(bytes.fromhex(v["mdoc_hex"]), None)
    assert ok
