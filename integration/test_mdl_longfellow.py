"""Real Longfellow proofs over a test mDL issued by the PKI's test DMV.

The wallet side is client/zkage.py (Prithvi's prover wrapper) fed by
zkarma_pki.mdl; the website side is the real, unmodified website/proofs.py with
the DMV key written from the PKI-verified issuer certificate. Skipped unless
zkage is built (zk/README.md).

    python -m pytest -q integration/test_mdl_longfellow.py
"""
from __future__ import annotations

import json
import tempfile
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

import integration.harness  # noqa: F401  (import paths)
import proofs as website_proofs  # website/proofs.py
import zkage  # client/zkage.py
from integration.harness import System
from integration.mdl_adapters import CLAIMS, make_wallet_prover, write_issuer_pub
from spec.zkarma_spec import build_transcript, operation_hash
from zkarma_pki import PKI, TrustStore, generate_key
from zkarma_pki.mdl import Mdl, MdlIssuer

pytestmark = pytest.mark.skipif(not zkage.available(), reason="zkage not built; see zk/README.md")

SITE = "http://127.0.0.1:5050"
AGENT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"   # an RFC 7638 thumbprint, as in PKI mode
REPO = Path(__file__).resolve().parents[1]


def op(op_id="a" * 32, quantity=1):
    return {"v": "zkarma-op-1", "site": SITE, "action": "checkout", "op_id": op_id,
            "item_id": "wine-001", "item_name": "Red wine, 750 ml", "quantity": quantity,
            "amount_cents": 1999 * quantity, "currency": "USD"}


def transcript(nonce=bytes(32), agent=AGENT, operation=None, origin=SITE):
    return build_transcript(origin, nonce, agent, operation_hash(operation or op()))


def utc(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    d = tmp_path_factory.mktemp("w")
    pki = PKI.create(d / "pki")
    trust = TrustStore.from_bundle(pki.base / "trust_bundle")
    issuer = MdlIssuer.from_pki(pki)
    issuer_pub = write_issuer_pub(d / "trust" / "issuer_pub.json", trust, issuer.cert)
    adult = issuer.issue_to_new_device(birth_date=date(2000, 1, 1))
    return {"pki": pki, "trust": trust, "issuer": issuer, "issuer_pub": issuer_pub, "adult": adult,
            "now": utc(datetime.now(timezone.utc))}


def website_verify(world, proof_hex, tr, now=None):
    """The website's real verifier, pointed at our zkage and the PKI-derived DMV key."""
    with mock.patch.object(website_proofs, "ZKAGE", zkage.ZKAGE), \
            mock.patch.object(website_proofs, "CIRCUITS", zkage.CIRCUITS), \
            mock.patch.object(website_proofs, "ISSUER_PUB", world["issuer_pub"]):
        return website_proofs.verify(proof_hex, tr, now or world["now"])


def prove(world, mdl, tr, now=None):
    return make_wallet_prover(mdl, zkage)(tr, now or world["now"], "age_over_18")


@pytest.fixture(scope="module")
def honest(world):
    tr = transcript()
    return tr, prove(world, world["adult"], tr)


# ----------------------------------------------------------------------------- the goal
def test_wallet_proof_accepted_by_website(world, honest):
    tr, proof = honest
    assert website_verify(world, proof, tr)
    assert json.loads(world["issuer_pub"].read_text())["issuer"] == "test-dmv"


@pytest.mark.parametrize("what,other", [
    ("nonce", {"nonce": b"\x01" * 32}),
    ("agent", {"agent": "another-agent-thumbprint"}),
    ("operation", {"operation": op(quantity=10)}),
    ("origin", {"origin": "https://evil.test"}),
])
def test_proof_bound_to_challenge(world, honest, what, other):
    """A proof works for exactly one (site, nonce, agent, operation)."""
    _, proof = honest
    assert not website_verify(world, proof, transcript(**other))


def test_retry_gets_fresh_proof_old_one_dead(world, honest):
    """Semantic-replay fix building block: the website re-challenges the SAME
    operation with a new nonce; the wallet re-signs DeviceAuth and proves again.
    The new proof verifies, the old one does not."""
    _, first = honest
    retry_tr = transcript(nonce=b"\x07" * 32)                    # same op_id, new nonce
    second = prove(world, world["adult"], retry_tr)
    assert website_verify(world, second, retry_tr)
    assert not website_verify(world, first, retry_tr)
    assert first != second


def test_age_over_21_claim(world):
    tr = transcript()
    proof = make_wallet_prover(world["adult"], zkage)(tr, world["now"], "age_over_21")
    c = world["adult"].issuer_coords()
    assert zkage.verify(proof, c["issuer_pkx"], c["issuer_pky"], tr, world["now"], CLAIMS["age_over_21"])
    assert not zkage.verify(proof, c["issuer_pkx"], c["issuer_pky"], tr, world["now"], CLAIMS["age_over_18"])


# ----------------------------------------------------------------------------- what must fail
def test_under_18_cannot_prove(world):
    minor = world["issuer"].issue_to_new_device(birth_date=date(2012, 6, 1))
    with pytest.raises(zkage.ZkageError):
        prove(world, minor, transcript())


def test_untrusted_dmv_rejected_by_website(world, tmp_path):
    """An attacker-run 'DMV' can issue a perfectly formed mDL; the website's DMV
    key comes from the PKI, so the proof doesn't verify."""
    evil = MdlIssuer.from_pki(PKI.create(tmp_path / "evil")).issue_to_new_device()
    tr = transcript()
    proof = prove(world, evil, tr)                                # proves under the evil key
    assert not website_verify(world, proof, tr)


@pytest.mark.parametrize("offset", [timedelta(days=-1), timedelta(days=400)])
def test_outside_validity_cannot_prove(world, offset):
    when = utc(datetime.now(timezone.utc) + offset)
    with pytest.raises(zkage.ZkageError):
        prove(world, world["adult"], transcript(), now=when)


def test_stolen_issuer_data_without_device_key(world):
    """Copying the issuer-signed mDL is useless without the wallet's device key."""
    thief = Mdl(world["adult"].issuer_signed, generate_key())
    tr = transcript()
    try:
        proof = prove(world, thief, tr)
    except zkage.ZkageError:
        return
    assert not website_verify(world, proof, tr)


def test_longfellow_test_mdl_cannot_bind_to_our_challenge(world):
    """The original problem: Longfellow's shipped test mDLs only prove against
    their own fixed transcript."""
    case = json.loads((REPO / "zk" / "testdata" / "plus18_mdoc_0.json").read_text())
    with pytest.raises(zkage.ZkageError):
        zkage.prove(bytes.fromhex(case["mdoc_hex"]), case["issuer_pkx"], case["issuer_pky"],
                    transcript(), case["now"])


def test_issuer_refuses_mdl_longfellow_cannot_prove(world):
    with pytest.raises(ValueError):
        world["issuer"].issue(generate_key().public_key(), {f"e{i}": True for i in range(8)})


# ----------------------------------------------------------------------------- whole system
def test_full_system_purchase_with_real_proof():
    """Agent -> website -> wallet -> website over HTTP, PKI mode, real Longfellow."""
    with tempfile.TemporaryDirectory() as d, System(d, mode="pki", proof="real") as s:
        a = s.safe_agent()
        a.browse_products()
        t = time.perf_counter()
        r = a.purchase("wine-001", 1)
        assert r["status"] == "placed"
        assert s.proof_checks == {"ok": 1}
        assert s.prove_metrics[0]["proof_bytes"] > 100_000
        assert time.perf_counter() - t < 30


def test_full_system_minor_gets_no_order():
    with tempfile.TemporaryDirectory() as d, \
            System(d, mode="pki", proof="real", mdl_birth_date=date(2012, 6, 1)) as s:
        a = s.safe_agent()
        a.browse_products()
        with pytest.raises(Exception, match="Wallet could not generate the proof"):
            a.purchase("wine-001", 1)
        assert not s.proof_checks                                  # nothing reached the website
        placed = [r for r in s.website.OPERATIONS.values() if r["status"] == "placed"]
        assert placed == []
