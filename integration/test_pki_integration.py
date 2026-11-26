"""Pytest entry point for the integrated PKI tests.

    python -m pytest -q integration                          # PKI mode, all scenarios
    ZKARMA_MAIN_WEBSITE=/path/to/main/website/app.py python -m pytest -q integration
                                                             # also run H5 on main's website

Every scenario must be "correct" in PKI mode: honest flows complete, attacks
are refused. The contrast modes are measured by run_preliminary.py, not
asserted here (they are expected to let some attacks through).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from integration.harness import REPO, System
from integration.scenarios import SCENARIOS, run

from spec import zkarma_spec as spec  # noqa: E402  (path set by harness)
from zkarma_pki import Role, TrustStore, VerificationError, canonical_encode  # noqa: E402
from zkarma_pki.keys import cert_to_pem  # noqa: E402

from integration.pki_adapters import issuer_pub_json, jwk_thumbprint  # noqa: E402

MAIN_WEBSITE = os.environ.get("ZKARMA_MAIN_WEBSITE")
if not MAIN_WEBSITE:
    # In a main checkout (after merging this branch) main's own website is right here:
    # it has the optional /enter check (ZKARMA_ENTRY_CHECK) and website/site_pki.py.
    _here = Path(__file__).resolve().parents[1] / "website"
    if (_here / "site_pki.py").exists() and "ENTRY_CHECK" in (_here / "app.py").read_text():
        MAIN_WEBSITE = str(_here / "app.py")


@pytest.mark.parametrize("sc", SCENARIOS, ids=lambda sc: sc.id)
def test_scenario_pki(sc, tmp_path):
    website = None
    if sc.needs == "enter+session":
        if not MAIN_WEBSITE:
            pytest.skip("set ZKARMA_MAIN_WEBSITE to main's website/app.py")
        website = MAIN_WEBSITE
    r = run(sc, tmp_path, "pki", website)
    assert r.correct, r.row()


# ---------------------------------------------------------------------------
# Interop checks between the PKI and the other modules' formats
# ---------------------------------------------------------------------------
def _vectors():
    return json.loads((REPO / "spec" / "test_vectors.json").read_text(encoding="utf-8"))


def test_spec_canonical_json_matches_pki_canonical_encode_on_vectors():
    for v in _vectors():
        assert spec.canonical_json(v["operation"]) == canonical_encode(v["operation"])
        assert hashlib.sha256(canonical_encode(v["operation"])).hexdigest() == v["operation_hash"]


def test_website_operations_hash_the_same_under_both_encoders(tmp_path):
    with System(tmp_path) as s:
        a = s.raw_agent()
        for item, qty in (("wine-001", 1), ("vape-001", 3), ("wine-001", 10)):
            code, b = a.site("POST", "/checkout", {"item_id": item, "quantity": qty})
            op = b["challenge"]["operation"]
            assert spec.canonical_json(op) == canonical_encode(op)
            assert s.website.operation_hash(op) == hashlib.sha256(canonical_encode(op)).digest()


def test_encoders_diverge_outside_the_agreed_value_types():
    """Documents the edge cases where spec.canonical_json (json.dumps) and the
    PKI's RFC 8785 encoder disagree, so nobody puts these in an operation."""
    assert spec.canonical_json({"amount": 19.99})            # spec accepts floats ...
    with pytest.raises(TypeError):
        canonical_encode({"amount": 19.99})                  # ... the PKI refuses them
    astral = {"\U0001F600": 1, "｡": 2}                    # key order: code point vs UTF-16
    assert spec.canonical_json(astral) != canonical_encode(astral)


def test_agent_identity_is_rfc7638_not_pki_key_id(tmp_path):
    """The website/wallet's agent_jkt and zkarma_pki.key_id are different
    identifiers for the same key; the adapter standardises on RFC 7638."""
    from zkarma_pki import key_id
    with System(tmp_path) as s:
        creds = s.agents["safe-agent"]
        assert creds.jkt == jwk_thumbprint(creds.cert.public_key())
        assert creds.jkt != key_id(creds.cert.public_key())
        assert len(creds.jkt) == 43


def test_issuer_pub_json_comes_only_from_a_trusted_issuer_cert(tmp_path):
    with System(tmp_path) as s:
        pub = issuer_pub_json(s.trust_site, s.issuer_cert_pem)
        n = s.issuer_cert.public_key().public_numbers()
        assert pub["pkx"] == "0x" + n.x.to_bytes(32, "big").hex()
        assert pub["pky"] == "0x" + n.y.to_bytes(32, "big").hex()
        from zkarma_pki import PKI
        rogue = PKI.create(s.tmp / "rogue")
        fake_dmv, _ = rogue.issue(Role.ISSUER, "test-dmv")
        with pytest.raises(VerificationError) as e:
            issuer_pub_json(s.trust_site, cert_to_pem(fake_dmv))
        assert e.value.code == "bad_chain"
        with pytest.raises(VerificationError) as e:
            issuer_pub_json(s.trust_site, cert_to_pem(s.site_cert))   # website cert as DMV
        assert e.value.code == "wrong_role"


def test_wallet_and_website_bind_the_proof_to_the_same_agent_identity(tmp_path):
    """The website's transcript uses the agent_jkt from ITS verifier and the
    wallet's uses the one from ITS verifier. They must agree, or every honest
    proof would fail."""
    with System(tmp_path) as s:
        r = s.raw_agent().run_operation("/checkout", {"item_id": "wine-001", "quantity": 1})
        assert r["code"] == 200 and r["body"]["status"] == "placed"
        assert s.proof_checks == {"ok": 1}
