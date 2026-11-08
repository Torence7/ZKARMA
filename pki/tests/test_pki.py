"""Unit tests for zkarma_pki.   Run:  python -m pytest -q"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))

from zkarma_pki import (PKI, PURPOSE_AUTHORIZATION, PURPOSE_CHALLENGE,  # noqa: E402
                        CanonicalEncodingError, ClientKeyRegistry, ClientKeyring, Role,
                        TrustStore, VerificationError, canonical_encode, generate_key, sign,
                        verify, verify_with_cert)
from zkarma_pki.keys import cert_to_pem  # noqa: E402

SHOP = "https://shop.test"


@pytest.fixture
def pki(tmp_path):
    return PKI.create(tmp_path / "pki")


@pytest.fixture
def trust(pki):
    return TrustStore.from_bundle(pki.base / "trust_bundle")


def code_of(fn, *a, **kw):
    with pytest.raises(VerificationError) as e:
        fn(*a, **kw)
    return e.value.code


# ---------------------------------------------------------------- canonical
class TestCanonical:
    def test_key_order_and_whitespace(self):
        assert canonical_encode({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'

    def test_same_bytes_regardless_of_insertion_order(self):
        assert canonical_encode({"x": 1, "y": {"q": 2, "p": 3}}) == \
               canonical_encode({"y": {"p": 3, "q": 2}, "x": 1})

    def test_unicode_is_utf8_not_escaped(self):
        assert canonical_encode({"k": "é"}) == '{"k":"é"}'.encode()

    def test_utf16_key_ordering(self):
        # U+10000 (surrogate pair D800..) sorts before U+FFFF in UTF-16 order (JCS rule)
        out = canonical_encode({"￿": 1, "\U00010000": 2}).decode()
        assert out.index("\U00010000") < out.index("￿")

    @pytest.mark.parametrize("bad", [1.5, {"a": float("nan")}, {1: "x"}, b"bytes", 2**60])
    def test_rejects_unsafe_values(self, bad):
        with pytest.raises(CanonicalEncodingError):
            canonical_encode(bad)


# ---------------------------------------------------------------- signing
class TestSigning:
    def test_roundtrip(self):
        k = generate_key()
        env = sign(k, PURPOSE_CHALLENGE, {"a": 1})
        assert verify(env, k.public_key(), PURPOSE_CHALLENGE) == {"a": 1}
        assert len(env["sig"]) == 86  # 64 raw bytes, base64url

    def test_tampered_payload(self):
        k = generate_key()
        env = sign(k, PURPOSE_CHALLENGE, {"a": 1})
        env["payload"]["a"] = 2
        assert code_of(verify, env, k.public_key(), PURPOSE_CHALLENGE) == "bad_signature"

    def test_purpose_separation(self):
        k = generate_key()
        env = sign(k, PURPOSE_CHALLENGE, {"a": 1})
        assert code_of(verify, env, k.public_key(), PURPOSE_AUTHORIZATION) == "bad_signature"
        env["purpose"] = PURPOSE_AUTHORIZATION   # relabelling doesn't help either
        assert code_of(verify, env, k.public_key(), PURPOSE_AUTHORIZATION) == "bad_signature"

    def test_wrong_key(self):
        env = sign(generate_key(), PURPOSE_CHALLENGE, {"a": 1})
        assert code_of(verify, env, generate_key().public_key(), PURPOSE_CHALLENGE) == "bad_key"

    def test_payload_copied_at_sign_time(self):
        k, p = generate_key(), {"a": {"b": 1}}
        env = sign(k, PURPOSE_CHALLENGE, p)
        p["a"]["b"] = 2
        assert verify(env, k.public_key(), PURPOSE_CHALLENGE) == {"a": {"b": 1}}

    def test_cert_must_match_key(self, pki):
        cert, _ = pki.issue(Role.AGENT, "agent-1")
        with pytest.raises(ValueError):
            sign(generate_key(), PURPOSE_CHALLENGE, {}, cert=cert)


# ---------------------------------------------------------------- trust store
class TestTrust:
    def test_valid_identities(self, pki, trust):
        for role, name in [(Role.AGENT, "agent-1"), (Role.WEBSITE, SHOP), (Role.ISSUER, "dmv")]:
            cert, _ = pki.issue(role, name)
            ident = trust.verify(cert, role, expected_name=name)
            assert ident.name == name and ident.role is role

    @pytest.mark.parametrize("issued,expected", [(Role.AGENT, Role.WEBSITE),
                                                 (Role.WEBSITE, Role.AGENT),
                                                 (Role.AGENT, Role.ISSUER)])
    def test_role_confusion(self, pki, trust, issued, expected):
        cert, _ = pki.issue(issued, SHOP if issued is Role.WEBSITE else "x")
        assert code_of(trust.verify, cert, expected) == "wrong_role"

    def test_foreign_ca(self, tmp_path, trust):
        evil = PKI.create(tmp_path / "evil")
        cert, _ = evil.issue(Role.AGENT, "agent-1")
        assert code_of(trust.verify, cert, Role.AGENT) == "bad_chain"

    def test_foreign_root_bundle_rejected(self, tmp_path, pki):
        evil = PKI.create(tmp_path / "evil")
        b = pki.base / "trust_bundle"
        (b / "agent_ca.pem").write_bytes((evil.base / "trust_bundle/agent_ca.pem").read_bytes())
        assert code_of(TrustStore.from_bundle, b) == "bad_chain"

    def test_ca_cert_cannot_be_leaf(self, pki, trust):
        assert code_of(trust.verify, pki.cas[Role.AGENT].cert, Role.AGENT) == "wrong_role"

    def test_expiry(self, pki, trust):
        cert, _ = pki.issue(Role.AGENT, "agent-1", ttl=timedelta(hours=1))
        later = datetime.now(timezone.utc) + timedelta(hours=2)
        assert code_of(trust.verify, cert, Role.AGENT, at=later, require_crl=False) == "expired"

    def test_stale_crl_fails_closed(self, pki, trust):
        cert, _ = pki.issue(Role.AGENT, "agent-1", ttl=timedelta(days=5))
        later = datetime.now(timezone.utc) + timedelta(days=2)
        assert code_of(trust.verify, cert, Role.AGENT, at=later) == "stale_crl"

    def test_revocation_and_crl_update(self, pki, trust):
        cert, _ = pki.issue(Role.AGENT, "agent-1")
        trust.verify(cert, Role.AGENT)
        pki.revoke(Role.AGENT, cert)
        trust.update_crl(Role.AGENT, (pki.base / "ca/agent/crl.pem").read_bytes())
        assert code_of(trust.verify, cert, Role.AGENT) == "revoked"

    def test_crl_rollback_refused(self, pki, trust):
        old = (pki.base / "ca/agent/crl.pem").read_bytes()
        cert, _ = pki.issue(Role.AGENT, "agent-1")
        pki.revoke(Role.AGENT, cert)
        trust.update_crl(Role.AGENT, (pki.base / "ca/agent/crl.pem").read_bytes())
        assert code_of(trust.update_crl, Role.AGENT, old) == "bad_crl"

    def test_forged_crl_refused(self, tmp_path, trust):
        evil = PKI.create(tmp_path / "evil")
        assert code_of(trust.update_crl, Role.AGENT,
                       (evil.base / "ca/agent/crl.pem").read_bytes()) == "bad_crl"

    def test_name_mismatch(self, pki, trust):
        cert, _ = pki.issue(Role.WEBSITE, SHOP)
        assert code_of(trust.verify, cert, Role.WEBSITE,
                       expected_name="https://evil.test") == "name_mismatch"

    def test_malformed_pem(self, trust):
        assert code_of(trust.verify, "not a cert", Role.AGENT) == "malformed"

    @pytest.mark.parametrize("bad", ["shop.test", "https://Shop.test/path", "agent 1"])
    def test_bad_website_names(self, pki, bad):
        with pytest.raises(ValueError):
            pki.issue(Role.WEBSITE, bad)

    def test_verify_with_cert(self, pki, trust):
        cert, key = pki.issue(Role.WEBSITE, SHOP)
        env = sign(key, PURPOSE_CHALLENGE, {"x": 1}, cert=cert)
        payload, ident = verify_with_cert(env, trust, Role.WEBSITE, PURPOSE_CHALLENGE, SHOP)
        assert payload == {"x": 1} and ident.name == SHOP
        a_cert, _ = pki.issue(Role.AGENT, "agent-1")
        env["cert"] = cert_to_pem(a_cert)
        assert code_of(verify_with_cert, env, trust, Role.WEBSITE, PURPOSE_CHALLENGE) == "wrong_role"

    def test_reload_persists(self, pki):
        cert, _ = pki.issue(Role.AGENT, "agent-1")
        again = PKI.load(pki.base)
        again.revoke(Role.AGENT, cert)
        t = TrustStore.from_bundle(pki.base / "trust_bundle")
        assert code_of(t.verify, cert, Role.AGENT) == "revoked"


# ---------------------------------------------------------------- client keys
class TestRegistry:
    def test_pairwise_keys_differ(self):
        ring = ClientKeyring()
        a = ring.registration_for(SHOP)["kid"]
        b = ring.registration_for("https://other.test")["kid"]
        assert a != b and ring.registration_for(SHOP)["kid"] == a

    def test_register_and_get(self):
        ring, reg = ClientKeyring(), ClientKeyRegistry(SHOP)
        kid = reg.register(ring.registration_for(SHOP))
        assert kid in reg and reg.get(kid)

    def test_wrong_site(self):
        reg = ClientKeyRegistry(SHOP)
        assert code_of(reg.register, ClientKeyring().registration_for("https://other.test")) \
            == "name_mismatch"

    def test_replayed_registration(self):
        ring, reg = ClientKeyring(), ClientKeyRegistry(SHOP)
        env = ring.registration_for(SHOP)
        reg.register(env)
        assert code_of(reg.register, env) == "replay"

    def test_stale_registration(self):
        env = ClientKeyring().registration_for(SHOP)
        reg = ClientKeyRegistry(SHOP)
        assert code_of(reg.register, env, now=env["payload"]["issued_at"] + 3600) == "expired"

    def test_swapped_public_key(self):
        env = ClientKeyring().registration_for(SHOP)
        env["payload"]["public_key"] = ClientKeyring().registration_for(SHOP)["payload"]["public_key"]
        assert code_of(ClientKeyRegistry(SHOP).register, env) in {"bad_key", "bad_signature"}

    def test_unknown_and_revoked(self):
        ring, reg = ClientKeyring(), ClientKeyRegistry(SHOP)
        assert code_of(reg.get, "nope") == "bad_key"
        kid = reg.register(ring.registration_for(SHOP))
        reg.revoke(kid)
        assert code_of(reg.get, kid) == "revoked"

    def test_keyring_persists(self, tmp_path):
        a = ClientKeyring(tmp_path).registration_for(SHOP)["kid"]
        assert ClientKeyring(tmp_path).registration_for(SHOP)["kid"] == a


# ---------------------------------------------------------------- directory service
def test_directory_service(pki):
    from fastapi.testclient import TestClient
    from zkarma_pki.directory import create_app
    from cryptography.hazmat.primitives import serialization

    pki.issue(Role.AGENT, "agent-1")
    c = TestClient(create_app(pki.base, "s3cret"))
    assert c.get("/health").json() == {"ok": True}
    assert "BEGIN CERTIFICATE" in c.get("/trust/root").text
    assert "BEGIN X509 CRL" in c.get("/trust/crl/agent").text
    assert c.get("/agents/agent-1/cert").status_code == 200
    assert c.get("/agents/nobody/cert").status_code == 404

    pub = generate_key().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    body = {"role": "agent", "name": "agent-9", "public_key_pem": pub}
    assert c.post("/admin/issue", json=body).status_code == 401
    r = c.post("/admin/issue", json=body, headers={"X-Admin-Token": "s3cret"})
    assert r.status_code == 200
    trust = TrustStore.from_bundle(pki.base / "trust_bundle")
    trust.verify(r.json()["cert_pem"], Role.AGENT, expected_name="agent-9")

    assert c.post("/admin/revoke", json={"role": "agent", "name": "agent-9"},
                  headers={"X-Admin-Token": "s3cret"}).status_code == 200
    trust.update_crl(Role.AGENT, c.get("/trust/crl/agent").text)
    assert code_of(trust.verify, r.json()["cert_pem"], Role.AGENT) == "revoked"


# ---------------------------------------------------------------- end-to-end demo
def test_demo_scenarios_all_pass():
    import run_demo
    results = run_demo.run_all()
    failed = [r.name for r in results if not r.passed]
    assert not failed, failed
