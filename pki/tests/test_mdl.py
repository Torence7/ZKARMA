"""Unit tests for zkarma_pki.mdl (no Longfellow needed).   Run:  python -m pytest -q

The Longfellow round trips live in integration/test_mdl_longfellow.py.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import cbor2
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zkarma_pki import PKI, Role, TrustStore, VerificationError, generate_key  # noqa: E402
from zkarma_pki.mdl import (DOC_TYPE, NAMESPACE, Mdl, MdlIssuer,  # noqa: E402
                            default_elements, device_authentication_bytes, verified_issuer_coords,
                            verify_device_response)

REPO = ROOT.parent
LONGFELLOW_VECTORS = sorted((REPO / "zk" / "testdata").glob("plus18_mdoc_*.json"))
NOW = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
NOW_S = "2026-11-26T12:00:00Z"


def transcript(nonce: bytes = bytes(32), agent: str = "agent-jkt", site="http://127.0.0.1:5050"):
    """Same shape as spec.build_transcript: [null, null, ["ZKARMAv1", sha256(...)]]."""
    inner = hashlib.sha256(cbor2.dumps([site, nonce, agent, b"\x11" * 32])).digest()
    return cbor2.dumps([None, None, ["ZKARMAv1", inner]])


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    pki = PKI.create(tmp_path_factory.mktemp("pki"))
    trust = TrustStore.from_bundle(pki.base / "trust_bundle")
    issuer = MdlIssuer.from_pki(pki, clock=lambda: NOW)
    return pki, trust, issuer


@pytest.fixture
def mdl(world):
    return world[2].issue_to_new_device(birth_date=date(2000, 1, 1))


def check(resp, tr, trust, **kw):
    return verify_device_response(resp, tr, now=kw.pop("now", NOW_S), trust=trust,
                                  attributes=kw.pop("attributes", {"age_over_18": True}), **kw)


# ----------------------------------------------------------------------------- honest path
def test_issue_present_verify(world, mdl):
    _, trust, _ = world
    tr = transcript()
    out = check(mdl.present(tr), tr, trust)
    assert out["elements"] == {"age_over_18": True}
    assert out["issuer"] == "test-dmv"
    assert out["valid_from"] == "2026-11-26T11:59:00Z"          # backdated by CLOCK_SKEW


def test_selective_disclosure(world, mdl):
    tr = transcript()
    doc = cbor2.loads(mdl.present(tr))["documents"][0]
    names = [cbor2.loads(i.value)["elementIdentifier"]
             for i in doc["issuerSigned"]["nameSpaces"][NAMESPACE]]
    assert names == ["age_over_18"]                        # nothing else leaves the wallet
    all_items = check(mdl.present(tr, reveal=None), tr, world[1], attributes={})
    assert set(all_items["elements"]) == {"family_name", "given_name", "birth_date",
                                          "issuing_country", "age_over_18", "age_over_21"}


def test_each_challenge_gets_its_own_device_signature(world, mdl):
    a, b = transcript(bytes(32)), transcript(b"\x01" * 32)
    ra, rb = mdl.present(a), mdl.present(b)
    check(ra, a, world[1])
    check(rb, b, world[1])
    with pytest.raises(VerificationError) as e:
        check(ra, b, world[1])                              # a's response replayed for b
    assert e.value.code == "mdl_device_signature"


@pytest.mark.parametrize("field,other", [("nonce", {"nonce": b"\x02" * 32}),
                                         ("agent", {"agent": "other-agent"}),
                                         ("site", {"site": "https://evil.test"})])
def test_transcript_binding(world, mdl, field, other):
    tr = transcript()
    with pytest.raises(VerificationError, match="mdl_device_signature"):
        check(mdl.present(tr), transcript(**other), world[1])


def test_wallet_view(mdl):
    e = mdl.elements()[NAMESPACE]
    assert e["birth_date"] == "2000-01-01" and e["age_over_18"] is True
    assert mdl.validity()["validUntil"] == "2027-11-26T11:59:00Z"


def test_save_load_roundtrip(tmp_path, world, mdl):
    p = tmp_path / "wallet" / "mdl.json"
    mdl.save(p)
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    again = Mdl.load(p)
    tr = transcript()
    check(again.present(tr), tr, world[1])


# ----------------------------------------------------------------------------- byte layout
def test_layout_matches_longfellow_vectors(mdl):
    """Same field order and encodings as Longfellow's own test mDLs, which its circuit parses."""
    ours = cbor2.loads(mdl.present(transcript()))
    theirs = cbor2.loads(bytes.fromhex(json.loads(LONGFELLOW_VECTORS[0].read_text())["mdoc_hex"]))
    assert list(ours) == list(theirs) == ["version", "documents", "status"]
    od, td = ours["documents"][0], theirs["documents"][0]
    assert list(od) == list(td)
    assert list(od["issuerSigned"]) == list(td["issuerSigned"])
    assert list(od["deviceSigned"]) == list(td["deviceSigned"])
    assert od["deviceSigned"]["nameSpaces"] == td["deviceSigned"]["nameSpaces"]
    item_o = cbor2.loads(od["issuerSigned"]["nameSpaces"][NAMESPACE][0].value)
    item_t = cbor2.loads(td["issuerSigned"]["nameSpaces"][NAMESPACE][0].value)
    assert list(item_o) == list(item_t) and len(item_o["random"]) == len(item_t["random"])
    mso_o = cbor2.loads(cbor2.loads(od["issuerSigned"]["issuerAuth"][2]).value)
    mso_t = cbor2.loads(cbor2.loads(td["issuerSigned"]["issuerAuth"][2]).value)
    assert list(mso_o) == list(mso_t)
    assert list(mso_o["deviceKeyInfo"]["deviceKey"]) == list(mso_t["deviceKeyInfo"]["deviceKey"])
    assert list(mso_o["validityInfo"]) == list(mso_t["validityInfo"])
    assert od["issuerSigned"]["issuerAuth"][0] == td["issuerSigned"]["issuerAuth"][0]   # {1: -7}


def test_dates_are_20_char_tdate(mdl):
    raw = cbor2.loads(mdl.issuer_signed)["issuerAuth"][2]
    mso_bytes = cbor2.loads(raw).value
    for key in (b"validFrom", b"validUntil", b"signed"):
        i = mso_bytes.index(key) + len(key)
        assert mso_bytes[i:i + 2] == b"\xc0\x74"           # tag 0, text(20)


# ----------------------------------------------------------------------------- reference verifier vs Longfellow's data
@pytest.mark.parametrize("path", LONGFELLOW_VECTORS, ids=lambda p: p.stem)
def test_reference_verifier_accepts_longfellow_vectors(path):
    """Cross-check: device_authentication_bytes() and the verifier reproduce the
    signatures in mDLs produced by an independent implementation."""
    from cryptography.hazmat.primitives.asymmetric import ec
    v = json.loads(path.read_text())
    pub = ec.EllipticCurvePublicNumbers(int(v["issuer_pkx"], 16), int(v["issuer_pky"], 16),
                                        ec.SECP256R1()).public_key()
    out = verify_device_response(bytes.fromhex(v["mdoc_hex"]), bytes.fromhex(v["transcript_hex"]),
                                 now=v["now"], issuer_public_key=pub,
                                 attributes={"age_over_18": True}, doc_type=v["doc_type"])
    assert out["elements"]["age_over_18"] is True


# ----------------------------------------------------------------------------- what must fail
def test_untrusted_issuer(world, tmp_path):
    evil = MdlIssuer.from_pki(PKI.create(tmp_path / "evil"), clock=lambda: NOW)
    m = evil.issue_to_new_device()
    tr = transcript()
    with pytest.raises(VerificationError) as e:
        check(m.present(tr), tr, world[1])
    assert e.value.code == "bad_chain"


def test_non_issuer_cert_cannot_sign_mdls(world):
    pki, trust, _ = world
    cert, key = pki.issue(Role.WEBSITE, "https://shop.test")
    m = MdlIssuer(key, cert, clock=lambda: NOW).issue_to_new_device()
    tr = transcript()
    with pytest.raises(VerificationError) as e:
        check(m.present(tr), tr, trust)
    assert e.value.code == "wrong_role"


def test_revoked_issuer(tmp_path):
    pki = PKI.create(tmp_path / "pki")
    issuer = MdlIssuer.from_pki(pki, clock=lambda: NOW)
    m = issuer.issue_to_new_device()
    pki.revoke(Role.ISSUER, issuer.cert)
    trust = TrustStore.from_bundle(pki.base / "trust_bundle")
    with pytest.raises(VerificationError, match="revoked"):
        tr = transcript()
        check(m.present(tr), tr, trust)


def test_under_18(world):
    m = world[2].issue_to_new_device(birth_date=date(2012, 6, 1))
    assert m.elements()[NAMESPACE]["age_over_18"] is False
    tr = transcript()
    with pytest.raises(VerificationError, match="mdl_attribute"):
        check(m.present(tr), tr, world[1])


@pytest.mark.parametrize("now", ["2026-11-26T11:58:59Z", "2027-11-26T11:59:01Z"])
def test_outside_validity(world, mdl, now):
    tr = transcript()
    with pytest.raises(VerificationError, match="mdl_validity"):
        check(mdl.present(tr), tr, world[1], now=now)


def test_wrong_device_key(world, mdl):
    """A thief with the issuer-signed data but not the device key."""
    thief = Mdl(mdl.issuer_signed, generate_key())
    tr = transcript()
    with pytest.raises(VerificationError, match="mdl_device_signature"):
        check(thief.present(tr), tr, world[1])


def test_tampered_element_value(world):
    tr = transcript()
    minor = world[2].issue_to_new_device(birth_date=date(2012, 6, 1))
    resp = cbor2.loads(minor.present(tr))
    items = resp["documents"][0]["issuerSigned"]["nameSpaces"][NAMESPACE]
    d = cbor2.loads(items[0].value)
    d["elementValue"] = True                                 # minor flips age_over_18 to true
    items[0] = cbor2.CBORTag(24, cbor2.dumps(d))
    with pytest.raises(VerificationError, match="mdl_digest"):
        check(cbor2.dumps(resp), tr, world[1])


def test_tampered_mso(world, mdl):
    tr = transcript()
    resp = cbor2.loads(mdl.present(tr))
    auth = resp["documents"][0]["issuerSigned"]["issuerAuth"]
    mso = cbor2.loads(cbor2.loads(auth[2]).value)
    mso["validityInfo"]["validUntil"] = cbor2.CBORTag(0, "2099-01-01T00:00:00Z")
    auth[2] = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))
    with pytest.raises(VerificationError, match="mdl_issuer_signature"):
        check(cbor2.dumps(resp), tr, world[1])


def test_device_auth_rejects_non_cbor_transcript():
    with pytest.raises(VerificationError):
        device_authentication_bytes(b"\x83\xf6")             # truncated array
    with pytest.raises(VerificationError):
        device_authentication_bytes(transcript() + b"\x00")  # trailing byte


def test_issue_input_checks(world):
    issuer = world[2]
    with pytest.raises(ValueError):
        issuer.issue(generate_key().public_key(), {})
    with pytest.raises(ValueError):
        issuer.issue(generate_key().public_key(), {f"e{i}": True for i in range(8)})  # Longfellow limit
    with pytest.raises(ValueError):
        issuer.issue(generate_key().public_key(), valid_from=NOW, valid_until=NOW)


def test_verifier_issuer_key_comes_from_trust(world, mdl):
    c = verified_issuer_coords(mdl.issuer_cert, world[1], expected_name="test-dmv")
    assert c["issuer_pkx"] == mdl.issuer_coords()["issuer_pkx"] and len(c["issuer_pkx"]) == 66


def test_default_elements_age_flags():
    e = default_elements(birth_date=date(2008, 11, 26), issue_date=date(2026, 11, 26))
    assert e["age_over_18"] is True and e["age_over_21"] is False
    e = default_elements(birth_date=date(2008, 11, 27), issue_date=date(2026, 11, 26))
    assert e["age_over_18"] is False
    e = default_elements(birth_date=date(2006, 2, 28), issue_date=date(2024, 2, 29))  # leap-day issue
    assert e["age_over_18"] is True
    e = default_elements(birth_date=date(2004, 2, 29), issue_date=date(2025, 2, 28))  # not 21 until Mar 1
    assert e["age_over_21"] is False
