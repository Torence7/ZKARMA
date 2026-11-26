"""Unit tests for zkarma_pki.mdl (no Longfellow needed).   Run:  python -m pytest -q

The Longfellow round trips live in integration/test_mdl_longfellow.py.
"""
from __future__ import annotations

import hashlib
import json
import os
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
    if os.name != "nt":                      # Windows has no Unix permission bits (always 0o666)
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


def forged_holder(issuer_signed, key):
    """A thief doesn't use our constructor's key check: build the object around it."""
    m = object.__new__(Mdl)
    m.issuer_signed, m.device_key, m.doc_type = issuer_signed, key, DOC_TYPE
    return m


def test_wallet_file_with_wrong_device_key_refused(mdl):
    with pytest.raises(ValueError, match="does not match"):
        Mdl(mdl.issuer_signed, generate_key())


def test_wrong_device_key(world, mdl):
    """A thief with the issuer-signed data but not the device key."""
    thief = forged_holder(mdl.issuer_signed, generate_key())
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


# ----------------------------------------------------------------------------- review fixes
def test_attribute_check_is_type_strict(world):
    """In Python 1 == True; Longfellow compares CBOR bytes (f5), so must we."""
    m = world[2].issue_to_new_device({"age_over_18": 1})
    tr = transcript()
    with pytest.raises(VerificationError, match="mdl_attribute"):
        check(m.present(tr), tr, world[1])


@pytest.mark.parametrize("bad_now", ["2026-11-26 12:00:00", "2026-11-26T12:00:00+00:00",
                                     "2026-11-26T12:00:00.5Z", "", None, 1795000000])
def test_now_must_be_tdate(world, mdl, bad_now):
    tr = transcript()
    with pytest.raises(ValueError):
        verify_device_response(mdl.present(tr), tr, now=bad_now, trust=world[1])


def test_naive_datetimes_refused(world):
    with pytest.raises(ValueError, match="timezone-aware"):
        world[2].issue(generate_key().public_key(), valid_from=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="timezone-aware"):
        MdlIssuer(world[2].key, world[2].cert, clock=lambda: datetime(2026, 1, 1)).issue_to_new_device()


def test_subsecond_validity_window_refused(world):
    t = datetime(2026, 1, 1, 0, 0, 0, 100, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        world[2].issue(generate_key().public_key(), valid_from=t, valid_until=t + timedelta(milliseconds=5))


def test_from_pki_never_replaces_existing_dmv_cert(tmp_path):
    pki = PKI.create(tmp_path / "pki")
    pki.issue(Role.ISSUER, "test-dmv", generate_key().public_key())   # cert only, key held elsewhere
    cert_file = pki.base / "issued" / "issuer" / "test-dmv" / "cert.pem"
    before = cert_file.read_bytes()
    with pytest.raises(FileNotFoundError):
        MdlIssuer.from_pki(pki)
    assert cert_file.read_bytes() == before


@pytest.mark.skipif(os.name == "nt", reason="Windows has no Unix permission bits")
def test_save_never_world_readable(tmp_path, mdl):
    p = tmp_path / "mdl.json"
    p.write_text("{}")
    p.chmod(0o644)                                           # pre-existing, readable file
    mdl.save(p)
    assert p.stat().st_mode & 0o077 == 0


def test_doc_type_mismatch_refused(mdl):
    with pytest.raises(ValueError, match="docType"):
        Mdl(mdl.issuer_signed, mdl.device_key, "org.example.other")


@pytest.mark.parametrize("x5chain", ["list", "empty", "garbage", "missing"])
def test_x5chain_variants(world, mdl, x5chain):
    tr = transcript()
    resp = cbor2.loads(mdl.present(tr))
    hdr = resp["documents"][0]["issuerSigned"]["issuerAuth"][1]
    if x5chain == "list":
        hdr[33] = [hdr[33]]                                  # ISO allows an array: still accepted
        check(cbor2.dumps(resp), tr, world[1])
        return
    if x5chain == "missing":
        del hdr[33]
    else:
        hdr[33] = b"" if x5chain == "empty" else b"\x30\x03\x02\x01\x00"
    with pytest.raises(VerificationError):
        check(cbor2.dumps(resp), tr, world[1])


@pytest.mark.parametrize("device_ns", ["missing", "unsigned-data"])
def test_device_namespaces_must_be_the_signed_empty_map(world, mdl, device_ns):
    tr = transcript()
    resp = cbor2.loads(mdl.present(tr))
    ds = resp["documents"][0]["deviceSigned"]
    if device_ns == "missing":
        del ds["nameSpaces"]
    else:
        ds["nameSpaces"] = cbor2.CBORTag(24, cbor2.dumps({NAMESPACE: {"age_over_18": True}}))
    with pytest.raises(VerificationError, match="malformed"):
        check(cbor2.dumps(resp), tr, world[1])


def test_fuzz_reference_verifier_only_raises_verification_error(world, mdl):
    """Flip random bytes / delete random map keys in a valid DeviceResponse.
    The verifier must reject every changed response, and only ever with
    VerificationError (never KeyError/TypeError/... nor acceptance)."""
    import random
    rng = random.Random(588)
    tr = transcript()
    good = mdl.present(tr)
    check(good, tr, world[1])
    accepted = 0
    for i in range(400):
        data = bytearray(good)
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        data = bytes(data)
        try:
            check(data, tr, world[1])
        except VerificationError:
            continue
        accepted += data != good and _semantic(data) != _semantic(good)
    assert accepted == 0

    def drop_random_key(obj):
        if isinstance(obj, dict) and obj:
            if rng.random() < 0.4:
                del obj[rng.choice(list(obj))]
                return True
            return any(drop_random_key(v) for v in obj.values())
        if isinstance(obj, list):
            return any(drop_random_key(v) for v in obj)
        return False

    for _ in range(200):
        resp = cbor2.loads(good)
        if not drop_random_key(resp):
            continue
        with pytest.raises(VerificationError):
            check(cbor2.dumps(resp), tr, world[1])


def _semantic(data):
    """What a byte flip may change without mattering: nothing the verifier reads."""
    try:
        return cbor2.dumps(cbor2.loads(data))
    except Exception:  # noqa: BLE001
        return data


# ----------------------------------------------------------------------------- CLI
def test_cli_issue_show_issuer_pub(tmp_path, capsys):
    from zkarma_pki import cli
    out = tmp_path / "pki_out"
    cli.main(["init", str(out)])
    cli.main(["mdl-issue", str(out), str(tmp_path / "adult.json")])
    cli.main(["mdl-issue", str(out), str(tmp_path / "minor.json"), "--birth-date", "2015-03-01"])
    cli.main(["mdl-issuer-pub", str(out), str(tmp_path / "trust" / "issuer_pub.json")])
    capsys.readouterr()
    cli.main(["mdl-show", str(tmp_path / "adult.json")])
    shown = json.loads(capsys.readouterr().out)
    pub = json.loads((tmp_path / "trust" / "issuer_pub.json").read_text())
    adult, minor = Mdl.load(tmp_path / "adult.json"), Mdl.load(tmp_path / "minor.json")
    assert shown["issuer_pkx"] == pub["pkx"] == adult.issuer_coords()["issuer_pkx"]
    assert adult.elements()[NAMESPACE]["age_over_18"] is True
    assert minor.elements()[NAMESPACE]["age_over_18"] is False
    trust = TrustStore.from_bundle(out / "trust_bundle")
    tr = transcript()
    verify_device_response(adult.present(tr), tr, now=datetime.now(timezone.utc), trust=trust,
                           attributes={"age_over_18": True})


def test_cli_issue_to_wallet_generated_key(tmp_path):
    """The wallet keeps its device key; the DMV only ever sees the public half."""
    from cryptography.hazmat.primitives import serialization
    from zkarma_pki import cli
    out = tmp_path / "pki_out"
    cli.main(["init", str(out)])
    device_key = generate_key()
    (tmp_path / "dev_pub.pem").write_bytes(device_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    cli.main(["mdl-issue", str(out), str(tmp_path / "issuer_signed.cbor"),
              "--device-pubkey", str(tmp_path / "dev_pub.pem")])
    mdl = Mdl((tmp_path / "issuer_signed.cbor").read_bytes(), device_key)
    tr = transcript()
    verify_device_response(mdl.present(tr), tr, now=datetime.now(timezone.utc),
                           trust=TrustStore.from_bundle(out / "trust_bundle"),
                           attributes={"age_over_18": True})
    with pytest.raises(ValueError):                       # someone else's key: refused up front
        Mdl((tmp_path / "issuer_signed.cbor").read_bytes(), generate_key())


def test_cli_thumbprint_matches_integration_adapter(tmp_path, capsys):
    """The pairing id printed by the CLI must equal the agent_jkt the website and
    wallet compute (integration/pki_adapters.jwk_thumbprint)."""
    sys.path.insert(0, str(REPO))
    from integration.pki_adapters import jwk_thumbprint
    from zkarma_pki import cli
    from zkarma_pki.keys import load_cert
    out = tmp_path / "pki_out"
    cli.main(["init", str(out)])
    capsys.readouterr()
    cert = out / "issued" / "agent" / "agent-1" / "cert.pem"
    cli.main(["thumbprint", str(cert)])
    assert capsys.readouterr().out.strip() == jwk_thumbprint(load_cert(cert).public_key())
