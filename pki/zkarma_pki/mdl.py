"""Test mobile driving licences (ISO/IEC 18013-5 mdoc) issued by the PKI's test DMV.

Why this exists: Longfellow proves facts about an mDL whose device key signed
DeviceAuthentication over a *session transcript*. The test mDLs that ship with
Longfellow were signed over their own fixed transcripts and we hold neither
their issuer nor their device private keys, so they can't be bound to a
ZKARMA challenge. Here the test DMV (an issuer-role certificate from this PKI)
signs the Mobile Security Object, and the wallet holds the device key, so the
wallet can sign DeviceAuth over spec.build_transcript(...) for every challenge.

    issuer = MdlIssuer.from_pki(pki)                       # DMV: PKI issuer key + cert
    mdl = issuer.issue_to_new_device(birth_date=date(2000, 1, 1))   # wallet keeps `mdl`
    mdoc = mdl.present(transcript)                         # DeviceResponse, DeviceAuth over transcript
    zkage.prove(mdoc, **mdl.issuer_coords(), transcript=..., now=...)  # Longfellow

Structures (CBOR, ISO 18013-5 section 8.3 / 9.1):

    IssuerSignedItemBytes = #6.24(bstr .cbor {digestID, random, elementIdentifier, elementValue})
    MobileSecurityObject  = {version, digestAlgorithm, docType, valueDigests,
                             deviceKeyInfo: {deviceKey: COSE_Key}, validityInfo}
    issuerAuth            = COSE_Sign1(protected {1: -7}, unprotected {33: x5chain},
                                       payload #6.24(bstr .cbor MSO), ES256 signature)
    DeviceAuthentication  = ["DeviceAuthentication", SessionTranscript, DocType,
                             #6.24(bstr .cbor {})]
    deviceSignature       = COSE_Sign1(protected {1: -7}, {}, null (detached),
                                       ES256 over #6.24(bstr .cbor DeviceAuthentication))
    DeviceResponse        = {version, documents: [{docType, issuerSigned, deviceSigned}], status}

Field order and encodings follow Longfellow's own test mDLs byte for byte
(tests/test_mdl.py checks this module against them), because Longfellow's
circuit parses these exact layouts.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)

from .keys import PrivateKey, PublicKey, generate_key, load_cert, load_private_key
from .roles import Role
from .trust import TrustStore, VerificationError

DOC_TYPE = "org.iso.18013.5.1.mDL"
NAMESPACE = "org.iso.18013.5.1"
MSO_VERSION = "1.0"
COSE_ALG_ES256 = -7
COSE_HEADER_ALG = 1
COSE_HEADER_X5CHAIN = 33
TAG_TDATE = 0          # RFC 8949 date/time string, "YYYY-MM-DDTHH:MM:SSZ"
TAG_FULL_DATE = 1004   # RFC 8943 full-date, "YYYY-MM-DD"
TAG_CBOR = 24          # embedded CBOR data item
DEFAULT_VALIDITY = timedelta(days=365)
# Backdate "signed"/"validFrom" like the CA backdates certificates: Longfellow
# rejects now < validFrom, so a wallet or website clock a second behind the
# DMV's would otherwise refuse a freshly issued mDL.
CLOCK_SKEW = timedelta(minutes=1)
# Longfellow's v1 circuit hashes the whole MSO inside the proof, so its size is
# bounded. The MSO grows ~35 bytes per element (one digest each). Measured with
# zkage (Longfellow rev 1424f50, zk-spec 7): 7 elements (MSO 553 B) prove, 8
# elements (MSO 588 B) fail with "GeneralFailure". Refuse at issuance instead.
MAX_ELEMENTS = 7

_PROTECTED_ES256 = cbor2.dumps({COSE_HEADER_ALG: COSE_ALG_ES256})
_EMPTY_DEVICE_NAMESPACES = cbor2.CBORTag(TAG_CBOR, cbor2.dumps({}))


# ---------------------------------------------------------------------------- encoding helpers
_TDATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _utc_second(when: datetime) -> datetime:
    """Aware UTC datetime truncated to the second. Naive datetimes are refused:
    datetime.utcnow() on a non-UTC laptop would silently shift validity."""
    if not isinstance(when, datetime) or when.tzinfo is None:
        raise ValueError("use timezone-aware datetimes, e.g. datetime.now(timezone.utc)")
    return when.astimezone(timezone.utc).replace(microsecond=0)


def tdate(when: datetime) -> cbor2.CBORTag:
    """tdate as Longfellow expects it: tag 0, exactly 20 characters, UTC, no fraction."""
    return cbor2.CBORTag(TAG_TDATE, _utc_second(when).strftime("%Y-%m-%dT%H:%M:%SZ"))


def full_date(d: date) -> cbor2.CBORTag:
    return cbor2.CBORTag(TAG_FULL_DATE, d.isoformat())


def _plain(v: Any) -> Any:
    """Decoded CBOR value -> plain Python: cbor2 turns tag 0 into datetime and
    tag 1004 into date; give back the strings that were signed."""
    if isinstance(v, cbor2.CBORTag):
        return v.value
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, date):
        return v.isoformat()
    return v


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _es256_sign(key: PrivateKey, data: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _es256_verify(pub: PublicKey, sig: bytes, data: bytes) -> bool:
    if not isinstance(sig, bytes) or len(sig) != 64:
        return False
    try:
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                   data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    """COSE Sig_structure for COSE_Sign1 with empty external_aad (RFC 9052 section 4.4)."""
    return cbor2.dumps(["Signature1", protected, b"", payload])


def cose_key(pub: PublicKey) -> dict:
    """COSE_Key for a P-256 public key, in Longfellow's field order."""
    n = pub.public_numbers()
    return {1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


def public_key_from_cose(k: Any) -> PublicKey:
    try:
        if k[1] != 2 or k[-1] != 1:
            raise ValueError("not an EC2 P-256 COSE key")
        x, y = int.from_bytes(k[-2], "big"), int.from_bytes(k[-3], "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except (KeyError, TypeError, ValueError) as e:
        raise VerificationError("malformed", f"device key: {e}") from e


def issuer_coords(pub: PublicKey) -> dict:
    """{"issuer_pkx", "issuer_pky"} in the 0x-hex form zkage and website/proofs.py use."""
    n = pub.public_numbers()
    return {"issuer_pkx": f"0x{n.x:064x}", "issuer_pky": f"0x{n.y:064x}"}


def _one_cbor_item(data: bytes, what: str) -> Any:
    """Decode exactly one CBOR data item (no trailing bytes)."""
    if not isinstance(data, (bytes, bytearray)):
        raise VerificationError("malformed", f"{what} is not bytes")
    fp = io.BytesIO(data)
    try:
        item = cbor2.CBORDecoder(fp).decode()
    except Exception as e:  # noqa: BLE001  any decode failure is malformed input
        raise VerificationError("malformed", f"{what}: {e}") from e
    if fp.tell() != len(data):
        raise VerificationError("malformed", f"{what}: trailing bytes")
    return item


def device_authentication_bytes(transcript: bytes, doc_type: str = DOC_TYPE) -> bytes:
    """#6.24(bstr .cbor DeviceAuthentication), with the transcript embedded byte for byte.

    `transcript` is the CBOR-encoded SessionTranscript (spec.build_transcript
    returns exactly that). It is spliced in unchanged rather than decoded and
    re-encoded, so the device key signs the same bytes the verifier hashes."""
    _one_cbor_item(transcript, "session transcript")
    da = (b"\x84" + cbor2.dumps("DeviceAuthentication") + bytes(transcript)
          + cbor2.dumps(doc_type) + cbor2.dumps(_EMPTY_DEVICE_NAMESPACES))
    return cbor2.dumps(cbor2.CBORTag(TAG_CBOR, da))


# ---------------------------------------------------------------------------- default holder data
def default_elements(birth_date: date = date(2000, 1, 1), issue_date: date | None = None,
                     family_name: str = "Doe", given_name: str = "Alex",
                     issuing_country: str = "US") -> dict:
    """A small, realistic set of mDL data elements. age_over_NN follow from birth_date."""
    issue_date = issue_date or _now().date()

    def over(years: int) -> bool:
        try:
            cutoff = issue_date.replace(year=issue_date.year - years)
        except ValueError:                      # 29 February
            cutoff = issue_date.replace(year=issue_date.year - years, day=28)
        return birth_date <= cutoff

    return {"family_name": family_name, "given_name": given_name,
            "birth_date": full_date(birth_date), "issuing_country": issuing_country,
            "age_over_18": over(18), "age_over_21": over(21)}


# ---------------------------------------------------------------------------- issuer (DMV)
class MdlIssuer:
    """The test DMV. Signs MSOs with the PKI's issuer-role key and attaches its
    certificate (x5chain), so verifiers can check it against the trust bundle."""

    def __init__(self, key: PrivateKey, cert: x509.Certificate,
                 clock: Callable[[], datetime] = _now):
        if key.public_key().public_numbers() != cert.public_key().public_numbers():
            raise ValueError("issuer certificate does not match issuer key")
        self.key, self.cert, self.clock = key, cert, clock

    @classmethod
    def from_pki(cls, pki, name: str = "test-dmv", **kw) -> "MdlIssuer":
        """Use (or create) the PKI's issuer-role entity `name`."""
        d = Path(pki.base) / "issued" / Role.ISSUER.value / name
        if (d / "key.pem").exists():
            return cls(load_private_key(d / "key.pem"), load_cert(d / "cert.pem"), **kw)
        if (d / "cert.pem").exists():
            # Issued with --pubkey: the key lives elsewhere. Re-issuing would
            # replace the certificate every website already trusts.
            raise FileNotFoundError(f"{d / 'cert.pem'} exists but its key.pem does not; "
                                    "use MdlIssuer.from_files(key, cert)")
        cert, key = pki.issue(Role.ISSUER, name)
        return cls(key, cert, **kw)

    @classmethod
    def from_files(cls, key_path, cert_path, **kw) -> "MdlIssuer":
        return cls(load_private_key(Path(key_path)), load_cert(Path(cert_path)), **kw)

    def issue(self, device_public_key: PublicKey, elements: dict | None = None, *,
              valid_from: datetime | None = None, valid_for: timedelta = DEFAULT_VALIDITY,
              valid_until: datetime | None = None, doc_type: str = DOC_TYPE,
              namespace: str = NAMESPACE) -> bytes:
        """Return IssuerSigned (CBOR bytes) binding `elements` to `device_public_key`.

        In a real deployment the wallet generates the device key in secure
        hardware and sends only the public key; this method never needs the
        private key."""
        elements = default_elements() if elements is None else dict(elements)
        if not 1 <= len(elements) <= MAX_ELEMENTS:
            raise ValueError(f"between 1 and {MAX_ELEMENTS} elements")
        if not isinstance(device_public_key, ec.EllipticCurvePublicKey) or \
                device_public_key.curve.name != "secp256r1":
            raise ValueError("device key must be P-256")
        signed = _utc_second(self.clock() - CLOCK_SKEW)
        valid_from = _utc_second(valid_from) if valid_from is not None else signed
        valid_until = _utc_second(valid_until) if valid_until is not None else valid_from + valid_for
        if valid_until <= valid_from:
            raise ValueError("valid_until must be after valid_from (at one-second resolution)")
        if not all(isinstance(k, str) and k for k in elements):
            raise ValueError("element identifiers must be non-empty strings")

        ids = list(range(len(elements)))
        secrets.SystemRandom().shuffle(ids)    # digest IDs don't reveal element order
        items, digests = [], {}
        for digest_id, (name, value) in zip(ids, elements.items()):
            item = cbor2.CBORTag(TAG_CBOR, cbor2.dumps({
                "digestID": digest_id, "random": secrets.token_bytes(16),
                "elementIdentifier": name, "elementValue": value}))
            items.append(item)
            digests[digest_id] = hashlib.sha256(cbor2.dumps(item)).digest()

        mso = {"version": MSO_VERSION, "digestAlgorithm": "SHA-256", "docType": doc_type,
               "valueDigests": {namespace: digests},
               "deviceKeyInfo": {"deviceKey": cose_key(device_public_key)},
               "validityInfo": {"signed": tdate(signed), "validFrom": tdate(valid_from),
                                "validUntil": tdate(valid_until)}}
        payload = cbor2.dumps(cbor2.CBORTag(TAG_CBOR, cbor2.dumps(mso)))
        x5chain = self.cert.public_bytes(serialization.Encoding.DER)
        issuer_auth = [_PROTECTED_ES256, {COSE_HEADER_X5CHAIN: x5chain}, payload,
                       _es256_sign(self.key, _sig_structure(_PROTECTED_ES256, payload))]
        return cbor2.dumps({"nameSpaces": {namespace: items}, "issuerAuth": issuer_auth})

    def issue_to_new_device(self, elements: dict | None = None, *, birth_date: date | None = None,
                            **kw) -> "Mdl":
        """Test convenience: make a device key and issue to it, as one wallet would."""
        if elements is None and birth_date is not None:
            elements = default_elements(birth_date=birth_date, issue_date=self.clock().date())
        device_key = generate_key()
        doc_type = kw.get("doc_type", DOC_TYPE)
        return Mdl(self.issue(device_key.public_key(), elements, **kw), device_key, doc_type)


# ---------------------------------------------------------------------------- holder (wallet)
@dataclass
class Mdl:
    """A wallet-held mDL: the issuer-signed data plus the device private key."""
    issuer_signed: bytes
    device_key: PrivateKey
    doc_type: str = DOC_TYPE

    def __post_init__(self):
        """Catch a wallet file whose private key isn't the MSO's device key now,
        rather than as an opaque Longfellow "GeneralFailure" at proving time."""
        mso_key = public_key_from_cose(self.mso()["deviceKeyInfo"]["deviceKey"])
        if mso_key.public_numbers() != self.device_key.public_key().public_numbers():
            raise ValueError("device_key does not match the device key in the mDL's MSO")
        if self.mso().get("docType") != self.doc_type:
            raise ValueError(f"doc_type {self.doc_type!r} != MSO docType {self.mso().get('docType')!r}")

    # ---- reading
    def _parsed(self) -> dict:
        return _one_cbor_item(self.issuer_signed, "IssuerSigned")

    def mso(self) -> dict:
        return _mso(self._parsed()["issuerAuth"])

    @property
    def issuer_cert(self) -> x509.Certificate:
        return x509.load_der_x509_certificate(self._parsed()["issuerAuth"][1][COSE_HEADER_X5CHAIN])

    def issuer_coords(self) -> dict:
        """Issuer key for zkage, read from the mDL's own x5chain. Fine for the
        wallet's prover input; a VERIFIER must take the issuer key from the
        trust bundle instead (see verified_issuer_coords)."""
        return issuer_coords(self.issuer_cert.public_key())

    def elements(self) -> dict:
        """{namespace: {elementIdentifier: elementValue}}, for the wallet UI."""
        out: dict = {}
        for ns, items in self._parsed()["nameSpaces"].items():
            for item in items:
                d = cbor2.loads(item.value)
                out.setdefault(ns, {})[d["elementIdentifier"]] = _plain(d["elementValue"])
        return out

    def validity(self) -> dict:
        v = self.mso()["validityInfo"]
        return {k: _plain(x) for k, x in v.items()}

    # ---- presenting
    def present(self, transcript: bytes, reveal: tuple[str, ...] | None = ("age_over_18",),
                namespace: str = NAMESPACE) -> bytes:
        """DeviceResponse for this challenge: the device key signs DeviceAuthentication
        over `transcript`. Only the `reveal` elements are included (None = all).
        The result is the `mdoc` argument of client/zkage.prove()."""
        issuer_signed = self._parsed()
        items = issuer_signed["nameSpaces"].get(namespace, [])
        if reveal is not None:
            wanted = set(reveal)
            items = [i for i in items if cbor2.loads(i.value)["elementIdentifier"] in wanted]
            found = {cbor2.loads(i.value)["elementIdentifier"] for i in items}
            if found != wanted:
                raise ValueError(f"mDL has no element(s) {sorted(wanted - found)}")
        signature = _es256_sign(self.device_key, _sig_structure(
            _PROTECTED_ES256, device_authentication_bytes(transcript, self.doc_type)))
        document = {
            "docType": self.doc_type,
            "issuerSigned": {"nameSpaces": {namespace: items}, "issuerAuth": issuer_signed["issuerAuth"]},
            "deviceSigned": {"nameSpaces": _EMPTY_DEVICE_NAMESPACES,
                             "deviceAuth": {"deviceSignature": [_PROTECTED_ES256, {}, None, signature]}},
        }
        return cbor2.dumps({"version": MSO_VERSION, "documents": [document], "status": 0})

    # ---- storage (test wallet only: a real device key never leaves secure hardware)
    def to_json(self) -> dict:
        return {"format": "zkarma-test-mdl-1", "doc_type": self.doc_type,
                "issuer_signed_hex": self.issuer_signed.hex(),
                "device_key_pem": self.device_key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()).decode()}

    @classmethod
    def from_json(cls, d: dict) -> "Mdl":
        if d.get("format") != "zkarma-test-mdl-1":
            raise ValueError("not a zkarma test mDL file")
        key = serialization.load_pem_private_key(d["device_key_pem"].encode(), password=None)
        return cls(bytes.fromhex(d["issuer_signed_hex"]), key, d.get("doc_type", DOC_TYPE))

    def save(self, path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # never world-readable
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(self.to_json(), indent=2))
        p.chmod(0o600)                                                   # if it already existed

    @classmethod
    def load(cls, path) -> "Mdl":
        return cls.from_json(json.loads(Path(path).read_text()))


# ---------------------------------------------------------------------------- verification
def _mso(issuer_auth: Any) -> dict:
    try:
        tagged = _one_cbor_item(issuer_auth[2], "MSO payload")
        if not (isinstance(tagged, cbor2.CBORTag) and tagged.tag == TAG_CBOR):
            raise VerificationError("malformed", "MSO payload is not tag 24")
        return _one_cbor_item(tagged.value, "MSO")
    except (KeyError, TypeError, IndexError) as e:
        raise VerificationError("malformed", f"issuerAuth: {e}") from e


def verified_issuer_coords(issuer_cert: x509.Certificate | bytes | str, trust: TrustStore,
                           expected_name: str | None = None) -> dict:
    """The DMV key for a VERIFIER (website/proofs.py): only from an issuer-role
    certificate that chains to the trust bundle and isn't revoked."""
    if isinstance(issuer_cert, list):          # ISO 18013-5 allows x5chain as an array
        issuer_cert = issuer_cert[0] if issuer_cert else b""
    if isinstance(issuer_cert, (bytes, bytearray)) and not bytes(issuer_cert).startswith(b"-----"):
        try:
            issuer_cert = x509.load_der_x509_certificate(bytes(issuer_cert))
        except Exception as e:  # noqa: BLE001  e.g. InvalidVersion is not a ValueError
            raise VerificationError("malformed", f"issuer certificate: {e}") from e
    ident = trust.verify(issuer_cert, Role.ISSUER, expected_name=expected_name)
    return {**issuer_coords(ident.public_key), "issuer": ident.name}


def verify_device_response(device_response: bytes, transcript: bytes, *, now: str | datetime,
                           trust: TrustStore | None = None, issuer_public_key: PublicKey | None = None,
                           attributes: dict | None = None, namespace: str = NAMESPACE,
                           doc_type: str = DOC_TYPE) -> dict:
    """Plain (NOT zero-knowledge) reference check of what Longfellow proves:

      1. issuerAuth is a valid ES256 signature by the issuer (from the trust
         bundle via x5chain, or `issuer_public_key`),
      2. each disclosed item's digest is in the MSO,
      3. validFrom <= now <= validUntil,
      4. the device key in the MSO signed DeviceAuthentication over `transcript`,
      5. the disclosed elements have the requested values.

    For tests and debugging only: a website must never see the mdoc itself.
    Returns {"elements": {...}, "issuer": ...}; raises VerificationError, and
    only VerificationError, for any bad input."""
    if isinstance(now, datetime):
        now = tdate(now).value
    if not (isinstance(now, str) and _TDATE_RE.match(now)):
        raise ValueError(f"now must be 'YYYY-MM-DDTHH:MM:SSZ', got {now!r}")
    if trust is None and issuer_public_key is None:
        raise ValueError("pass trust= or issuer_public_key=")
    try:
        return _verify_device_response(device_response, transcript, now, trust, issuer_public_key,
                                       attributes or {}, namespace, doc_type)
    except VerificationError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, cbor2.CBORError) as e:
        raise VerificationError("malformed", f"{type(e).__name__}: {e}") from e


def _same_value(got: Any, want: Any) -> bool:
    """Type-strict equality: Longfellow compares CBOR bytes, and in Python 1 == True."""
    return type(got) is type(want) and got == want


def _verify_device_response(device_response, transcript, now, trust, issuer_public_key,
                            attributes, namespace, doc_type) -> dict:
    resp = _one_cbor_item(device_response, "DeviceResponse")
    try:
        if resp["version"] != MSO_VERSION or resp["status"] != 0 or len(resp["documents"]) != 1:
            raise VerificationError("malformed", "unexpected DeviceResponse header")
        doc = resp["documents"][0]
        if doc["docType"] != doc_type:
            raise VerificationError("mdl_doctype", f"{doc['docType']!r}")
        issuer_auth = doc["issuerSigned"]["issuerAuth"]
        items = doc["issuerSigned"]["nameSpaces"].get(namespace, [])
        dsig = doc["deviceSigned"]["deviceAuth"]["deviceSignature"]
        # DeviceAuthentication is signed over EMPTY DeviceNameSpaces; anything else
        # here would be device-asserted data the signature doesn't cover.
        if doc["deviceSigned"]["nameSpaces"] != _EMPTY_DEVICE_NAMESPACES:
            raise VerificationError("malformed", "deviceSigned nameSpaces must be #6.24(<<{}>>)")
        protected, unprotected, payload, signature = issuer_auth
        dprotected, _, dpayload, dsignature = dsig
    except (KeyError, TypeError, ValueError) as e:
        raise VerificationError("malformed", f"DeviceResponse: {e}") from e

    # 1. issuer signature
    if _one_cbor_item(protected, "issuerAuth protected header") != {COSE_HEADER_ALG: COSE_ALG_ES256}:
        raise VerificationError("malformed", "issuerAuth alg is not ES256")
    issuer_name = None
    if trust is not None:
        info = verified_issuer_coords(unprotected.get(COSE_HEADER_X5CHAIN, b""), trust)
        issuer_name = info["issuer"]
        n = (int(info["issuer_pkx"], 16), int(info["issuer_pky"], 16))
        issuer_public_key = ec.EllipticCurvePublicNumbers(*n, ec.SECP256R1()).public_key()
    if not _es256_verify(issuer_public_key, signature, _sig_structure(protected, payload)):
        raise VerificationError("mdl_issuer_signature", "MSO not signed by the issuer")
    mso = _mso(issuer_auth)
    if mso.get("docType") != doc_type or mso.get("digestAlgorithm") != "SHA-256":
        raise VerificationError("mdl_doctype", "MSO docType/digest algorithm")

    # 2. digests of disclosed items
    digests = mso["valueDigests"].get(namespace, {})
    elements = {}
    for item in items:
        if not (isinstance(item, cbor2.CBORTag) and item.tag == TAG_CBOR):
            raise VerificationError("malformed", "IssuerSignedItem is not tag 24")
        d = _one_cbor_item(item.value, "IssuerSignedItem")
        if digests.get(d.get("digestID")) != hashlib.sha256(cbor2.dumps(item)).digest():
            raise VerificationError("mdl_digest", f"{d.get('elementIdentifier')!r} not in MSO")
        elements[d["elementIdentifier"]] = _plain(d["elementValue"])

    # 3. validity
    v = mso["validityInfo"]
    vf, vu = _plain(v["validFrom"]), _plain(v["validUntil"])
    if not (vf <= now <= vu):
        raise VerificationError("mdl_validity", f"{now} not in [{vf}, {vu}]")

    # 4. device signature over the transcript (detached payload)
    if dpayload is not None or \
            _one_cbor_item(dprotected, "deviceSignature protected header") != {COSE_HEADER_ALG: COSE_ALG_ES256}:
        raise VerificationError("malformed", "deviceSignature header/payload")
    device_pub = public_key_from_cose(mso["deviceKeyInfo"]["deviceKey"])
    if not _es256_verify(device_pub, dsignature,
                         _sig_structure(dprotected, device_authentication_bytes(transcript, doc_type))):
        raise VerificationError("mdl_device_signature", "DeviceAuth does not cover this transcript")

    # 5. requested values
    for name, want in attributes.items():
        if name not in elements or not _same_value(elements[name], want):
            raise VerificationError("mdl_attribute", f"{name} != {want!r}")
    return {"elements": elements, "issuer": issuer_name, "valid_from": vf, "valid_until": vu}
