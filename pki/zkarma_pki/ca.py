"""Certificate authorities: one root, three role-specific intermediates.

    ZKARMA Test Root CA
     |-- ZKARMA Issuer CA   -> issuer (DMV document-signer) certificates
     |-- ZKARMA Website CA  -> one certificate per website origin
     '-- ZKARMA Agent CA    -> one short-lived certificate per agent

Client (wallet) keys are deliberately NOT certified here. A single certified
client key would let every website recognise the same user. Clients instead
register a fresh per-site key with each website (see registry.py).

On-disk layout created by `PKI.create(...)`:

    <base>/root/{key.pem,cert.pem}
    <base>/ca/<role>/{key.pem,cert.pem,crl.pem,index.json}
    <base>/issued/<role>/<name>/{cert.pem[,key.pem]}
    <base>/trust_bundle/{root.pem,<role>_ca.pem,<role>_crl.pem}

`trust_bundle/` is the ONLY thing the client and website need. It must be
installed out of band (config / registration), never fetched through an agent.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .keys import (PrivateKey, PublicKey, generate_key, load_cert, load_private_key,
                   save_cert, save_private_key)
from .roles import (AGENT_URI_PREFIX, CA_NAME, ISSUER_URI_PREFIX, ROLE_EKU, ROOT_NAME,
                    Role)

DEFAULT_TTL = {
    Role.ISSUER: timedelta(days=365),
    Role.WEBSITE: timedelta(days=90),
    # Short-lived: limits the damage window when an agent is corrupted.
    Role.AGENT: timedelta(hours=24),
}
CRL_TTL = timedelta(days=1)

_ORIGIN_RE = re.compile(r"^https?://[a-z0-9.-]+(:[0-9]{1,5})?$")
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZKARMA Prototype"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ski(pub: PublicKey) -> x509.SubjectKeyIdentifier:
    return x509.SubjectKeyIdentifier.from_public_key(pub)


def _ca_cert(subject_cn: str, pub: PublicKey, issuer_cert: x509.Certificate | None,
             issuer_key: PrivateKey, ttl: timedelta, path_length: int | None) -> x509.Certificate:
    now = _now()
    issuer_name = issuer_cert.subject if issuer_cert else _name(subject_cn)
    aki_source = issuer_cert.public_key() if issuer_cert else pub
    return (x509.CertificateBuilder()
            .subject_name(_name(subject_cn))
            .issuer_name(issuer_name)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + ttl)
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(_ski(pub), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(aki_source),
                           critical=False)
            .sign(issuer_key, hashes.SHA256()))


def subject_uri(role: Role, name: str) -> str:
    """The identity string bound into a leaf certificate's SAN."""
    if role is Role.WEBSITE:
        if not _ORIGIN_RE.match(name):
            raise ValueError(f"website name must be an origin like https://shop.test, got {name!r}")
        return name
    if not _NAME_RE.match(name):
        raise ValueError(f"{role.value} name must match {_NAME_RE.pattern}, got {name!r}")
    return (AGENT_URI_PREFIX if role is Role.AGENT else ISSUER_URI_PREFIX) + name


@dataclass
class IntermediateCA:
    role: Role
    key: PrivateKey
    cert: x509.Certificate
    dir: Path

    # ---------- issuance ----------
    def issue(self, name: str, public_key: PublicKey,
              ttl: timedelta | None = None) -> x509.Certificate:
        """Certify `public_key` for `name` in this CA's role.

        In a real deployment the subject generates its own key and sends only
        the public key (or a CSR); the CA never sees the private key.
        """
        uri = subject_uri(self.role, name)
        now = _now()
        ttl = ttl or DEFAULT_TTL[self.role]
        cert = (x509.CertificateBuilder()
                .subject_name(_name(name))
                .issuer_name(self.cert.subject)
                .public_key(public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(min(now + ttl, self.cert.not_valid_after_utc))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False,
                                             key_agreement=False, key_cert_sign=False,
                                             crl_sign=False, encipher_only=False,
                                             decipher_only=False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ROLE_EKU[self.role]]), critical=True)
                .add_extension(x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(uri)]), critical=False)
                .add_extension(_ski(public_key), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.key.public_key()), critical=False)
                .sign(self.key, hashes.SHA256()))
        self._record(cert, name)
        return cert

    # ---------- revocation ----------
    def revoke(self, serial: int, reason: x509.ReasonFlags = x509.ReasonFlags.key_compromise,
               when: datetime | None = None) -> x509.CertificateRevocationList:
        idx = self._index()
        idx["revoked"][str(serial)] = {"at": int((when or _now()).timestamp()),
                                       "reason": reason.value}
        self._save_index(idx)
        return self.write_crl()

    def write_crl(self) -> x509.CertificateRevocationList:
        idx = self._index()
        now = _now()
        b = (x509.CertificateRevocationListBuilder()
             .issuer_name(self.cert.subject)
             .last_update(now - timedelta(minutes=1))
             .next_update(now + CRL_TTL)
             .add_extension(x509.CRLNumber(idx["crl_number"]), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                 self.key.public_key()), critical=False))
        for serial, info in idx["revoked"].items():
            b = b.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(int(serial))
                .revocation_date(datetime.fromtimestamp(info["at"], timezone.utc))
                .add_extension(x509.CRLReason(x509.ReasonFlags(info["reason"])), critical=False)
                .build())
        crl = b.sign(self.key, hashes.SHA256())
        idx["crl_number"] += 1
        self._save_index(idx)
        from cryptography.hazmat.primitives.serialization import Encoding
        (self.dir / "crl.pem").write_bytes(crl.public_bytes(Encoding.PEM))
        return crl

    # ---------- bookkeeping ----------
    def _index(self) -> dict:
        p = self.dir / "index.json"
        if p.exists():
            return json.loads(p.read_text())
        return {"issued": {}, "revoked": {}, "crl_number": 1}

    def _save_index(self, idx: dict) -> None:
        (self.dir / "index.json").write_text(json.dumps(idx, indent=2))

    def _record(self, cert: x509.Certificate, name: str) -> None:
        idx = self._index()
        idx["issued"][str(cert.serial_number)] = {
            "name": name, "not_after": int(cert.not_valid_after_utc.timestamp())}
        self._save_index(idx)


class PKI:
    """Owns the root and the three intermediates, persisted under `base`."""

    def __init__(self, base: Path, root_key: PrivateKey, root_cert: x509.Certificate,
                 cas: dict[Role, IntermediateCA]):
        self.base = Path(base)
        self.root_key = root_key
        self.root_cert = root_cert
        self.cas = cas

    # ---------- construction ----------
    @classmethod
    def create(cls, base: Path | str) -> "PKI":
        base = Path(base)
        if (base / "root" / "cert.pem").exists():
            raise FileExistsError(f"a PKI already exists at {base}; use PKI.load()")
        root_key = generate_key()
        root_cert = _ca_cert(ROOT_NAME, root_key.public_key(), None, root_key,
                             timedelta(days=3650), path_length=1)
        save_private_key(root_key, base / "root" / "key.pem")
        save_cert(root_cert, base / "root" / "cert.pem")
        cas = {}
        for role in Role:
            k = generate_key()
            c = _ca_cert(CA_NAME[role], k.public_key(), root_cert, root_key,
                         timedelta(days=730), path_length=0)
            d = base / "ca" / role.value
            save_private_key(k, d / "key.pem")
            save_cert(c, d / "cert.pem")
            cas[role] = IntermediateCA(role, k, c, d)
            cas[role].write_crl()
        pki = cls(base, root_key, root_cert, cas)
        pki.export_trust_bundle()
        return pki

    @classmethod
    def load(cls, base: Path | str) -> "PKI":
        base = Path(base)
        cas = {}
        for role in Role:
            d = base / "ca" / role.value
            cas[role] = IntermediateCA(role, load_private_key(d / "key.pem"),
                                       load_cert(d / "cert.pem"), d)
        return cls(base, load_private_key(base / "root" / "key.pem"),
                   load_cert(base / "root" / "cert.pem"), cas)

    # ---------- convenience ----------
    def issue(self, role: Role, name: str, public_key: PublicKey | None = None,
              ttl: timedelta | None = None) -> tuple[x509.Certificate, PrivateKey | None]:
        """Issue a leaf cert. If no public key is given, generate a key pair
        (demo convenience only) and store the private key next to the cert."""
        priv = None
        if public_key is None:
            priv = generate_key()
            public_key = priv.public_key()
        cert = self.cas[role].issue(name, public_key, ttl)
        d = self.base / "issued" / role.value / name.replace("://", "_").replace(":", "_")
        save_cert(cert, d / "cert.pem")
        if priv is not None:
            save_private_key(priv, d / "key.pem")
        return cert, priv

    def revoke(self, role: Role, cert: x509.Certificate) -> None:
        self.cas[role].revoke(cert.serial_number)
        self.export_trust_bundle()

    def export_trust_bundle(self) -> Path:
        out = self.base / "trust_bundle"
        out.mkdir(parents=True, exist_ok=True)
        save_cert(self.root_cert, out / "root.pem")
        for role, ca in self.cas.items():
            save_cert(ca.cert, out / f"{role.value}_ca.pem")
            (out / f"{role.value}_crl.pem").write_bytes((ca.dir / "crl.pem").read_bytes())
        return out
