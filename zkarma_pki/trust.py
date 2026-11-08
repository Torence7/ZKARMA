"""TrustStore: what the client and website use to verify certificates.

Load it from the trust bundle that was installed out of band:

    trust = TrustStore.from_bundle("pki_out/trust_bundle")
    ident = trust.verify(cert_pem, Role.AGENT)            # -> VerifiedIdentity
    ident = trust.verify(cert_pem, Role.WEBSITE, expected_name="https://shop.test")

Every failure raises VerificationError with a machine-readable `code`, so
the security evaluation can count *why* things were rejected.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from .keys import PublicKey, cert_from_pem, key_id, load_cert
from .roles import AGENT_URI_PREFIX, EKU_ROLE, ISSUER_URI_PREFIX, Role


class VerificationError(Exception):
    """Raised when a certificate (or a signature, see signing.py) is rejected.

    code is one of: bad_chain, wrong_role, expired, not_yet_valid, revoked,
    name_mismatch, stale_crl, bad_crl, malformed, bad_signature, bad_key.
    """

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class VerifiedIdentity:
    role: Role
    name: str             # website origin, agent id or issuer name
    public_key: PublicKey
    key_id: str
    serial: int
    not_after: datetime


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _check_validity(cert: x509.Certificate, at: datetime, what: str) -> None:
    if at < cert.not_valid_before_utc:
        raise VerificationError("not_yet_valid", what)
    if at > cert.not_valid_after_utc:
        raise VerificationError("expired", what)


class TrustStore:
    def __init__(self, root: x509.Certificate, cas: dict[Role, x509.Certificate],
                 crls: dict[Role, x509.CertificateRevocationList] | None = None):
        self.root = root
        # Root must be self-signed; each intermediate must chain to it.
        try:
            root.verify_directly_issued_by(root)
        except (InvalidSignature, ValueError, TypeError) as e:
            raise VerificationError("bad_chain", f"root is not self-signed: {e}") from e
        for role, ca in cas.items():
            try:
                ca.verify_directly_issued_by(root)
            except (InvalidSignature, ValueError, TypeError) as e:
                raise VerificationError("bad_chain", f"{role.value} CA not issued by root") from e
            bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                raise VerificationError("bad_chain", f"{role.value} CA cert is not a CA")
        self.cas = cas
        self.crls: dict[Role, x509.CertificateRevocationList] = {}
        for role, crl in (crls or {}).items():
            self.update_crl(role, crl)

    # ---------- loading ----------
    @classmethod
    def from_bundle(cls, bundle_dir: Path | str) -> "TrustStore":
        d = Path(bundle_dir)
        cas = {r: load_cert(d / f"{r.value}_ca.pem") for r in Role}
        crls = {}
        for r in Role:
            p = d / f"{r.value}_crl.pem"
            if p.exists():
                crls[r] = x509.load_pem_x509_crl(p.read_bytes())
        return cls(load_cert(d / "root.pem"), cas, crls)

    def update_crl(self, role: Role, crl: x509.CertificateRevocationList | bytes) -> None:
        """Install a newer CRL. CRLs are signed by the CA, so they can be
        fetched over any channel; a forged or older CRL is refused."""
        if isinstance(crl, (bytes, str)):
            crl = x509.load_pem_x509_crl(crl if isinstance(crl, bytes) else crl.encode())
        ca = self.cas[role]
        if crl.issuer != ca.subject or not crl.is_signature_valid(ca.public_key()):
            raise VerificationError("bad_crl", f"CRL not signed by {role.value} CA")
        old = self.crls.get(role)
        if old is not None:
            n_old = old.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
            n_new = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
            if n_new < n_old:
                raise VerificationError("bad_crl", "refusing to roll back to an older CRL")
        self.crls[role] = crl

    # ---------- verification ----------
    def verify(self, cert: x509.Certificate | str | bytes, role: Role,
               expected_name: str | None = None, at: datetime | None = None,
               require_crl: bool = True) -> VerifiedIdentity:
        at = at or _now()
        if isinstance(cert, (str, bytes)):
            try:
                cert = cert_from_pem(cert if isinstance(cert, str) else cert.decode())
            except Exception as e:  # noqa: BLE001 - any parse failure is "malformed"
                raise VerificationError("malformed", str(e)) from e

        # 1. Role: the leaf's EKU must say exactly `role`. Checked before the
        #    chain so the error is informative for cert-type confusion.
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            raise VerificationError("wrong_role", "no ZKARMA role in certificate") from None
        roles = {EKU_ROLE[o] for o in eku if o in EKU_ROLE}
        if roles != {role}:
            got = ",".join(sorted(r.value for r in roles)) or "none"
            raise VerificationError("wrong_role", f"expected {role.value}, got {got}")

        # 2. Chain: leaf must be signed by THE intermediate for that role.
        ca = self.cas[role]
        try:
            cert.verify_directly_issued_by(ca)
        except (InvalidSignature, ValueError, TypeError) as e:
            raise VerificationError("bad_chain", f"not issued by {role.value} CA") from e
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            raise VerificationError("wrong_role", "CA certificate used as a leaf")

        # 3. Validity windows (leaf, intermediate, root).
        _check_validity(cert, at, "leaf certificate")
        _check_validity(ca, at, f"{role.value} CA certificate")
        _check_validity(self.root, at, "root certificate")

        # 4. Revocation. Fail closed if the CRL is missing or stale.
        crl = self.crls.get(role)
        if crl is None:
            if require_crl:
                raise VerificationError("stale_crl", f"no CRL for {role.value} CA")
        else:
            if crl.next_update_utc is not None and at > crl.next_update_utc:
                raise VerificationError("stale_crl", f"{role.value} CRL expired")
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
                raise VerificationError("revoked", f"serial {cert.serial_number}")

        # 5. Identity from the SAN URI.
        name = _identity(cert, role)
        if expected_name is not None and name != expected_name:
            raise VerificationError("name_mismatch", f"expected {expected_name!r}, got {name!r}")

        pub = cert.public_key()
        return VerifiedIdentity(role, name, pub, key_id(pub), cert.serial_number,
                                cert.not_valid_after_utc)


def _identity(cert: x509.Certificate, role: Role) -> str:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise VerificationError("malformed", "certificate has no SAN") from None
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise VerificationError("malformed", "expected exactly one SAN URI")
    uri = uris[0]
    prefix = {Role.AGENT: AGENT_URI_PREFIX, Role.ISSUER: ISSUER_URI_PREFIX}.get(role)
    if prefix:
        if not uri.startswith(prefix):
            raise VerificationError("malformed", f"SAN {uri!r} lacks {prefix}")
        return uri[len(prefix):]
    return uri
