"""Key generation, key IDs and PEM helpers. All keys are ECDSA P-256.

P-256 is used everywhere because mobile driver's licences (ISO 18013-5) and
Longfellow use it for issuer and device keys, and phone secure hardware
supports it.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PrivateKey = ec.EllipticCurvePrivateKey
PublicKey = ec.EllipticCurvePublicKey


def generate_key() -> PrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_key_der(pub: PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(pub: PublicKey) -> str:
    """Stable key identifier: base64url(SHA-256(SubjectPublicKeyInfo DER))."""
    return b64u(hashlib.sha256(public_key_der(pub)).digest())


def public_key_to_b64(pub: PublicKey) -> str:
    return b64u(public_key_der(pub))


def public_key_from_b64(s: str) -> PublicKey:
    pub = serialization.load_der_public_key(b64u_decode(s))
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise ValueError("only P-256 public keys are accepted")
    return pub


# ---------- PEM I/O ----------

def save_private_key(key: PrivateKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)


def load_private_key(path: Path) -> PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return key


def save_cert(cert: x509.Certificate, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert_from_pem(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())
