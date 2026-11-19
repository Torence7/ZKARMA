"""Signed envelopes: the one format everyone uses to sign protocol messages.

    env = sign(key, "zkarma/challenge", {"site": ..., "operation": ...}, cert=website_cert)
    payload, who = verify_with_cert(env, trust, Role.WEBSITE, "zkarma/challenge",
                                    expected_name="https://shop.test")

Envelope (plain JSON, safe to send through the agent):

    {
      "v": 1,
      "purpose": "zkarma/challenge",   # domain separation, see below
      "payload": {...},                 # any canonical-encodable object
      "alg": "ES256",
      "kid": "<key id of signer>",
      "sig": "<base64url raw r||s, 64 bytes>",
      "cert": "<PEM>"                   # optional, for certified signers
    }

The bytes that are signed are
    canonical_encode({"v": 1, "purpose": purpose, "payload": payload})
so a signature made for one purpose (say a challenge) can never be replayed
as a different message type (say an authorization).

Signatures are raw r||s (as in JWS ES256 and WebCrypto), not DER, so
teammates using JavaScript or other languages can interoperate easily.
"""
from __future__ import annotations

import json
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)

from .canonical import canonical_encode
from .keys import PrivateKey, PublicKey, b64u, b64u_decode, cert_to_pem, key_id
from .roles import Role
from .trust import TrustStore, VerificationError, VerifiedIdentity

VERSION = 1
ALG = "ES256"

# Well-known purposes. Add new ones here so the team shares one list.
PURPOSE_AGENT_REQUEST = "zkarma/agent-request"      # agent -> website: "I want to do X"
PURPOSE_CHALLENGE = "zkarma/challenge"              # website -> client (via agent)
PURPOSE_AUTHORIZATION = "zkarma/authorization"      # client -> website (via agent)
PURPOSE_PRESENTATION = "zkarma/presentation"        # agent's wrapper around the proof
PURPOSE_CREDENTIAL = "zkarma/credential"            # issuer -> client (mock credential)
PURPOSE_CLIENT_REGISTRATION = "zkarma/client-registration"  # client -> website, direct


def _signed_bytes(purpose: str, payload: Any) -> bytes:
    return canonical_encode({"v": VERSION, "purpose": purpose, "payload": payload})


def sign(key: PrivateKey, purpose: str, payload: Any,
         cert: x509.Certificate | None = None) -> dict:
    signed = _signed_bytes(purpose, payload)
    # Store a private copy of exactly what was signed, so later mutation of
    # the caller's object can't silently change the envelope.
    payload = json.loads(signed)["payload"]
    der = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    env = {"v": VERSION, "purpose": purpose, "payload": payload, "alg": ALG,
           "kid": key_id(key.public_key()),
           "sig": b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}
    if cert is not None:
        if key_id(cert.public_key()) != env["kid"]:
            raise ValueError("certificate does not match signing key")
        env["cert"] = cert_to_pem(cert)
    return env


def verify(env: dict, public_key: PublicKey, purpose: str) -> Any:
    """Verify an envelope against a known public key. Returns the payload."""
    if not isinstance(env, dict):
        raise VerificationError("malformed", "envelope is not an object")
    if env.get("v") != VERSION or env.get("alg") != ALG:
        raise VerificationError("malformed", "unsupported version or algorithm")
    if env.get("purpose") != purpose:
        raise VerificationError("bad_signature",
                                f"purpose {env.get('purpose')!r} != expected {purpose!r}")
    if env.get("kid") != key_id(public_key):
        raise VerificationError("bad_key", "envelope kid does not match expected key")
    try:
        raw = b64u_decode(env["sig"])
        if len(raw) != 64:
            raise ValueError("bad length")
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                   int.from_bytes(raw[32:], "big"))
        public_key.verify(der, _signed_bytes(purpose, env["payload"]),
                          ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, KeyError, TypeError) as e:
        raise VerificationError("bad_signature", "signature does not verify") from e
    return env["payload"]


def verify_with_cert(env: dict, trust: TrustStore, role: Role, purpose: str,
                     expected_name: str | None = None) -> tuple[Any, VerifiedIdentity]:
    """Verify an envelope whose signer attached a certificate.

    Checks the certificate chain/role/revocation/name via `trust`, then the
    signature with the certified key.
    """
    if "cert" not in env:
        raise VerificationError("malformed", "envelope carries no certificate")
    ident = trust.verify(env["cert"], role, expected_name=expected_name)
    return verify(env, ident.public_key, purpose), ident
