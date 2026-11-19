"""Adapters that plug zkarma_pki into the website, wallet and agent.

These replace the stubs that spec/README.md lists as "to swap out later":

| Stub today                          | Adapter here                                   |
|-------------------------------------|------------------------------------------------|
| X-Dev-Agent-Thumbprint header       | AgentRequestSigner + RequestVerifier           |
| spec.stub_sign / spec.stub_verify   | WebsiteMessageSigner / verify_website_message  |
| trust/issuer_pub.json (hand-made)   | issuer_pub_json() from a verified issuer cert  |

Nothing in website/, client/, agent/ or pki/ is modified. The integration
harness (harness.py) installs these at the stubs' call sites.

Design notes worth agreeing on as a team (see integration/README.md):
  * Agent identity. The website and wallet key everything on `agent_jkt`, a
    key thumbprint. zkarma_pki's `key_id` is SHA-256 over the SPKI DER, which
    is NOT the RFC 7638 JWK thumbprint. The adapter derives an RFC 7638
    thumbprint from the *certified* key so both sides compute the same value.
  * Request signing uses a new purpose, "zkarma/http-request", covering the
    method, the full target URL (origin + path), a body hash, a timestamp
    and a one-time nonce. A signature made for the website cannot be replayed
    to the wallet (different target), or replayed at all (nonce cache).
  * Website messages (challenges, status) are signed over the spec's
    `signed_payload()` bytes, so the spec stays the single source of truth for
    what is covered; the PKI provides the key and the certificate.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

from zkarma_pki import Role, TrustStore, VerificationError, canonical_encode, sign, verify_with_cert
from zkarma_pki.keys import PublicKey, b64u, b64u_decode
from zkarma_pki.signing import PURPOSE_CHALLENGE, verify

PURPOSE_HTTP_REQUEST = "zkarma/http-request"
SIGNATURE_HEADER = "ZKARMA-Agent-Signature"
MAX_REQUEST_SKEW_S = 60


# ----------------------------------------------------------------------------
# Identity
# ----------------------------------------------------------------------------
def jwk_thumbprint(pub: PublicKey) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) of a P-256 public key."""
    n = pub.public_numbers()
    jwk = ('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}'
           % (b64u(n.x.to_bytes(32, "big")), b64u(n.y.to_bytes(32, "big"))))
    return b64u(hashlib.sha256(jwk.encode()).digest())


def encode_compact(env: dict) -> str:
    """Envelope -> one header-safe token (base64url of its canonical JSON)."""
    return b64u(canonical_encode(env))


def decode_compact(token) -> dict:
    try:
        env = json.loads(b64u_decode(token))
    except Exception as e:  # noqa: BLE001 - any decoding problem is "malformed"
        raise VerificationError("malformed", "signature token does not decode") from e
    if not isinstance(env, dict):
        raise VerificationError("malformed", "signature token is not an object")
    return env


def _target(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path or '/'}" + (f"?{p.query}" if p.query else "")


# ----------------------------------------------------------------------------
# Agent -> website / wallet: signed HTTP requests
# ----------------------------------------------------------------------------
class AgentRequestSigner:
    """Agent side. Produces the signature header for one HTTP request."""

    def __init__(self, key, cert, clock: Callable[[], float] = time.time):
        self.key, self.cert, self.clock = key, cert, clock

    def payload(self, method: str, url: str, body: bytes) -> dict:
        return {"method": method.upper(), "target": _target(url),
                "body_sha256": hashlib.sha256(body or b"").hexdigest(),
                "created": int(self.clock()), "nonce": secrets.token_hex(16)}

    def headers(self, method: str, url: str, body: bytes) -> dict:
        env = sign(self.key, PURPOSE_HTTP_REQUEST, self.payload(method, url, body), cert=self.cert)
        return {SIGNATURE_HEADER: encode_compact(env)}


class SignedTransport:
    """Wraps the agent's JSON transport (agent/http.py JsonHTTP) and signs every
    request. Drops the dev identity header so only the PKI identity counts."""

    def __init__(self, signer: AgentRequestSigner, inner):
        self.signer, self.inner = signer, inner
        self.header_bytes: list[int] = []

    def request(self, method, url, body=None, headers=None):
        data = b"" if body is None else json.dumps(body).encode()  # same bytes JsonHTTP sends
        h = {k: v for k, v in (headers or {}).items() if k.lower() != "x-dev-agent-thumbprint"}
        sig = self.signer.headers(method, url, data)
        self.header_bytes.append(len(sig[SIGNATURE_HEADER]))
        h.update(sig)
        return self.inner.request(method, url, body, h)


@dataclass(frozen=True)
class VerifiedAgent:
    jkt: str            # RFC 7638 thumbprint of the certified key
    name: str           # agent id from the certificate SAN
    serial: int


class RequestVerifier:
    """Website / wallet side. Verifies the agent's signature header."""

    def __init__(self, trust: TrustStore, origin: str, max_skew_s: int = MAX_REQUEST_SKEW_S,
                 clock: Callable[[], float] = time.time):
        self.trust, self.origin, self.max_skew_s, self.clock = trust, origin.rstrip("/"), max_skew_s, clock
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self.rejections: Counter[str] = Counter()
        self.accepted = 0
        self.verify_ms: list[float] = []

    def verify(self, method: str, path_qs: str, body: bytes, token: str | None) -> VerifiedAgent:
        start = time.perf_counter()
        try:
            ident, payload = self._verify(method, path_qs, body, token)
        except VerificationError as e:
            self.rejections[e.code] += 1
            raise
        finally:
            self.verify_ms.append((time.perf_counter() - start) * 1000)
        self.accepted += 1
        return VerifiedAgent(jwk_thumbprint(ident.public_key), ident.name, ident.serial)

    def _verify(self, method, path_qs, body, token):
        if not token:
            raise VerificationError("missing_signature", "no agent signature header")
        env = decode_compact(token)
        now = self.clock()
        payload, ident = self._verify_at(env, now)
        if not (isinstance(payload, dict) and isinstance(payload.get("nonce"), str)
                and type(payload.get("created")) is int):
            raise VerificationError("malformed", "bad request-signature payload")
        if payload.get("method") != method.upper() or payload.get("target") != self.origin + path_qs:
            raise VerificationError("wrong_target", f"signed for {payload.get('target')!r}")
        if payload.get("body_sha256") != hashlib.sha256(body or b"").hexdigest():
            raise VerificationError("body_mismatch", "request body changed after signing")
        if abs(now - payload["created"]) > self.max_skew_s:
            raise VerificationError("expired", "request signature too old or from the future")
        with self._lock:
            for n, exp in list(self._seen.items()):
                if exp < now:
                    del self._seen[n]
            if payload["nonce"] in self._seen:
                raise VerificationError("replay", "request nonce already used")
            self._seen[payload["nonce"]] = payload["created"] + self.max_skew_s
        return ident, payload

    def _verify_at(self, env, now):
        """verify_with_cert, evaluated at the verifier's clock (lets tests
        move time forward to exercise expiry and CRL freshness)."""
        if "cert" not in env:
            raise VerificationError("malformed", "envelope carries no certificate")
        ident = self.trust.verify(env["cert"], Role.AGENT, at=datetime.fromtimestamp(now, timezone.utc))
        return verify(env, ident.public_key, PURPOSE_HTTP_REQUEST), ident

    def flask_identity(self, req) -> str | None:
        """Drop-in for website/app.py verify_agent_signature and
        client/wallet.py agent_identity: returns agent_jkt or None."""
        path_qs = req.path + (f"?{req.query_string.decode()}" if req.query_string else "")
        try:
            return self.verify(req.method, path_qs, req.get_data(cache=True),
                               req.headers.get(SIGNATURE_HEADER)).jkt
        except VerificationError:
            return None


# ----------------------------------------------------------------------------
# Website -> wallet (through the agent): signed challenges and status
# ----------------------------------------------------------------------------
class WebsiteMessageSigner:
    """Replaces spec.stub_sign. The website signs SHA-256(spec.signed_payload(msg))."""

    def __init__(self, key, cert, signed_payload: Callable[[dict], bytes]):
        self.key, self.cert, self.signed_payload = key, cert, signed_payload
        self.sizes: list[int] = []

    def sign_message(self, message: dict) -> str:
        digest = hashlib.sha256(self.signed_payload(message)).hexdigest()
        token = encode_compact(sign(self.key, PURPOSE_CHALLENGE, {"msg_sha256": digest}, cert=self.cert))
        self.sizes.append(len(token))
        return token


def verify_website_message(message: dict, signature, trust: TrustStore, expected_origin: str,
                           signed_payload: Callable[[dict], bytes]):
    """Replaces spec.stub_verify. `expected_origin` must be a site the USER chose
    (the wallet's allowlist), never something the agent supplied unchecked."""
    env = decode_compact(signature)
    payload, ident = verify_with_cert(env, trust, Role.WEBSITE, PURPOSE_CHALLENGE,
                                      expected_name=expected_origin)
    digest = hashlib.sha256(signed_payload(message)).hexdigest()
    if not isinstance(payload, dict) or payload.get("msg_sha256") != digest:
        raise VerificationError("bad_signature", "message changed after the website signed it")
    return ident


# ----------------------------------------------------------------------------
# Issuer (DMV) key for the Longfellow verifier
# ----------------------------------------------------------------------------
def issuer_pub_json(trust: TrustStore, issuer_cert_pem: str) -> dict:
    """website/proofs.py reads {"pkx": "0x..", "pky": "0x.."}. Produce it from an
    issuer certificate only after the PKI accepts that certificate."""
    ident = trust.verify(issuer_cert_pem, Role.ISSUER)
    n = ident.public_key.public_numbers()
    return {"pkx": "0x" + n.x.to_bytes(32, "big").hex(), "pky": "0x" + n.y.to_bytes(32, "big").hex(),
            "issuer": ident.name, "serial": str(ident.serial)}
