"""The website's side of Kaustubh's PKI (pki/zkarma_pki). app.py turns it on
when ZKARMA_PKI_DIR is set (setup steps are at the top of app.py).

Same formats as Kaustubh's integration/pki_adapters.py, so his agent signer
and wallet checks work with this site as is:
  * Agent requests carry a ZKARMA-Agent-Signature header. It's a PKI envelope
    (purpose "zkarma/http-request") over the method, full URL, body hash,
    time and a one-time nonce, signed by the agent's certified key.
  * agent_jkt is the RFC 7638 thumbprint of that certified key.
  * Challenges and status messages get a "signature" field. It's a PKI
    envelope (purpose "zkarma/challenge") over SHA-256 of the message
    without the signature (spec.signed_payload).
  * The DMV key comes from the test DMV's certificate, checked by the PKI.
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (ROOT / "pki", ROOT):  # Kaustubh's zkarma_pki, and spec/
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from spec.zkarma_spec import signed_payload  # noqa: E402
from zkarma_pki import (Role, TrustStore, VerificationError, canonical_encode,  # noqa: E402
                        load_cert, load_private_key, sign, verify)
from zkarma_pki.keys import b64u, b64u_decode  # noqa: E402
from zkarma_pki.signing import PURPOSE_CHALLENGE  # noqa: E402

SIGNATURE_HEADER = "ZKARMA-Agent-Signature"
PURPOSE_HTTP_REQUEST = "zkarma/http-request"  # not in zkarma_pki yet (integration/README.md)
MAX_SKEW_S = 60  # how old a signed request can be


def jwk_thumbprint(public_key) -> str:
    """RFC 7638 thumbprint of a P-256 key. This is the agent_jkt."""
    n = public_key.public_numbers()
    jwk = ('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}'
           % (b64u(n.x.to_bytes(32, "big")), b64u(n.y.to_bytes(32, "big"))))
    return b64u(hashlib.sha256(jwk.encode()).digest())


class SitePKI:
    def __init__(self, pki_dir, origin: str, dmv: str = "test-dmv"):
        d = Path(pki_dir).resolve()
        site = d / "issued" / "website" / origin.replace("://", "_").replace(":", "_")
        dmv_cert = d / "issued" / "issuer" / dmv / "cert.pem"
        for path, fix in ((d / "trust_bundle", f"init {d}"), (site / "key.pem", f"issue {d} website {origin}"),
                          (dmv_cert, f"issue {d} issuer {dmv}")):
            if not path.exists():
                raise SystemExit(f"Missing {path}. Run from pki/: python -m zkarma_pki.cli {fix}")
        self.origin, self.dmv, self.bundle = origin, dmv, d / "trust_bundle"
        self.key, self.cert = load_private_key(site / "key.pem"), load_cert(site / "cert.pem")
        self.dmv_cert = dmv_cert.read_text()
        self._trust, self._stamp = None, None
        self._seen: dict[str, float] = {}  # request nonce -> when it can be forgotten
        self._lock = threading.Lock()
        self.trust().verify(self.cert, Role.WEBSITE, expected_name=origin)  # fail now, not mid-demo

    def trust(self) -> TrustStore:
        """The trust bundle, reloaded when `cli revoke` writes a new CRL, so
        revoking an agent or the DMV works while the site is running."""
        stamp = max(p.stat().st_mtime_ns for p in self.bundle.iterdir())
        if stamp != self._stamp:
            self._trust, self._stamp = TrustStore.from_bundle(self.bundle), stamp
        return self._trust

    def agent(self, method: str, path: str, body: bytes, token: str) -> tuple[str | None, str | None]:
        """(agent_jkt, None) if the request is properly signed, else (None, reason)."""
        try:
            env = json.loads(b64u_decode(token))
            ident = self.trust().verify(env["cert"], Role.AGENT)  # chain, role, dates, revocation
            p = verify(env, ident.public_key, PURPOSE_HTTP_REQUEST)  # the signature itself
        except VerificationError as e:
            return None, e.code
        except (ValueError, TypeError, KeyError, AttributeError):
            return None, "malformed"
        if not (isinstance(p, dict) and isinstance(p.get("nonce"), str) and type(p.get("created")) is int):
            return None, "malformed"
        if p.get("method") != method or p.get("target") != self.origin + path:
            return None, "wrong_target"  # signed for another site, route or method
        if p.get("body_sha256") != hashlib.sha256(body).hexdigest():
            return None, "body_mismatch"  # body changed after signing
        now = time.time()
        if abs(now - p["created"]) > MAX_SKEW_S:
            return None, "expired"
        with self._lock:  # each signed request works once
            self._seen = {n: t for n, t in self._seen.items() if t > now}
            if p["nonce"] in self._seen:
                return None, "replay"
            self._seen[p["nonce"]] = p["created"] + MAX_SKEW_S
        return jwk_thumbprint(ident.public_key), None

    def sign_message(self, message: dict) -> str:
        """The "signature" field for a challenge or status message."""
        digest = hashlib.sha256(signed_payload(message)).hexdigest()
        env = sign(self.key, PURPOSE_CHALLENGE, {"msg_sha256": digest}, cert=self.cert)
        return b64u(canonical_encode(env))

    def dmv_key(self) -> tuple[dict | None, str | None]:
        """({"pkx", "pky"}, None) from the DMV's certificate, or (None, reason)
        if the PKI no longer accepts it (revoked, expired)."""
        try:
            ident = self.trust().verify(self.dmv_cert, Role.ISSUER, expected_name=self.dmv)
        except VerificationError as e:
            return None, e.code
        n = ident.public_key.public_numbers()
        return {"pkx": "0x" + n.x.to_bytes(32, "big").hex(), "pky": "0x" + n.y.to_bytes(32, "big").hex()}, None
