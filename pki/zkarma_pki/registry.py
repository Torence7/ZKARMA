"""Pairwise (per-site) client keys.

Why: if the wallet used one certified key everywhere, every website could
recognise the same user across sites. Instead the wallet makes a fresh key
pair for each website (ClientKeyring) and registers the public key with that
website once (ClientKeyRegistry). Sites can't link a user to each other by key.

Channel requirement (from the security model): registration must go DIRECTLY
from client to website (e.g. a QR code / link the user opens on their phone),
never through an agent. Otherwise a malicious agent could register its own key
as "the user's".

Registration is self-signed by the new key (proof of possession) and names
the site, so a registration message for site A can't be replayed at site B.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from pathlib import Path

from .keys import (PrivateKey, PublicKey, generate_key, key_id, load_private_key,
                   public_key_from_b64, public_key_to_b64, save_private_key)
from .signing import PURPOSE_CLIENT_REGISTRATION, sign, verify
from .trust import VerificationError

REGISTRATION_MAX_AGE = 300  # seconds


class ClientKeyring:
    """Wallet side: one key per website origin."""

    def __init__(self, store_dir: Path | str | None = None):
        self.dir = Path(store_dir) if store_dir else None
        self._keys: dict[str, PrivateKey] = {}

    def _path(self, site: str) -> Path:
        assert self.dir is not None
        return self.dir / (site.replace("://", "_").replace(":", "_").replace("/", "_") + ".pem")

    def key_for(self, site: str) -> PrivateKey:
        if site in self._keys:
            return self._keys[site]
        if self.dir and self._path(site).exists():
            k = load_private_key(self._path(site))
        else:
            k = generate_key()
            if self.dir:
                save_private_key(k, self._path(site))
        self._keys[site] = k
        return k

    def registration_for(self, site: str) -> dict:
        """Signed registration message to hand DIRECTLY to `site`."""
        k = self.key_for(site)
        return sign(k, PURPOSE_CLIENT_REGISTRATION, {
            "site": site,
            "public_key": public_key_to_b64(k.public_key()),
            "issued_at": int(time.time()),
            "nonce": secrets.token_hex(16),
        })


class ClientKeyRegistry:
    """Website side: the registered client keys for ONE site."""

    def __init__(self, site: str, store_path: Path | str | None = None):
        self.site = site
        self.path = Path(store_path) if store_path else None
        self._lock = threading.Lock()
        self._keys: dict[str, dict] = {}
        self._seen_nonces: set[str] = set()
        if self.path and self.path.exists():
            self._keys = json.loads(self.path.read_text())

    def register(self, env: dict, now: int | None = None) -> str:
        now = int(now if now is not None else time.time())
        try:
            payload = env["payload"]
            pub = public_key_from_b64(payload["public_key"])
        except (KeyError, TypeError, ValueError) as e:
            raise VerificationError("malformed", f"bad registration: {e}") from e
        verify(env, pub, PURPOSE_CLIENT_REGISTRATION)  # proof of possession
        if payload.get("site") != self.site:
            raise VerificationError("name_mismatch",
                                    f"registration is for {payload.get('site')!r}, not {self.site!r}")
        age = now - int(payload.get("issued_at", 0))
        if age < -30 or age > REGISTRATION_MAX_AGE:
            raise VerificationError("expired", "registration too old or from the future")
        with self._lock:
            if payload["nonce"] in self._seen_nonces:
                raise VerificationError("replay", "registration nonce already used")
            self._seen_nonces.add(payload["nonce"])
            kid = key_id(pub)
            self._keys[kid] = {"public_key": payload["public_key"], "registered_at": now,
                               "revoked": False}
            self._save()
        return kid

    def get(self, kid: str) -> PublicKey:
        rec = self._keys.get(kid)
        if rec is None:
            raise VerificationError("bad_key", "client key not registered at this site")
        if rec["revoked"]:
            raise VerificationError("revoked", "client key revoked")
        return public_key_from_b64(rec["public_key"])

    def revoke(self, kid: str) -> None:
        with self._lock:
            if kid in self._keys:
                self._keys[kid]["revoked"] = True
                self._save()

    def __contains__(self, kid: str) -> bool:
        return kid in self._keys and not self._keys[kid]["revoked"]

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._keys, indent=2))
