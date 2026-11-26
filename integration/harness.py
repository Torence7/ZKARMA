"""Boots the real website, wallet and agent, with or without the PKI installed.

    with System(tmpdir) as s:                  # "pki":   PKI installed, dev mode OFF everywhere
        s.safe_agent().purchase("wine-001")
    with System(tmpdir, mode="nopki") as s:    # "nopki": dev identity header, unsigned challenges,
        ...                                    #          but the same binding proof as "pki"
    with System(tmpdir, mode="dev") as s:      # "dev":   today's system as shipped (dev-proof)

Comparing "nopki" with "pki" isolates what the PKI itself contributes;
"dev" shows the system exactly as it runs today.

PKI mode replaces every stub except the zero-knowledge proof:
  * website: verify_agent_signature -> RequestVerifier (agent cert + request signature)
             challenge()            -> same body plus a PKI website signature
  * wallet:  agent_identity         -> RequestVerifier (agent cert + request signature)
             validate.check_signature -> verify_website_message (website cert, name == user's site)
  * agent:   transport              -> SignedTransport (signs every request)
  * proof:   still a stand-in, but a *binding* one: "bind:" + SHA-256(transcript),
             so a proof only verifies for the exact site, nonce, agent and operation
             (same idea as client/tests/helpers.binding_proof).

The servers are real HTTP servers on 127.0.0.1; the agent talks to them with
the same JsonHTTP transport it uses in production.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import itertools
import os
import socket
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
for _p in (REPO, REPO / "pki", REPO / "client", REPO / "website"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
os.environ.pop("ZKARMA_DEV", None)  # client/config.py reads it at import time

from werkzeug.serving import make_server  # noqa: E402

import prover as client_prover  # noqa: E402
import validate as client_validate  # noqa: E402
import wallet as client_wallet  # noqa: E402
from agent.http import JsonHTTP  # noqa: E402
from agent.runtime import SafeAgent  # noqa: E402
from spec import zkarma_spec as spec  # noqa: E402
from store import Store  # noqa: E402
from validate import Refused  # noqa: E402
from zkarma_pki import PKI, Role, TrustStore, VerificationError  # noqa: E402
from zkarma_pki.keys import cert_to_pem  # noqa: E402

from integration.pki_adapters import (AgentRequestSigner, RequestVerifier,  # noqa: E402
                                      SignedTransport, WebsiteMessageSigner, jwk_thumbprint,
                                      verify_website_message)

DEFAULT_WEBSITE = REPO / "website" / "app.py"
_ORIGINALS = {
    (client_wallet, "agent_identity"): client_wallet.agent_identity,
    (client_wallet, "prove"): client_wallet.prove,
    (client_wallet, "DEV"): client_wallet.DEV,
    (client_validate, "check_signature"): client_validate.check_signature,
    (client_validate, "DEV"): client_validate.DEV,
    (client_prover, "DEV"): client_prover.DEV,
}
_counter = itertools.count()


def binding_proof(transcript: bytes) -> str:
    return "bind:" + hashlib.sha256(transcript).hexdigest()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def load_website(path: Path, origin: str, port: int, dev: bool):
    """Import a fresh copy of a website/app.py (fresh in-memory state)."""
    os.environ.update(ZKARMA_ORIGIN=origin, ZKARMA_PORT=str(port))
    if dev:
        os.environ["ZKARMA_DEV"] = "1"
    if str(Path(path).parent) not in sys.path:
        sys.path.insert(0, str(Path(path).parent))
    name = f"zkarma_website_{next(_counter)}"
    mod_spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(mod_spec)
    sys.modules[name] = mod
    try:
        mod_spec.loader.exec_module(mod)
    finally:
        os.environ.pop("ZKARMA_DEV", None)
    return mod


class _Server:
    def __init__(self, app, port: int):
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        self.srv = make_server("127.0.0.1", port, app, threaded=True)
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


class AutoConsent:
    """Stands in for the user at the wallet prompt. `policy(operation) -> bool`
    is the user's intent; every prompt is recorded so a test can tell whether
    an attack was stopped before or after the user was asked."""

    def __init__(self, policy):
        self.policy = policy
        self.prompts: list[dict] = []

    def decide(self, req) -> bool:
        self.prompts.append(copy.deepcopy(req.operation))
        return bool(self.policy(req.operation))


def approve(*items: str, enter: bool = True):
    return lambda op: (op.get("action") == "enter" and enter) or op.get("item_id") in items


@dataclass
class AgentCreds:
    name: str
    cert: object
    key: object

    @property
    def jkt(self) -> str:
        return jwk_thumbprint(self.cert.public_key())

    def signer(self) -> AgentRequestSigner:
        return AgentRequestSigner(self.key, self.cert)


class System:
    """proof="binding" (default) uses the SHA-256 stand-in. proof="real" gives the
    wallet a test mDL from the PKI's test DMV and runs real Longfellow proofs
    (client/zkage.py) checked by the real website/proofs.py. ZKARMA_PROOF=real
    switches the default, so every existing scenario can run on real proofs."""

    def __init__(self, tmp, *, mode: str = "pki", website_file: Path | str | None = None,
                 consent: AutoConsent | None = None, agent_name: str = "safe-agent",
                 site_clock=time.time, proof: str | None = None, mdl_birth_date=None):
        if mode not in ("pki", "nopki", "dev"):
            raise ValueError(f"unknown mode {mode!r}")
        self.proof = proof or os.environ.get("ZKARMA_PROOF", "binding")
        if self.proof not in ("binding", "real"):
            raise ValueError(f"unknown proof {self.proof!r}")
        if self.proof == "real" and mode == "dev":
            raise ValueError("dev mode means dev-proof; use proof='real' with pki or nopki")
        self.mdl_birth_date = mdl_birth_date
        self.prove_metrics: list[dict] = []
        self.tmp, self.mode, self.pki_mode = Path(tmp), mode, mode == "pki"
        self.website_file = Path(website_file or DEFAULT_WEBSITE)
        self.site_port, self.wallet_port = free_port(), free_port()
        self.origin = f"http://127.0.0.1:{self.site_port}"
        self.wallet_origin = f"http://127.0.0.1:{self.wallet_port}"
        self.consent = consent or AutoConsent(approve("wine-001", "vape-001", "water-001"))
        self.store = Store(None)
        self.store.allow_origin(self.origin)
        self.proof_checks: Counter[str] = Counter()
        self.wallet_sig_rejections: Counter[str] = Counter()
        self.agents: dict[str, AgentCreds] = {}
        self._servers: list[_Server] = []
        self._stop = threading.Event()

        # PKI material. Each party gets its OWN TrustStore from the bundle,
        # as if installed out of band.
        self.pki = PKI.create(self.tmp / "pki")
        self.site_cert, self.site_key = self.pki.issue(Role.WEBSITE, self.origin)
        self.issuer_cert, self.issuer_key = self.pki.issue(Role.ISSUER, "test-dmv")
        bundle = self.tmp / "pki" / "trust_bundle"
        self.trust_site = TrustStore.from_bundle(bundle)
        self.trust_wallet = TrustStore.from_bundle(bundle)
        self.add_agent(agent_name)

        self.website = load_website(self.website_file, self.origin, self.site_port,
                                    dev=not self.pki_mode)
        # main's website keeps /enter but only enables it with ZKARMA_ENTRY_CHECK=1.
        entry = getattr(self.website, "ENTRY_CHECK", "enter" in self.website.app.view_functions)
        self.variant = "enter+session" if entry else "public-catalog"
        if self.pki_mode:
            self._install_pki(site_clock)
        else:
            self._install_dev(binding=mode == "nopki")
        self.wallet = client_wallet.Wallet(self.store)

    # ------------------------------------------------------------------ setup
    def add_agent(self, name: str, ttl: timedelta | None = None, pair: bool = True) -> AgentCreds:
        cert, key = self.pki.issue(Role.AGENT, name, ttl=ttl)
        creds = AgentCreds(name, cert, key)
        self.agents[name] = creds
        if pair:
            # PKI mode pairs the certified key's thumbprint; dev mode the header value.
            self.store.pair_agent(creds.jkt if self.pki_mode else name, f"Agent {name}")
        return creds

    def revoke_agent(self, name: str) -> None:
        self.pki.revoke(Role.AGENT, self.agents[name].cert)
        crl = (self.tmp / "pki" / "trust_bundle" / "agent_crl.pem").read_bytes()
        self.trust_site.update_crl(Role.AGENT, crl)
        self.trust_wallet.update_crl(Role.AGENT, crl)

    def _install_pki(self, site_clock) -> None:
        web = self.website
        self.site_verifier = RequestVerifier(self.trust_site, self.origin, clock=site_clock)
        web.verify_agent_signature = self.site_verifier.flask_identity
        self.msg_signer = WebsiteMessageSigner(self.site_key, self.site_cert, spec.signed_payload)
        original_challenge = web.challenge

        def signed_challenge(record):
            body, code, headers = original_challenge(record)
            data = body.get_json()
            data["challenge"]["signature"] = self.msg_signer.sign_message(data["challenge"])
            return web.jsonify(data), code, headers

        web.challenge = signed_challenge

        self._install_proof()

        self.wallet_verifier = RequestVerifier(self.trust_wallet, self.wallet_origin)
        client_wallet.DEV = client_validate.DEV = client_prover.DEV = False
        client_wallet.agent_identity = self.wallet_verifier.flask_identity
        client_validate.check_signature = self._wallet_check_signature

    def _install_proof(self) -> None:
        if self.proof == "real":
            self._install_real_proof()
        else:
            self._install_binding_proof()

    def _install_real_proof(self) -> None:
        """Wallet: test mDL from the PKI's test DMV + client/zkage.py.
        Website: its own website/proofs.py, DMV key from the PKI-verified cert."""
        from datetime import date

        import proofs as real_proofs  # website/proofs.py
        import zkage
        from integration.mdl_adapters import make_wallet_prover, write_issuer_pub
        from zkarma_pki.mdl import MdlIssuer

        if not zkage.available():
            raise RuntimeError("proof='real' needs zkage; see zk/README.md")
        self.mdl = MdlIssuer(self.issuer_key, self.issuer_cert).issue_to_new_device(
            birth_date=self.mdl_birth_date or date(2000, 1, 1))
        client_wallet.prove = make_wallet_prover(self.mdl, zkage, self.prove_metrics.append)
        issuer_pub = write_issuer_pub(self.tmp / "trust" / "issuer_pub.json", self.trust_site,
                                      self.issuer_cert_pem)
        saved = {k: getattr(real_proofs, k) for k in ("ZKAGE", "CIRCUITS", "ISSUER_PUB")}
        self._restore_proofs = lambda: [setattr(real_proofs, k, v) for k, v in saved.items()]
        real_proofs.ZKAGE, real_proofs.CIRCUITS = zkage.ZKAGE, zkage.CIRCUITS
        real_proofs.ISSUER_PUB = issuer_pub

        def verify_proof(proof, transcript, now):
            ok = real_proofs.verify(proof, transcript, now)
            self.proof_checks["ok" if ok else "invalid"] += 1
            return ok

        self.website.proofs = SimpleNamespace(verify=verify_proof)

    def _install_binding_proof(self) -> None:
        def verify_proof(proof, transcript, now):
            ok = proof == binding_proof(transcript)
            self.proof_checks["ok" if ok else "unbound"] += 1
            return ok

        self.website.proofs = SimpleNamespace(verify=verify_proof)
        client_wallet.prove = lambda transcript, now, claim: binding_proof(transcript)

    def _install_dev(self, binding: bool) -> None:
        for (mod, attr), value in _ORIGINALS.items():
            setattr(mod, attr, value)
        client_wallet.DEV = client_validate.DEV = client_prover.DEV = True
        if binding:
            self._install_proof()

    def _wallet_check_signature(self, message: dict) -> bool:
        sig = message.get("signature")
        if sig is None:
            self.wallet_sig_rejections["unsigned"] += 1
            raise Refused("unsigned")
        origin = message.get("origin", message.get("site"))
        if origin not in self.store.origins:  # expected name = a site the USER allowed
            raise Refused("origin_not_allowed")
        try:
            verify_website_message(message, sig, self.trust_wallet, origin, spec.signed_payload)
        except VerificationError as e:
            self.wallet_sig_rejections[e.code] += 1
            raise Refused(f"website_sig_{e.code}") from None
        return True

    # -------------------------------------------------------------- lifecycle
    def __enter__(self):
        self._servers.append(_Server(self.website.app, self.site_port))
        self._servers.append(_Server(client_wallet.create_app(self.wallet), self.wallet_port))
        self._loop = threading.Thread(target=self._consent_loop, daemon=True)
        self._loop.start()
        return self

    def _consent_loop(self):
        while not self._stop.is_set():
            rid = self.wallet.next_request(timeout=0.02)
            if rid:
                self.wallet.decide(rid, self.consent)

    def __exit__(self, *exc):
        self._stop.set()
        for s in self._servers:
            s.stop()
        self._loop.join(timeout=2)
        for (mod, attr), value in _ORIGINALS.items():
            setattr(mod, attr, value)
        getattr(self, "_restore_proofs", lambda: None)()
        return False

    # ----------------------------------------------------------------- agents
    def transport(self, name: str = "safe-agent"):
        if self.pki_mode:
            return SignedTransport(self.agents[name].signer(), JsonHTTP())
        return JsonHTTP()

    def safe_agent(self, name: str = "safe-agent", **kw) -> SafeAgent:
        kw.setdefault("emit", lambda *a: None)
        kw.setdefault("poll_interval", 0.01)
        kw.setdefault("approval_timeout", 10)
        return SafeAgent(self.origin, self.wallet_origin, agent_id=name, http=self.transport(name), **kw)

    def raw_agent(self, name: str = "safe-agent", transport=None) -> "RawAgent":
        return RawAgent(self, name, transport or self.transport(name))

    @property
    def issuer_cert_pem(self) -> str:
        return cert_to_pem(self.issuer_cert)


class RawAgent:
    """A scripted agent. Honest when driven step by step; tests use it to
    deviate from the protocol (the 'malicious agent')."""

    def __init__(self, system: System, name: str, transport):
        self.s, self.name, self.http = system, name, transport

    def call(self, method, base, path, body=None, headers=None):
        h = {"X-Dev-Agent-Thumbprint": self.name, **(headers or {})}  # ignored in PKI mode
        return self.http.request(method, base + path, body, h)

    def site(self, method, path, body=None, headers=None):
        return self.call(method, self.s.origin, path, body, headers)

    def wallet(self, method, path, body=None):
        return self.call(method, self.s.wallet_origin, path, body)

    def authorize(self, challenge, status=None, timeout: float = 5):
        body = {"challenge": challenge} if status is None else {"challenge": challenge, "status": status}
        code, resp = self.wallet("POST", "/authorize", body)
        if code != 202:
            return code, resp
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code, ans = self.wallet("GET", f"/authorize/{resp['request_id']}")
            if code != 200 or ans.get("status") != "pending":
                return code, ans
            time.sleep(0.01)
        return 0, {"status": "timeout"}

    def redeem(self, nonce, proof, headers=None):
        return self.site("POST", "/redeem", {"nonce": nonce, "proof": proof}, headers)

    def run_operation(self, path, body=None, headers=None):
        """Start an operation, get the user's approval, redeem. Returns a trace."""
        code, ch = self.site("POST", path, body, headers)
        if code != 401:
            return {"step": "start", "code": code, "body": ch}
        code, ans = self.authorize(ch["challenge"])
        if ans.get("status") != "approved":
            return {"step": "wallet", "code": code, "body": ans, "challenge": ch["challenge"]}
        code, res = self.redeem(ans["nonce"], ans["proof"], headers)
        return {"step": "redeem", "code": code, "body": res, "challenge": ch["challenge"], "approval": ans}
