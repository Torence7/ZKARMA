"""Stand-ins for the parts the rest of the team is building.

    MockIssuer   -> test DMV          (issues a signed credential)
    mock_zk_*    -> Longfellow        (PLACEHOLDER: reveals the credential!)
    MockClient   -> P's wallet
    MockAgent    -> V's agent
    MockWebsite  -> T's website

Only the PKI calls (TrustStore, sign/verify, ClientKeyring/Registry) are the
real thing. Everything else is the simplest code that exercises them, so each
teammate can replace their mock without touching the PKI. Look for
"PKI HOOK" comments: those are the exact calls each real component needs.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from zkarma_pki import (PURPOSE_AGENT_REQUEST, PURPOSE_AUTHORIZATION, PURPOSE_CHALLENGE,
                        PURPOSE_CREDENTIAL, PURPOSE_PRESENTATION, ClientKeyRegistry,
                        ClientKeyring, Role, TrustStore, VerificationError, canonical_hash,
                        generate_key, key_id, public_key_from_b64, public_key_to_b64, sign,
                        verify, verify_with_cert)
from zkarma_pki.keys import cert_to_pem

PREDICATE = "age_over_18"


def wire(msg):
    """Simulate sending a message over the network: JSON out, JSON in.
    Guarantees no party shares Python objects with another."""
    import json
    return json.loads(json.dumps(msg))


# ============================================================ issuer (DMV)
class MockIssuer:
    def __init__(self, cert, key):
        self.cert, self.key = cert, key

    def issue_credential(self, device_public_key, attributes: dict) -> dict:
        # PKI HOOK: the issuer signs with its certified Issuer-role key.
        return sign(self.key, PURPOSE_CREDENTIAL, {
            "attributes": attributes,
            "device_key": public_key_to_b64(device_public_key),
            "issued_at": int(time.time()),
        }, cert=self.cert)


# ============================================================ ZK proof (placeholder)
def mock_zk_prove(credential: dict, device_key, predicate: str, bind_hash: str) -> dict:
    """PLACEHOLDER for Longfellow. Longfellow proves the same three facts
    (issuer signature valid, attribute true, device key signed the binding)
    WITHOUT revealing the credential. This mock simply attaches it."""
    return {"mock": True, "predicate": predicate, "bind": bind_hash,
            "credential": credential,
            "device_sig": sign(device_key, "zkarma/mock-device-binding", bind_hash)}


def mock_zk_verify(proof: dict, trust: TrustStore, predicate: str, bind_hash: str) -> None:
    if proof.get("predicate") != predicate or proof.get("bind") != bind_hash:
        raise VerificationError("proof_unbound", "proof is for a different predicate/binding")
    # PKI HOOK: with real Longfellow, the website still does exactly this
    # first step to learn which issuer public key to feed the verifier.
    cred, issuer = verify_with_cert(proof["credential"], trust, Role.ISSUER, PURPOSE_CREDENTIAL)
    if cred["attributes"].get(predicate) is not True:
        raise VerificationError("predicate_false", f"{predicate} does not hold")
    verify(proof["device_sig"], public_key_from_b64(cred["device_key"]),
           "zkarma/mock-device-binding")


# ============================================================ website (T)
@dataclass
class Result:
    accepted: bool
    reason: str = "ok"
    detail: str = ""


class MockWebsite:
    CHALLENGE_TTL = 120

    def __init__(self, origin, cert, key, trust: TrustStore,
                 clock: Callable[[], float] = time.time):
        self.origin, self.cert, self.key, self.trust, self.clock = origin, cert, key, trust, clock
        self.registry = ClientKeyRegistry(origin)       # PKI HOOK: pairwise client keys
        self.challenges: dict[str, dict] = {}
        self.used_challenges: set[str] = set()
        self.executed_actions: set[str] = set()         # action-level ledger
        self.executed_log: list[dict] = []
        self._lock = threading.Lock()

    # Step 1: agent asks to perform an operation -> website returns signed challenge
    def handle_agent_request(self, req_env: dict) -> dict:
        # PKI HOOK: verify the agent's certificate and request signature.
        req, agent = verify_with_cert(req_env, self.trust, Role.AGENT, PURPOSE_AGENT_REQUEST)
        if req.get("site") != self.origin:
            raise VerificationError("wrong_site", "request is for another site")
        now = int(self.clock())
        ch = {"challenge_id": secrets.token_hex(16), "site": self.origin,
              "operation": req["operation"], "predicate": PREDICATE,
              "agent_id": agent.name, "agent_kid": agent.key_id,
              "nonce": secrets.token_hex(16),
              "issued_at": now, "expires_at": now + self.CHALLENGE_TTL}
        self.challenges[ch["challenge_id"]] = ch
        # PKI HOOK: sign the challenge with the website's certified key.
        return sign(self.key, PURPOSE_CHALLENGE, ch, cert=self.cert)

    # Step 3: agent presents the user's authorization + proof
    def handle_presentation(self, pres_env: dict) -> Result:
        try:
            return self._handle_presentation(pres_env)
        except VerificationError as e:
            return Result(False, e.code, e.detail)
        except (KeyError, TypeError) as e:
            return Result(False, "malformed", str(e))

    def _handle_presentation(self, pres_env: dict) -> Result:
        # (a) Who is presenting? PKI HOOK: agent cert + signature.
        pres, presenter = verify_with_cert(pres_env, self.trust, Role.AGENT, PURPOSE_PRESENTATION)
        auth_env, proof = pres["authorization"], pres["proof"]
        auth_claimed = auth_env["payload"]

        # (b) Right site?
        if auth_claimed.get("site") != self.origin or pres.get("site") != self.origin:
            raise VerificationError("wrong_site", "authorization is for another site")

        # (c) Did a registered user sign it? PKI HOOK: pairwise client key.
        client_pub = self.registry.get(auth_env.get("kid"))
        auth = verify(auth_env, client_pub, PURPOSE_AUTHORIZATION)

        # (d) Is it an answer to a challenge WE issued, unmodified?
        ch = self.challenges.get(auth["challenge_id"])
        if ch is None:
            raise VerificationError("unknown_challenge", "challenge not issued here")
        if auth["challenge_hash"] != canonical_hash(ch) or auth["decision"] != "approve":
            raise VerificationError("bad_signature", "authorization does not match challenge")

        # (e) Agent binding: the presenter must be the agent the user approved.
        if presenter.name != ch["agent_id"] or presenter.key_id != ch["agent_kid"]:
            raise VerificationError("agent_mismatch",
                                    f"presented by {presenter.name}, authorized for {ch['agent_id']}")

        # (f) Freshness.
        if int(self.clock()) > ch["expires_at"]:
            raise VerificationError("expired", "challenge expired")

        # (g) Predicate proof bound to this exact authorization.
        mock_zk_verify(proof, self.trust, PREDICATE, canonical_hash(auth))

        # (h) Single use + action-level ledger (semantic replay), atomically.
        action_id = canonical_hash({"site": self.origin, "client": auth_env["kid"],
                                    "operation": ch["operation"]})
        with self._lock:
            if ch["challenge_id"] in self.used_challenges:
                raise VerificationError("replay", "challenge already answered")
            if action_id in self.executed_actions:
                raise VerificationError("semantic_replay", "this action already executed")
            self.used_challenges.add(ch["challenge_id"])
            self.executed_actions.add(action_id)
            self.executed_log.append(ch["operation"])
        return Result(True)


# ============================================================ client / wallet (P)
class MockClient:
    """The user's wallet. `intent` is what the user actually asked for."""

    def __init__(self, trust: TrustStore, issuer: MockIssuer, over_18: bool = True):
        self.trust = trust
        self.keyring = ClientKeyring()          # PKI HOOK: one key per site
        self.device_key = generate_key()
        self.credential = issuer.issue_credential(self.device_key.public_key(),
                                                  {PREDICATE: over_18, "issuing_state": "NY"})
        self.intent: dict | None = None         # {"site", "agent_id", "operation"}

    def registration_for(self, site: str) -> dict:
        """Handed DIRECTLY to the website (QR code / link), never via an agent."""
        return self.keyring.registration_for(site)

    def handle_challenge(self, ch_env: dict) -> dict:
        if self.intent is None:
            raise VerificationError("no_intent", "user has not delegated anything")
        # PKI HOOK: the challenge must come from the website the USER chose
        # (expected_name comes from the user's intent, not from the message).
        ch, site = verify_with_cert(ch_env, self.trust, Role.WEBSITE, PURPOSE_CHALLENGE,
                                    expected_name=self.intent["site"])
        # "What you see is what you sign": show the user the verified challenge.
        if not self.user_approves(ch):
            raise VerificationError("user_declined", "operation/agent differs from user intent")
        auth = {"challenge_id": ch["challenge_id"], "challenge_hash": canonical_hash(ch),
                "site": site.name, "agent_id": ch["agent_id"], "agent_kid": ch["agent_kid"],
                "decision": "approve"}
        auth_env = sign(self.keyring.key_for(site.name), PURPOSE_AUTHORIZATION, auth)
        proof = mock_zk_prove(self.credential, self.device_key, ch["predicate"],
                              canonical_hash(auth))
        return {"authorization": auth_env, "proof": proof}

    def user_approves(self, ch: dict) -> bool:
        # Stand-in for the approval screen on the phone.
        return (ch["operation"] == self.intent["operation"]
                and ch["agent_id"] == self.intent["agent_id"])


# ============================================================ agent (V)
class MockAgent:
    """An honest agent. Attacks in run_demo.py tamper with its messages."""

    def __init__(self, agent_id, cert, key):
        self.agent_id, self.cert, self.key = agent_id, cert, key

    def request(self, site: str, operation: dict) -> dict:
        # PKI HOOK: agent signs its request with its certified key.
        return sign(self.key, PURPOSE_AGENT_REQUEST, {"site": site, "operation": operation},
                    cert=self.cert)

    def present(self, site: str, client_response: dict) -> dict:
        return sign(self.key, PURPOSE_PRESENTATION, {"site": site, **client_response},
                    cert=self.cert)

    def run(self, website: MockWebsite, client: MockClient, operation: dict):
        """Full honest round trip. Returns (website Result, presentation)."""
        ch_env = wire(website.handle_agent_request(wire(self.request(website.origin, operation))))
        resp = wire(client.handle_challenge(ch_env))
        pres = wire(self.present(website.origin, resp))
        return website.handle_presentation(wire(pres)), pres
