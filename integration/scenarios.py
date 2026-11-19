"""Integrated PKI scenarios: honest flows and attacks against the REAL website,
wallet and agent (not the mock parties in pki/demo/).

Each scenario is `fn(system) -> Result`. The attacker controls the agent (the
untrusted relay) and may own its own certified agent or website identities;
it never holds the user's wallet, the PKI's CA keys or the real website's key.

Scenarios marked `contrast=True` also run against today's system (dev header
identity, unsigned challenges, dev-proof) so the PKI's contribution is visible.
"""
from __future__ import annotations

import copy
import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path

from integration.harness import System  # first: puts pki/, client/, website/ on sys.path

from agent.http import JsonHTTP  # noqa: E402
from spec import zkarma_spec as spec  # noqa: E402
from zkarma_pki import PKI, Role, sign  # noqa: E402
from zkarma_pki.keys import cert_to_pem, generate_key  # noqa: E402

from integration.pki_adapters import (PURPOSE_HTTP_REQUEST, SIGNATURE_HEADER,  # noqa: E402
                                      AgentRequestSigner, SignedTransport, WebsiteMessageSigner,
                                      encode_compact)

WINE = {"item_id": "wine-001", "quantity": 1}


@dataclass
class Result:
    id: str
    title: str
    kind: str                 # "honest" | "attack"
    mode: str                 # "pki" | "nopki" | "dev"
    accepted: bool            # honest: the flow completed; attack: the attacker got what it wanted
    stopped_at: str = "-"     # website | wallet | agent | -
    reason: str = "ok"
    user_prompted: bool = False
    note: str = ""

    @property
    def correct(self) -> bool:
        return self.accepted if self.kind == "honest" else not self.accepted

    def row(self) -> dict:
        return {**asdict(self), "correct": self.correct}


@dataclass
class Scenario:
    id: str
    title: str
    kind: str
    fn: object
    contrast: bool = False
    needs: str = "public-catalog"   # website variant it targets
    extra: dict = field(default_factory=dict)


SCENARIOS: list[Scenario] = []


def scenario(id, title, kind="attack", contrast=False, needs="public-catalog"):
    def deco(fn):
        SCENARIOS.append(Scenario(id, title, kind, fn, contrast, needs))
        return fn
    return deco


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _site_reason(s: System, before: Counter) -> str:
    if not s.pki_mode:
        return ""
    diff = s.site_verifier.rejections - before
    return ",".join(sorted(diff)) or ""


def _wallet_reason(s: System, before: Counter) -> str:
    if not s.pki_mode:
        return ""
    diff = s.wallet_verifier.rejections - before
    return ",".join(sorted(diff)) or ""


def _snap(s: System):
    if not s.pki_mode:
        return Counter(), Counter()
    return Counter(s.site_verifier.rejections), Counter(s.wallet_verifier.rejections)


def _result(s, sc_id, title, kind, accepted, stopped_at="-", reason="ok", note=""):
    return Result(sc_id, title, kind, s.mode, accepted, stopped_at, reason,
                  bool(s.consent.prompts), note)


def _get_challenge(agent, body=None):
    code, b = agent.site("POST", "/checkout", body or WINE)
    assert code == 401, (code, b)
    return b["challenge"]


def _raw(s: System, method, base, path, body, headers):
    return JsonHTTP().request(method, base + path, body, headers)


def _http_reject(s, code, body, site_before, title, sc_id, where="website"):
    reason = body.get("error", f"http_{code}")
    detail = _site_reason(s, site_before) if where == "website" else ""
    return _result(s, sc_id, title, "attack", False, where, f"{reason}" + (f" ({detail})" if detail else ""))


def _attacker_pki(s: System):
    """An attacker-run CA that mimics ZKARMA's names. Not in anyone's trust bundle."""
    return PKI.create(s.tmp / "rogue_pki")


# ----------------------------------------------------------------------------
# honest flows
# ----------------------------------------------------------------------------
@scenario("H1", "Safe agent buys an age-restricted item (wine)", "honest", contrast=True)
def h1(s):
    a = s.safe_agent()
    a.browse_products()
    r = a.purchase("wine-001")
    return _result(s, "H1", "", "honest", r["status"] == "placed", reason=r["status"])


@scenario("H2", "Safe agent buys an unrestricted item (no proof needed)", "honest", contrast=True)
def h2(s):
    a = s.safe_agent()
    a.browse_products()
    r = a.purchase("water-001")
    return _result(s, "H2", "", "honest", r["status"] == "placed" and not s.consent.prompts,
                   reason=r["status"])


@scenario("H3", "A second, separately certified agent buys for the same user", "honest", contrast=True)
def h3(s):
    s.add_agent("agent-2")
    a = s.safe_agent("agent-2")
    a.browse_products()
    r = a.purchase("vape-001")
    return _result(s, "H3", "", "honest", r["status"] == "placed", reason=r["status"])


@scenario("H4", "Revoking agent-1 does not affect agent-2", "honest")
def h4(s):
    s.add_agent("agent-2")
    s.revoke_agent("safe-agent")
    a = s.safe_agent("agent-2")
    a.browse_products()
    r = a.purchase("wine-001")
    return _result(s, "H4", "", "honest", r["status"] == "placed", reason=r["status"])


@scenario("H5", "Main-branch website: enter (session) -> browse -> checkout", "honest",
          contrast=True, needs="enter+session")
def h5(s):
    a = s.raw_agent()
    t = a.run_operation("/enter")
    if t["code"] != 200:
        return _result(s, "H5", "", "honest", False, t["step"], str(t["body"]))
    h = {"Authorization": f"ZKARMA {t['body']['session_token']}"}
    code, _ = a.site("GET", "/products", headers=h)
    t = a.run_operation("/checkout", {"item_id": "wine-001", "quantity": 2}, headers=h)
    ok = code == 200 and t["code"] == 200 and t["body"].get("status") == "placed"
    return _result(s, "H5", "", "honest", ok, reason=t["body"].get("status", str(t["body"])))


# ----------------------------------------------------------------------------
# attacks on agent identity (website / wallet verify agent requests)
# ----------------------------------------------------------------------------
@scenario("A1", "Request with no signature, only the dev identity header", contrast=True)
def a1(s):
    sb, _ = _snap(s)
    code, body = _raw(s, "POST", s.origin, "/checkout", WINE, {"X-Dev-Agent-Thumbprint": "safe-agent"})
    if code == 401 and body.get("error") == "age_check_required":
        return _result(s, "A1", "", "attack", True, note="website accepted the claimed identity")
    return _http_reject(s, code, body, sb, "", "A1")


@scenario("A2", "Unpaired agent claims to be the user's paired agent at the wallet", contrast=True)
def a2(s):
    # The attacker obtained a genuine challenge (it can ask the website itself).
    evil = s.add_agent("agent-evil", pair=False)
    if s.pki_mode:
        attacker = s.raw_agent("agent-evil")          # can only sign as itself
    else:
        attacker = s.raw_agent("safe-agent")          # dev: just claims the paired name
    ch = _get_challenge(attacker)
    _, wb = _snap(s)
    code, ans = attacker.authorize(ch)
    if ans.get("status") == "approved":
        return _result(s, "A2", "", "attack", True, note="wallet produced a proof for the impostor")
    return _result(s, "A2", "", "attack", False, "wallet", ans.get("error", ans.get("status")))


@scenario("A3", "Agent certificate forged by an attacker-run CA")
def a3(s):
    rogue = _attacker_pki(s)
    cert, key = rogue.issue(Role.AGENT, "safe-agent")
    sb, _ = _snap(s)
    code, body = s.raw_agent(transport=_signed(AgentRequestSigner(key, cert))).site("POST", "/checkout", WINE)
    return _outcome_site(s, "A3", code, body, sb)


@scenario("A4", "Stolen agent certificate presented without its private key")
def a4(s):
    victim = s.agents["safe-agent"]
    attacker_key = generate_key()
    url = s.origin + "/checkout"
    payload = AgentRequestSigner(attacker_key, None).payload("POST", url, json.dumps(WINE).encode())
    env = sign(attacker_key, PURPOSE_HTTP_REQUEST, payload)
    env["cert"] = cert_to_pem(victim.cert)
    sb, _ = _snap(s)
    code, body = _raw(s, "POST", s.origin, "/checkout", WINE, {SIGNATURE_HEADER: encode_compact(env)})
    return _outcome_site(s, "A4", code, body, sb)


@scenario("A5", "Agent revoked after compromise keeps sending requests")
def a5(s):
    a = s.raw_agent()
    _get_challenge(a)  # works before revocation
    s.revoke_agent("safe-agent")
    sb, _ = _snap(s)
    code, body = a.site("POST", "/checkout", WINE)
    return _outcome_site(s, "A5", code, body, sb)


@scenario("A6", "Agent certificate past its expiry")
def a6(s):
    s.add_agent("old-agent", ttl=timedelta(seconds=-30))
    sb, _ = _snap(s)
    code, body = s.raw_agent("old-agent").site("POST", "/checkout", WINE)
    return _outcome_site(s, "A6", code, body, sb)


@scenario("A7", "Website certificate used as an agent certificate (role confusion)")
def a7(s):
    cert, key = s.pki.issue(Role.WEBSITE, "http://evil.test")   # attacker legitimately owns evil.test
    sb, _ = _snap(s)
    code, body = s.raw_agent(transport=_signed(AgentRequestSigner(key, cert))).site("POST", "/checkout", WINE)
    return _outcome_site(s, "A7", code, body, sb)


@scenario("A8", "Exact replay of a captured signed request", contrast=True)
def a8(s):
    url = s.origin + "/checkout"
    headers = (s.agents["safe-agent"].signer().headers("POST", url, json.dumps(WINE).encode())
               if s.pki_mode else {"X-Dev-Agent-Thumbprint": "safe-agent"})
    first = _raw(s, "POST", s.origin, "/checkout", WINE, headers)
    assert first[0] == 401, first
    sb, _ = _snap(s)
    code, body = _raw(s, "POST", s.origin, "/checkout", WINE, headers)
    if code == 401 and body.get("error") == "age_check_required":
        return _result(s, "A8", "", "attack", True, note="replayed request created a second operation")
    return _http_reject(s, code, body, sb, "", "A8")


@scenario("A9", "Request body changed in transit (quantity 1 -> 10)", contrast=True)
def a9(s):
    url = s.origin + "/checkout"
    tampered = {"item_id": "wine-001", "quantity": 10}
    headers = (s.agents["safe-agent"].signer().headers("POST", url, json.dumps(WINE).encode())
               if s.pki_mode else {"X-Dev-Agent-Thumbprint": "safe-agent"})
    sb, _ = _snap(s)
    code, body = _raw(s, "POST", s.origin, "/checkout", tampered, headers)
    if code == 401 and body.get("challenge", {}).get("operation", {}).get("quantity") == 10:
        return _result(s, "A9", "", "attack", True, note="website accepted the altered body")
    return _http_reject(s, code, body, sb, "", "A9")


@scenario("A10", "Request signed for the wallet replayed to the website")
def a10(s):
    signer = s.agents["safe-agent"].signer()
    headers = signer.headers("POST", s.wallet_origin + "/checkout", json.dumps(WINE).encode())
    sb, _ = _snap(s)
    code, body = _raw(s, "POST", s.origin, "/checkout", WINE, headers)
    return _outcome_site(s, "A10", code, body, sb)


@scenario("A11", "Website's agent CRL is stale (no fresh revocation info)")
def a11(s):
    # Run the website verifier 2 days ahead: the 1-day CRL is stale while the
    # 7-day agent certificate is still valid. Must fail closed.
    import time as _t
    s.add_agent("week-agent", ttl=timedelta(days=7))
    s.site_verifier.clock = lambda: _t.time() + 2 * 86400
    sb, _ = _snap(s)
    code, body = s.raw_agent("week-agent").site("POST", "/checkout", WINE)
    return _outcome_site(s, "A11", code, body, sb)


# ----------------------------------------------------------------------------
# attacks on challenges (wallet verifies the website's signature)
# ----------------------------------------------------------------------------
@scenario("A12", "Agent rewrites the challenge's amount (and recomputes its hash)", contrast=True)
def a12(s):
    a = s.raw_agent()
    ch = _get_challenge(a)
    forged = copy.deepcopy(ch)
    forged["operation"]["amount_cents"] = 1
    forged["operation_hash"] = spec.operation_hash(forged["operation"]).hex()
    return _wallet_attack(s, a, "A12", forged)


@scenario("A13", "Agent forges a challenge and signs it with its own agent certificate")
def a13(s):
    a = s.raw_agent()
    ch = _get_challenge(a)
    me = s.agents["safe-agent"]
    forged = {k: v for k, v in ch.items() if k != "signature"}
    forged["signature"] = WebsiteMessageSigner(me.key, me.cert, spec.signed_payload).sign_message(forged)
    return _wallet_attack(s, a, "A13", forged)


@scenario("A14", "Challenge signed by a different certified website, relabelled as the user's site")
def a14(s):
    a = s.raw_agent()
    ch = _get_challenge(a)
    cert, key = s.pki.issue(Role.WEBSITE, "http://evil.test")
    forged = {k: v for k, v in ch.items() if k != "signature"}
    forged["signature"] = WebsiteMessageSigner(key, cert, spec.signed_payload).sign_message(forged)
    return _wallet_attack(s, a, "A14", forged)


@scenario("A15", "Agent strips the website's signature from the challenge (downgrade)")
def a15(s):
    a = s.raw_agent()
    ch = _get_challenge(a)
    ch.pop("signature", None)
    return _wallet_attack(s, a, "A15", ch, harmful_if_prompted=True)


# ----------------------------------------------------------------------------
# attacks on proofs (website binds proofs to its own transcript)
# ----------------------------------------------------------------------------
@scenario("A16", "Another agent redeems a proof the user approved for agent-1", contrast=True)
def a16(s):
    a = s.raw_agent()
    ch = _get_challenge(a)
    _, ans = a.authorize(ch)
    assert ans["status"] == "approved", ans
    if s.pki_mode:
        s.add_agent("agent-thief", pair=False)
        thief = s.raw_agent("agent-thief")
    else:
        thief = s.raw_agent("safe-agent")             # dev: thief claims agent-1's name
    sb, _ = _snap(s)
    code, body = thief.redeem(ans["nonce"], ans["proof"])
    if code == 200 and body.get("status") == "placed":
        return _result(s, "A16", "", "attack", True, note="thief's order was placed")
    return _http_reject(s, code, body, sb, "", "A16")


@scenario("A17", "Same proof redeemed twice", contrast=True)
def a17(s):
    a = s.raw_agent()
    t = a.run_operation("/checkout", WINE)
    assert t["code"] == 200, t
    sb, _ = _snap(s)
    code, body = a.redeem(t["approval"]["nonce"], t["approval"]["proof"])
    if code == 200:
        return _result(s, "A17", "", "attack", True)
    return _http_reject(s, code, body, sb, "", "A17")


@scenario("A18", "Proof for one order redeemed against a bigger order", contrast=True)
def a18(s):
    a = s.raw_agent()
    small = _get_challenge(a)
    big = _get_challenge(a, {"item_id": "wine-001", "quantity": 10})
    _, ans = a.authorize(small)
    sb, _ = _snap(s)
    code, body = a.redeem(big["nonce"], ans["proof"])
    if code == 200:
        return _result(s, "A18", "", "attack", True, note="bigger order placed with the small order's proof")
    return _http_reject(s, code, body, sb, "", "A18")


@scenario("A19", "Re-run an order that already ran (fresh challenge for the same op_id)", contrast=True)
def a19(s):
    a = s.raw_agent()
    t = a.run_operation("/checkout", WINE)
    assert t["code"] == 200, t
    op_id = t["challenge"]["op_id"]
    code, again = a.site("POST", f"/operations/{op_id}/challenge")
    prompts_before = len(s.consent.prompts)
    code, ans = a.authorize(again["challenge"])
    if ans.get("status") != "approved":
        r = _result(s, "A19", "", "attack", False, "wallet", ans.get("error", ans.get("status")))
        r.user_prompted = len(s.consent.prompts) > prompts_before
        return r
    sb, _ = _snap(s)
    code, body = a.redeem(ans["nonce"], ans["proof"])
    r = (_result(s, "A19", "", "attack", True) if code == 200
         else _http_reject(s, code, body, sb, "", "A19"))
    r.user_prompted = len(s.consent.prompts) > prompts_before
    return r


@scenario("A20", "Revoked agent asks the wallet directly for a proof")
def a20(s):
    a = s.raw_agent()
    ch = _get_challenge(a)
    s.revoke_agent("safe-agent")
    _, wb = _snap(s)
    code, ans = a.authorize(ch)
    if ans.get("status") == "approved":
        return _result(s, "A20", "", "attack", True)
    detail = _wallet_reason(s, wb)
    return _result(s, "A20", "", "attack", False, "wallet",
                   ans.get("error", ans.get("status")) + (f" ({detail})" if detail else ""))


# ----------------------------------------------------------------------------
def _signed(signer):
    return SignedTransport(signer, JsonHTTP())


def _outcome_site(s, sc_id, code, body, sb):
    if code == 401 and body.get("error") == "age_check_required":
        return _result(s, sc_id, "", "attack", True, note="website accepted the request")
    return _http_reject(s, code, body, sb, "", sc_id)


def _wallet_attack(s, agent, sc_id, forged, harmful_if_prompted=False):
    """Send a forged challenge to the wallet. Success for the attacker = the
    user is shown something the website never issued."""
    code, ans = agent.authorize(forged)
    prompted = bool(s.consent.prompts)
    if prompted:
        shown = s.consent.prompts[-1]
        r = _result(s, sc_id, "", "attack", True, "-", "user_prompted_with_unauthenticated_challenge",
                    note=f"user was shown amount_cents={shown.get('amount_cents')}")
        if ans.get("status") == "approved":
            sb, _ = _snap(s)
            c2, b2 = agent.redeem(ans["nonce"], ans["proof"])
            r.note += f"; website then answered {c2} {b2.get('error', b2.get('status'))}"
        return r
    return _result(s, sc_id, "", "attack", False, "wallet", ans.get("error", ans.get("status")))


def run(sc: Scenario, tmp: Path, mode: str = "pki", website_file=None) -> Result:
    with System(tmp, mode=mode, website_file=website_file) as s:
        if sc.needs != s.variant:
            raise LookupError(f"{sc.id} needs the {sc.needs} website, got {s.variant}")
        r = sc.fn(s)
    r.title = sc.title
    return r
