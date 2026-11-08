"""ZKARMA PKI prototype: dummy end-to-end workflow + adversarial scenarios.

    python demo/run_demo.py            # human-readable report
    python demo/run_demo.py --json results.json

Each scenario builds a fresh world (new PKI, parties, keys) so they are
independent. Outcomes are summarised as the two metrics from the proposal:
legitimate acceptance rate and unauthorized acceptance rate.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mock_parties import MockAgent, MockClient, MockIssuer, MockWebsite, Result  # noqa: E402

from zkarma_pki import (PKI, PURPOSE_AGENT_REQUEST, PURPOSE_AUTHORIZATION,  # noqa: E402
                        PURPOSE_CHALLENGE, Role, TrustStore, VerificationError, generate_key,
                        sign)
from zkarma_pki.keys import cert_to_pem  # noqa: E402

SHOP, OTHER = "https://shop.test", "https://other.test"
OP = {"type": "purchase", "item": "wine-cabernet-750ml", "qty": 1, "order_ref": "task-42"}
OP2 = {"type": "purchase", "item": "wine-merlot-750ml", "qty": 1, "order_ref": "task-43"}


# ------------------------------------------------------------------ world
class World:
    """One complete test deployment: PKI + issuer + 2 websites + 2 agents + client."""

    def __init__(self, base: Path, over_18: bool = True, clock=None):
        self.pki = PKI.create(base)
        bundle = base / "trust_bundle"
        # Each party loads its OWN trust store from the out-of-band bundle.
        new_trust = lambda: TrustStore.from_bundle(bundle)  # noqa: E731
        self.issuer = MockIssuer(*self.pki.issue(Role.ISSUER, "test-dmv"))
        kw = {"clock": clock} if clock else {}
        self.shop = MockWebsite(SHOP, *self.pki.issue(Role.WEBSITE, SHOP), new_trust(), **kw)
        self.other = MockWebsite(OTHER, *self.pki.issue(Role.WEBSITE, OTHER), new_trust(), **kw)
        self.agent1 = MockAgent("agent-1", *self.pki.issue(Role.AGENT, "agent-1"))
        self.agent2 = MockAgent("agent-2", *self.pki.issue(Role.AGENT, "agent-2"))
        self.client = MockClient(new_trust(), self.issuer, over_18=over_18)
        # Out-of-band registration of the wallet's per-site keys.
        for site in (self.shop, self.other):
            site.registry.register(self.client.registration_for(site.origin))
        self.client.intent = {"site": SHOP, "agent_id": "agent-1", "operation": OP}


@dataclass
class Outcome:
    name: str
    kind: str          # "legit" or "attack"
    attempts: int
    accepted: int
    reason: str
    stage: str         # where it was stopped: website / client / -

    @property
    def passed(self) -> bool:
        return self.accepted == self.attempts if self.kind == "legit" else self.accepted == 0


SCENARIOS = []


def scenario(name, kind, **world_kw):
    def deco(fn):
        SCENARIOS.append((name, kind, world_kw, fn))
        return fn
    return deco


def at_website(r: Result) -> tuple[int, str, str]:
    return (1 if r.accepted else 0), r.reason, "website"


# ------------------------------------------------------------------ legit
@scenario("Honest flow: agent-1 buys for an adult user", "legit")
def s_honest(w: World):
    r, _ = w.agent1.run(w.shop, w.client, OP)
    return at_website(r)


@scenario("Second, different purchase is still allowed", "legit")
def s_second_action(w: World):
    w.agent1.run(w.shop, w.client, OP)
    w.client.intent["operation"] = OP2
    r, _ = w.agent1.run(w.shop, w.client, OP2)
    return at_website(r)


@scenario("User delegates to agent-2 instead", "legit")
def s_other_agent(w: World):
    w.client.intent["agent_id"] = "agent-2"
    r, _ = w.agent2.run(w.shop, w.client, OP)
    return at_website(r)


# ------------------------------------------------------------------ attacks
@scenario("Proof replay (same presentation sent twice)", "attack")
def s_replay(w: World):
    _, pres = w.agent1.run(w.shop, w.client, OP)
    return at_website(w.shop.handle_presentation(pres))


@scenario("Concurrent replay (20 threads, same presentation)", "attack")
def s_concurrent(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    pres = w.agent1.present(SHOP, w.client.handle_challenge(ch))
    results, barrier = [], threading.Barrier(20)

    def go():
        barrier.wait()
        results.append(w.shop.handle_presentation(pres))
    ts = [threading.Thread(target=go) for _ in range(20)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    ok = sum(r.accepted for r in results)
    # Exactly one acceptance is the legitimate execution; anything more is an attack success.
    reasons = sorted({r.reason for r in results if not r.accepted})
    return ok - 1, f"1 accepted, others: {','.join(reasons)}" if ok == 1 else f"{ok} accepted!", "website"


@scenario("Semantic replay (fresh challenge for an already-executed action)", "attack")
def s_semantic(w: World):
    w.agent1.run(w.shop, w.client, OP)
    r, _ = w.agent1.run(w.shop, w.client, OP)   # user's wallet happily approves again
    return at_website(r)


@scenario("Cross-website reuse (shop.test proof shown to other.test)", "attack")
def s_cross_site(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp = w.client.handle_challenge(ch)
    return at_website(w.other.handle_presentation(w.agent1.present(OTHER, resp)))


@scenario("Agent impersonation (agent-2 presents agent-1's authorization)", "attack")
def s_impersonate(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp = w.client.handle_challenge(ch)
    return at_website(w.shop.handle_presentation(w.agent2.present(SHOP, resp)))


@scenario("Stolen agent cert without its key", "attack")
def s_stolen_cert(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp = w.client.handle_challenge(ch)
    pres = w.agent2.present(SHOP, resp)
    pres["cert"] = cert_to_pem(w.agent1.cert)        # claim to be agent-1
    return at_website(w.shop.handle_presentation(pres))


@scenario("Forged agent cert from an attacker-run CA", "attack")
def s_forged_ca(w: World):
    with tempfile.TemporaryDirectory() as d:
        evil = PKI.create(d)
        cert, key = evil.issue(Role.AGENT, "agent-1")
        env = sign(key, PURPOSE_AGENT_REQUEST, {"site": SHOP, "operation": OP}, cert=cert)
    try:
        w.shop.handle_agent_request(env)
        return 1, "accepted", "website"
    except VerificationError as e:
        return 0, e.code, "website"


@scenario("Revoked agent (compromised mid-session)", "attack")
def s_revoked(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp = w.client.handle_challenge(ch)
    w.pki.revoke(Role.AGENT, w.agent1.cert)
    # Website pulls the new signed CRL (e.g. from the directory service).
    w.shop.trust.update_crl(Role.AGENT, (w.pki.base / "ca/agent/crl.pem").read_bytes())
    return at_website(w.shop.handle_presentation(w.agent1.present(SHOP, resp)))


@scenario("Operation tampering before the user sees it", "attack")
def s_tamper_challenge(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    ch["payload"]["operation"]["qty"] = 10   # agent edits the signed challenge
    try:
        w.client.handle_challenge(ch)
        return 1, "accepted", "client"
    except VerificationError as e:
        return 0, e.code, "client"


@scenario("Operation swap after the user signed", "attack")
def s_tamper_auth(w: World):
    ch_a = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp = w.client.handle_challenge(ch_a)
    evil_op = {**OP, "qty": 10}
    ch_b = w.shop.handle_agent_request(w.agent1.request(SHOP, evil_op))
    resp["authorization"]["payload"]["challenge_id"] = ch_b["payload"]["challenge_id"]
    return at_website(w.shop.handle_presentation(w.agent1.present(SHOP, resp)))


@scenario("Agent requests an operation the user never asked for", "attack")
def s_wrong_intent(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, {**OP, "qty": 10}))
    try:
        w.client.handle_challenge(ch)          # validly signed, but not what the user wants
        return 1, "accepted", "client"
    except VerificationError as e:
        return 0, e.code, "client"


@scenario("Fake challenge signed with an agent cert (cert-type confusion)", "attack")
def s_type_confusion(w: World):
    fake = sign(w.agent1.key, PURPOSE_CHALLENGE, {"site": SHOP, "operation": OP},
                cert=w.agent1.cert)
    try:
        w.client.handle_challenge(fake)
        return 1, "accepted", "client"
    except VerificationError as e:
        return 0, e.code, "client"


@scenario("Challenge from a different (real) website than the user chose", "attack")
def s_wrong_site_challenge(w: World):
    ch = w.other.handle_agent_request(w.agent1.request(OTHER, OP))
    try:
        w.client.handle_challenge(ch)
        return 1, "accepted", "client"
    except VerificationError as e:
        return 0, e.code, "client"


@scenario("Agent signs the authorization with its own key", "attack")
def s_agent_forges_auth(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp = w.client.handle_challenge(ch)
    resp["authorization"] = sign(generate_key(), PURPOSE_AUTHORIZATION,
                                 resp["authorization"]["payload"])
    return at_website(w.shop.handle_presentation(w.agent1.present(SHOP, resp)))


@scenario("Proof lifted from a different authorization", "attack")
def s_proof_swap(w: World):
    ch1 = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp1 = w.client.handle_challenge(ch1)
    ch2 = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp2 = w.client.handle_challenge(ch2)
    resp2["proof"] = resp1["proof"]
    return at_website(w.shop.handle_presentation(w.agent1.present(SHOP, resp2)))


@scenario("Expired challenge (presented after the 120 s window)", "attack", clock="fake")
def s_expired(w: World):
    ch = w.shop.handle_agent_request(w.agent1.request(SHOP, OP))
    resp = w.client.handle_challenge(ch)
    w.fake_time[0] += 200
    return at_website(w.shop.handle_presentation(w.agent1.present(SHOP, resp)))


@scenario("Credential from a fake DMV", "attack")
def s_fake_dmv(w: World):
    with tempfile.TemporaryDirectory() as d:
        evil = PKI.create(d)
        fake_issuer = MockIssuer(*evil.issue(Role.ISSUER, "test-dmv"))
    w.client.credential = fake_issuer.issue_credential(w.client.device_key.public_key(),
                                                       {"age_over_18": True})
    r, _ = w.agent1.run(w.shop, w.client, OP)
    return at_website(r)


@scenario("Under-18 user", "attack", over_18=False)
def s_minor(w: World):
    r, _ = w.agent1.run(w.shop, w.client, OP)
    return at_website(r)


# ------------------------------------------------------------------ runner
def run_all() -> list[Outcome]:
    out = []
    for name, kind, kw, fn in SCENARIOS:
        with tempfile.TemporaryDirectory() as d:
            fake_time = [1_800_000_000.0]
            wkw = {k: v for k, v in kw.items() if k != "clock"}
            if kw.get("clock") == "fake":
                import time as _t
                fake_time[0] = _t.time()
                wkw["clock"] = lambda: fake_time[0]
            w = World(Path(d), **wkw)
            w.fake_time = fake_time
            attempts = 19 if fn is s_concurrent else 1
            accepted, reason, stage = fn(w)
            out.append(Outcome(name, kind, attempts, accepted, reason, stage))
    return out


def report(results: list[Outcome]) -> bool:
    print("\nZKARMA PKI prototype: dummy workflow\n" + "=" * 100)
    print(f"{'':2}{'scenario':64}{'result':12}{'stopped at':11}reason")
    print("-" * 100)
    for r in results:
        if r.kind == "legit":
            res = "ACCEPTED" if r.accepted == r.attempts else "REJECTED"
            stage = "-" if r.accepted else r.stage
        else:
            res = "REJECTED" if r.accepted == 0 else f"ACCEPTED x{r.accepted}"
            stage = r.stage
        mark = "ok" if r.passed else "!!"
        print(f"{mark:2}{r.name[:63]:64}{res:12}{stage:11}{r.reason}")
    legit = [r for r in results if r.kind == "legit"]
    att = [r for r in results if r.kind == "attack"]
    la = sum(r.accepted for r in legit) / sum(r.attempts for r in legit)
    ua = sum(r.accepted for r in att) / sum(r.attempts for r in att)
    print("-" * 100)
    print(f"Legitimate acceptance rate:   {la:6.1%}  ({len(legit)} scenarios)")
    print(f"Unauthorized acceptance rate: {ua:6.1%}  ({len(att)} scenarios, "
          f"{sum(r.attempts for r in att)} attempts)")
    print("\nNote: the ZK proof is a MOCK that reveals the credential; Longfellow replaces it.")
    return all(r.passed for r in results)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write results to this file")
    a = ap.parse_args()
    res = run_all()
    ok = report(res)
    if a.json:
        Path(a.json).write_text(json.dumps([r.__dict__ for r in res], indent=2))
    sys.exit(0 if ok else 1)
