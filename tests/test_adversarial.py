"""Practical security checks against existing mock parties and real PKI.

Run independently: python -m pytest tests/test_adversarial.py -v
"""
from copy import deepcopy
from dataclasses import dataclass
import time

import pytest

from adversarial import attacks
from demo.mock_parties import MockAgent, MockClient, MockIssuer, MockWebsite, wire
from zkarma_pki import PKI, Role, TrustStore, VerificationError

SITE_A = "https://shop.test"
SITE_B = "https://other.test"
OP = {"type": "purchase", "item": "wine-cabernet-750ml", "qty": 1, "order_ref": "task-42"}


@dataclass
class Harness:
    """Trusted fixture: do not expose this object as a future LLM tool."""
    sites: dict
    agents: dict
    wallet: MockClient
    now: list

    def approve(self, agent="a", site=SITE_A, operation=None):
        # Represents explicit user approval in setup, never an attacker action.
        self.wallet.intent = {"site": site, "agent_id": self.agents[agent].agent_id,
                              "operation": deepcopy(OP if operation is None else operation)}

    def challenge(self, agent="a", site=SITE_A, operation=None):
        request = self.agents[agent].request(site, deepcopy(OP if operation is None else operation))
        return wire(self.sites[site].handle_agent_request(wire(request)))

    def response(self, agent="a", site=SITE_A, operation=None):
        return wire(self.wallet.handle_challenge(self.challenge(agent, site, operation)))

    def presentation(self, agent="a", site=SITE_A, operation=None):
        return attacks.present_as(self.agents[agent], site, self.response(agent, site, operation))

    def submit(self, presentation, site=SITE_A):
        return self.sites[site].handle_presentation(wire(presentation))

    def assert_executed(self, expected_a=(), expected_b=()):
        # Check exact actions, not just status codes or ledger cardinality.
        for origin, expected in [(SITE_A, expected_a), (SITE_B, expected_b)]:
            website = self.sites[origin]
            assert website.executed_log == list(expected)
            assert len(website.executed_actions) == len(expected)
            assert len(website.used_challenges) == len(expected)


@pytest.fixture
def world(tmp_path):
    pki = PKI.create(tmp_path / "pki")
    def trust():
        return TrustStore.from_bundle(pki.base / "trust_bundle")
    now = [time.time()]
    issuer = MockIssuer(*pki.issue(Role.ISSUER, "test-dmv"))
    wallet = MockClient(trust(), issuer)
    sites = {origin: MockWebsite(origin, *pki.issue(Role.WEBSITE, origin), trust(),
                                 clock=lambda: now[0]) for origin in (SITE_A, SITE_B)}
    agents = {name: MockAgent(name, *pki.issue(Role.AGENT, name)) for name in ("a", "b")}
    for origin, site in sites.items():
        site.registry.register(wallet.registration_for(origin))
    harness = Harness(sites, agents, wallet, now)
    harness.approve()
    return harness


def rejected(result, reason):
    assert result.accepted is False, result
    assert result.reason == reason, result


def assert_single_execution(world, results, reason):
    assert sum(r.accepted for r in results) == 1, results
    assert all(r.reason == reason for r in results if not r.accepted), results
    world.assert_executed([OP])


@pytest.mark.parametrize("agent", ["a", "b"])
def test_honest_authorized_agent(world, agent):
    world.approve(agent)
    assert world.submit(world.presentation(agent)).accepted
    world.assert_executed([OP])


def test_separately_approved_identical_purchase(world):
    assert world.submit(world.presentation()).accepted
    second = {**OP, "order_ref": "task-43"}
    world.approve(operation=second)
    assert world.submit(world.presentation(operation=second)).accepted
    world.assert_executed([OP, second])


def test_exact_replay(world):
    results = attacks.replay(world.submit, world.presentation())
    assert results[0].accepted
    rejected(results[1], "replay")
    world.assert_executed([OP])


def test_cross_website_reuse(world):
    response = world.response()
    presentation = attacks.present_as(world.agents["a"], SITE_B, response)
    rejected(world.submit(presentation, SITE_B), "wrong_site")
    world.assert_executed()
    # The donor authorization really was valid and unconsumed.
    assert world.submit(attacks.present_as(world.agents["a"], SITE_A, response)).accepted
    world.assert_executed([OP])


def test_cross_website_proof_substitution(world):
    response_a = world.response()
    world.approve(site=SITE_B)
    response_b = world.response(site=SITE_B)
    mixed = attacks.substitute_proof(response_b, response_a)
    rejected(world.submit(attacks.present_as(world.agents["a"], SITE_B, mixed), SITE_B),
             "proof_unbound")
    world.assert_executed()
    assert world.submit(attacks.present_as(world.agents["a"], SITE_B, response_b), SITE_B).accepted
    world.assert_executed(expected_b=[OP])


def test_agent_impersonation(world):
    response = world.response()
    rejected(world.submit(attacks.present_as(world.agents["b"], SITE_A, response)), "agent_mismatch")
    world.assert_executed()
    assert world.submit(attacks.present_as(world.agents["a"], SITE_A, response)).accepted
    world.assert_executed([OP])


@pytest.mark.parametrize("change", [{"qty": 10}, {"item": "wine-merlot-750ml"},
                                    {"type": "transfer"}, {"order_ref": "task-evil"}])
def test_operation_tampering_after_approval(world, change):
    response = world.response()
    other_challenge = world.challenge(operation={**OP, **change})
    altered = attacks.redirect_authorization(response, other_challenge)
    rejected(world.submit(attacks.present_as(world.agents["a"], SITE_A, altered)), "bad_signature")
    world.assert_executed()
    assert world.submit(attacks.present_as(world.agents["a"], SITE_A, response)).accepted
    world.assert_executed([OP])


def test_operation_tampering_before_approval_stopped_by_wallet(world):
    challenge = world.challenge()
    altered = attacks.change_challenge_operation(challenge, qty=10)
    with pytest.raises(VerificationError) as exc:
        world.wallet.handle_challenge(altered)
    assert exc.value.code == "bad_signature"
    world.assert_executed()
    assert challenge["payload"]["operation"] == OP


def test_new_order_reference_without_user_approval_is_declined(world):
    challenge = world.challenge(operation={**OP, "order_ref": "task-evil"})
    with pytest.raises(VerificationError) as exc:
        world.wallet.handle_challenge(challenge)
    assert exc.value.code == "user_declined"
    world.assert_executed()


def test_expired_authorization(world):
    challenge = world.challenge()
    response = wire(world.wallet.handle_challenge(challenge))
    world.now[0] = challenge["payload"]["expires_at"] + 1
    rejected(world.submit(attacks.present_as(world.agents["a"], SITE_A, response)), "expired")
    world.assert_executed()


def test_invalid_proof(world):
    response = world.response()
    altered = attacks.corrupt_proof(response)
    rejected(world.submit(attacks.present_as(world.agents["a"], SITE_A, altered)), "bad_signature")
    world.assert_executed()
    assert world.submit(attacks.present_as(world.agents["a"], SITE_A, response)).accepted
    world.assert_executed([OP])


def test_proof_from_another_authorization(world):
    donor, recipient = world.response(), world.response()
    mixed = attacks.substitute_proof(recipient, donor)
    rejected(world.submit(attacks.present_as(world.agents["a"], SITE_A, mixed)), "proof_unbound")
    world.assert_executed()


@pytest.mark.parametrize("round_number", range(3))
def test_concurrent_exact_replay(world, round_number):
    presentation = world.presentation()
    results = attacks.submit_concurrently(world.submit, [presentation] * 20)
    assert_single_execution(world, results, "replay")


def test_semantic_replay(world):
    first = world.presentation()
    assert world.submit(first).accepted
    fresh = world.presentation()
    assert first["payload"]["authorization"]["payload"]["challenge_id"] != \
        fresh["payload"]["authorization"]["payload"]["challenge_id"]
    assert first["payload"]["proof"] != fresh["payload"]["proof"]
    rejected(world.submit(fresh), "semantic_replay")
    world.assert_executed([OP])


@pytest.mark.parametrize("round_number", range(3))
def test_concurrent_semantic_replay(world, round_number):
    presentations = [world.presentation() for _ in range(20)]
    challenge_ids = {p["payload"]["authorization"]["payload"]["challenge_id"] for p in presentations}
    assert len(challenge_ids) == 20
    results = attacks.submit_concurrently(world.submit, presentations)
    assert_single_execution(world, results, "semantic_replay")


def test_colluding_agents_exchange_proofs(world):
    response_a = world.response()
    operation_b = {**OP, "order_ref": "task-for-b"}
    world.approve("b", operation=operation_b)
    response_b = world.response("b", operation=operation_b)
    for presenter, stolen in [("b", response_a), ("a", response_b)]:
        rejected(world.submit(attacks.present_as(world.agents[presenter], SITE_A, stolen)),
                 "agent_mismatch")
    world.assert_executed()
    for presenter, own in [("a", response_a), ("b", response_b)]:
        assert world.submit(attacks.present_as(world.agents[presenter], SITE_A, own)).accepted
    world.assert_executed([OP, operation_b])


def test_composed_impersonation_corruption_and_replay(world):
    response = world.response()
    corrupted = attacks.corrupt_proof(response)
    forged = attacks.present_as(world.agents["b"], SITE_A, corrupted)
    for result in attacks.replay(world.submit, forged, count=3):
        # Identity checking precedes proof checking: report the actual defense.
        rejected(result, "agent_mismatch")
    world.assert_executed()
    rejected(world.submit(attacks.present_as(world.agents["a"], SITE_A, corrupted)), "bad_signature")
    world.assert_executed()
    assert world.submit(attacks.present_as(world.agents["a"], SITE_A, response)).accepted
    world.assert_executed([OP])


def test_execution_assertion_detects_disabled_semantic_ledger(world, monkeypatch):
    # Test-only deliberate fault, never an attacker capability or production fix.
    class ForgetfulSet(set):
        def __contains__(self, item):
            return False
    monkeypatch.setattr(world.sites[SITE_A], "executed_actions", ForgetfulSet())
    assert world.submit(world.presentation()).accepted
    assert world.submit(world.presentation()).accepted
    with pytest.raises(AssertionError):
        world.assert_executed([OP])


def test_concurrency_worker_crash_is_not_a_rejection():
    def broken_submit(message):
        raise RuntimeError("simulated verifier crash")
    with pytest.raises(RuntimeError, match="simulated verifier crash"):
        attacks.submit_concurrently(broken_submit, [{}, {}])
