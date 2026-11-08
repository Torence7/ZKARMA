"""Composable attacks: only messages, agent signing, and submission callbacks.

Trusted setup, wallet approval, clock control, and execution observations belong
to the test harness, never to these functions. Inputs are copied like wire data.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Barrier


def change_challenge_operation(challenge, **changes):
    """Edit a website-signed operation without possessing the website key."""
    changed = deepcopy(challenge)
    changed["payload"]["operation"].update(changes)
    return changed


def redirect_authorization(response, challenge):
    """Point an approved wallet response at another challenge without re-signing."""
    changed = deepcopy(response)
    changed["authorization"]["payload"]["challenge_id"] = challenge["payload"]["challenge_id"]
    return changed


def substitute_proof(response, donor_response):
    """Mix an authorization with a proof obtained from a different exchange."""
    changed = deepcopy(response)
    changed["proof"] = deepcopy(donor_response["proof"])
    return changed


def corrupt_proof(response):
    """Alter the mock proof's device signature, leaving other bindings intact."""
    changed = deepcopy(response)
    signature = changed["proof"]["device_sig"]["sig"]
    changed["proof"]["device_sig"]["sig"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    return changed


def present_as(agent, site, response):
    """Rewrap captured material using this agent's own valid signature.

    Choosing another agent models impersonation/collusion; choosing another
    destination models cross-site reuse. No wallet signatures are regenerated.
    """
    return agent.present(site, deepcopy(response))


def replay(submit, presentation, count=2):
    """Sequentially submit independent copies of the same signed presentation."""
    if count < 1:
        raise ValueError("count must be positive")
    return [submit(deepcopy(presentation)) for _ in range(count)]


def submit_concurrently(submit, presentations):
    """Release a bounded batch together; propagate worker errors to the test.

    Identical messages exercise exact replay. Distinct fresh presentations for
    one authorization exercise semantic replay. Order of completion is arbitrary.
    """
    messages = deepcopy(list(presentations))
    if not 2 <= len(messages) <= 64:
        raise ValueError("use between 2 and 64 concurrent submissions")
    barrier = Barrier(len(messages), timeout=10)

    def send(message):
        barrier.wait()
        return submit(message)

    with ThreadPoolExecutor(max_workers=len(messages)) as pool:
        return list(pool.map(send, messages))
