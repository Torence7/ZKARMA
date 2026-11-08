# ZKARMA adversarial test suite

This suite provides **practical, reproducible checks of security threats that
ZKARMA is intended to withstand**. It drives the existing protocol simulation in
`demo/mock_parties.py`, using real signatures and certificate verification from
`zkarma_pki/`. It does not connect to `website/app.py`, run Longfellow, or require
an LLM. The existing demo and implementation are unchanged.

Passing means these particular experiments produced the expected behavior in
this simulation. It is not a security proof, exhaustive attack coverage, or
evidence that the actual website is secure. The suite complements the project's
formal analysis and future integration tests.

## Run

From the repository root, using Python 3.10 or later:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

# Run the adversarial suite, including honest controls.
python -m pytest tests/test_adversarial.py -v

# Select a category or run all existing and new tests.
python -m pytest tests/test_adversarial.py -v -k semantic
python -m pytest -q

# Save machine-readable results outside the source tree.
python -m pytest tests/test_adversarial.py --junitxml=/tmp/zkarma-adversarial.xml
```

No extra dependencies beyond the repository's existing requirements are needed.
Each test gets fresh temporary PKI material, wallet, websites, and ledgers. Tests
use synthetic credentials only; keys and signatures are freshly randomized, while
the attack steps and expected outcomes are fixed. Expiration uses a controlled
website clock instead of sleeping. Each concurrency variant runs three separate
rounds with 20 submissions per round. These are sampled thread schedules, not an
exhaustive concurrency analysis.

## Files and boundaries

| File | Purpose |
| --- | --- |
| `adversarial/attacks.py` | Reusable message transformations, presentation wrapping, sequential replay, and concurrent submission |
| `tests/test_adversarial.py` | Trusted setup, attack scenarios, explicit wallet approvals, and assertions |
| `demo/mock_parties.py` | Existing simulated issuer, wallet, agents, verifier, and execution ledger |
| `zkarma_pki/` | Existing real signing and identity verification |

The attack functions take captured messages, an agent with its own signing key,
or a submission callback. They copy messages before changing or submitting them.
They do not receive the wallet, issuer, ledger, or a way to approve arbitrary
actions. Valid outer agent signatures are regenerated when appropriate so tests
reach the intended inner authorization or proof check.

The trusted test harness may create credentials, set the user's intent, advance
the test clock, and observe execution logs. Those are **experiment setup and
measurement powers**, not attacker powers. Python object boundaries are a coding
convention here, not a sandbox against hostile Python code.

## Threat coverage

The nine categories follow the proposal's security evaluation (pages 4–5) and
the supplied presentation's threat model and evaluation (slides 12–15 and 19).

| Threat | Experiment | Required result |
| --- | --- | --- |
| Exact replay | Submit the same signed presentation twice | First accepted; second rejected with `replay`; one execution |
| Cross-website reuse | Present A's authorization at B, with a valid agent wrapper targeting B | `wrong_site`; no execution at either site |
| Agent impersonation | B signs a presentation containing A's approved authorization | `agent_mismatch`; no execution |
| Operation tampering | Redirect approval to a challenge with changed quantity, item, action type, or order reference | `bad_signature`; changed action never executes |
| Expiration | Submit after the challenge's validity window | `expired`; no execution |
| Invalid proof | Corrupt the device signature inside the mock proof | `bad_signature`; no execution |
| Concurrent replay | Submit 20 copies of one valid presentation together | Exactly one success and execution; other submissions report `replay` |
| Semantic replay | Obtain a fresh challenge and proof for an executed authorization | `semantic_replay`; total executions remain one |
| Colluding agents | A and B exchange valid authorization bundles, then present under their own identities | Both exchanges rejected with `agent_mismatch` |

Additional checks cover:

- A proof from Site A substituted into an otherwise valid Site B authorization.
- A proof substituted between two authorizations on the same site.
- Twenty distinct fresh proofs for the same action submitted concurrently;
  losers must report `semantic_replay`, not duplicate-challenge replay.
- A changed signed challenge rejected **by the wallet** before approval.
- A validly signed request with an unapproved new order reference declined by
  the wallet. The attacker cannot create user approval by renaming an order.
- A composed sequence: corrupt a proof, present it as the other agent, and replay
  it three times; then present the corrupted proof as the intended agent.
- Honest authorization for each agent, and an explicitly approved second purchase
  with the same item and quantity but a different order reference.

Several negative tests subsequently redeem the untouched original authorization
to verify that the input was usable and that a reject-everything implementation
cannot satisfy the full suite. Positive controls provide additional coverage.

## What counts as semantic replay?

For these fixtures, the trusted wallet initially approves:

```text
task-42: purchase one bottle of wine at Site A through Agent A
```

The wallet can generate fresh proofs for that same intent. Fresh challenges,
nonces, and proof bytes must not permit executing it again. The existing mock
website identifies consumed actions by hashing site, wallet key ID, and the
complete operation (including `order_ref`).

A second purchase with `order_ref=task-43` succeeds only after the trusted harness
models a separate user approval. Identical item/quantity alone is not a replay.
This models the current implementation's action identity; it does not solve the
general problem of recognizing semantically equivalent natural-language tasks.
The real website currently uses a different, `op_id`-based representation and
will need its own integration tests later.

## Reading results

Pytest reports individual scenarios and returns a nonzero exit status for a
failure or error. Tests check expected rejection reasons **and exact executed
operations**, plus consumption-ledger counts at both sites. Unexpected exceptions
and worker crashes propagate and cannot count as successful rejection. Concurrent
tests require one legitimate success as well as no duplicate execution.

Wallet-side rejection is explicitly named separately from website rejection.
There are two test-harness checks: a deliberate test-only disabling of semantic
ledger membership confirms the execution assertion catches a duplicate, and a
simulated worker crash confirms the concurrency helper propagates errors. Neither
is an attacker capability or a counted protocol defense.

The suite currently produces pytest/JUnit results, **not an acceptance-rate
benchmark**. A pass count is not an unauthorized acceptance rate. For a later
measurement runner, record individual submissions and executions, separate setup
and honest controls from attack attempts, exclude the permitted first concurrent
execution from attack successes, and report errors separately. Measure legitimate
acceptance and unauthorized acceptance with those denominators explicitly stated.

## Later use as tools for an LLM agent

Yes: these primitives can become tools for an LLM that chooses attack parameters,
sequences multiple attacks, and adapts to observed rejections. An LLM need not be
trained to be malicious; it can orchestrate the programmable capabilities.

For example, the existing composition test demonstrates:

```text
captured wallet response
  -> corrupt_proof
  -> present_as(Agent B)
  -> replay(count=3)
```

The same captured response can be transformed again, sent to another configured
site, or combined with another captured proof. Scenarios can retain messages and
reuse state between steps; only separate test cases reset the environment.

Before exposing these functions to an LLM, add a narrow tool wrapper that:

1. Uses opaque message and agent handles instead of exposing Python objects,
   private keys, or the whole test harness.
2. Restricts submissions to the configured experimental sites and controlled agent
   identities, with bounded request counts and concurrency.
3. Lets the trusted wallet independently enforce a preconfigured approval policy.
   Approval changes and clock advancement remain harness-controlled events.
4. Records tool calls, parameters, responses, and trusted execution observations so
   discovered sequences can become deterministic regression tests.

The model should choose attacks; the harness should judge success. Do not let the
model edit the ledger, set user intent, mint arbitrary wallet proofs, or decide
that its own attack passed. This commit-sized implementation supplies reusable
Python primitives and one composition test, not an LLM integration or tool server.

## Limits of the evidence

- The proof is a mock that exposes credential attributes and a device public key.
  These tests establish neither credential confidentiality nor zero knowledge.
- Signature checks are real, but passing mock proof checks says nothing about
  Longfellow soundness or complete proof-format validation.
- The suite checks a finite set of attack variants. It does not claim every
  malformed message, every attack composition, or every adaptive corruption
  strategy is covered. Existing PKI/demo tests retain their separate coverage.
- Collusion here means sharing messages, not using the authorized agent's private
  key. If that key is shared or compromised, signatures alone cannot distinguish
  the collaborator from the authorized agent. The hardware/non-transferable ID
  assumption mentioned in the presentation is not implemented by this suite.
- Ledger protection is measured in one process with in-memory state. Restart
  durability, multiple workers, distributed races, HTTP authentication, real order
  side effects, and database transactions require later integration testing.
- Thread barriers encourage contention; they do not guarantee all possible
  interleavings. Callbacks are the local mock verifier; the concurrency helper is
  not a hard-timeout sandbox for an arbitrarily hanging remote service.

The practical claim is deliberately narrow: **under these explicit setups, the
existing simulated protocol rejects the listed unauthorized behaviors while
allowing the tested legitimate operations.**
