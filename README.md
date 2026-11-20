# ZKARMA: Zero-Knowledge Authorization for Restricted, Malicious Agents

A CSE 588 project at the University of Michigan.

AI agents increasingly browse websites and place orders on behalf of users,
while more and more websites are legally required to check a visitor's age.
Today, an agent that reaches an age check either gives up or is handed the
user's ID, which exposes the user's personal details and gives the agent a
reusable secret.

ZKARMA lets an agent pass an age check without ever holding the user's
credential. When the website asks for proof of age, the agent forwards the
challenge to the user's **wallet**. The wallet shows the user exactly what the
agent is trying to do. If the user approves, the wallet returns a
zero-knowledge proof that the user is over 18. The proof reveals nothing else
and is bound to that site, that agent, that operation and that challenge, so a
malicious agent cannot reuse it elsewhere or pass it to another agent.

```
 Website ──challenge──▶ Agent ──▶ Wallet ──▶ user approves
 Website ◀────proof──── Agent ◀── Wallet ◀── ZK proof bound to site + agent + operation + nonce
```

## Team

| Member                                | Component                          |
|---------------------------------------|------------------------------------|
| Prithviraj Renjella Rajendra Prasad   | Client (wallet) and ZK proofs      |
| Torence Mwindaare                     | Website                            |
| Vijay Vittala Prabhakaran             | Agents                             |
| Kaustubh Hari Sethi                   | Public key infrastructure          |

## Where everything is

All the components are integrated on the **`prithvi`** branch: the client, ZK
prover/verifier, PKI and safe agent are merged there, and their test suites
pass together.

| Directory              | What it is |
|------------------------|------------|
| [`client/`](client/)   | The user's trusted wallet: shows each operation for consent and produces the proof |
| [`website/`](website/) | Demo shop: public catalog, challenges for age-restricted checkout, proof verification |
| [`agent/`](agent/)     | The safe agent: an LLM shopper that relays challenges and proofs without ever seeing them |
| [`pki/`](pki/)         | Test public key infrastructure: DMV issuer, website and agent certificates and keys |
| [`zk/`](zk/)           | `zkage`, a CLI around Google's Longfellow ZK that proves and verifies mDL age claims |
| [`spec/`](spec/)       | Proposed shared message formats and test vectors (not yet used by the website) |

Each directory has its own README with setup and test instructions, except
`website/`, which is run as part of the agent's setup. To run the whole system
(website, wallet and agent in three terminals), start with
[agent/README.md](agent/README.md).
