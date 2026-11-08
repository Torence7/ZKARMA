# ZKARMA: Public Key Infrastructure (prototype v0.1)

The PKI component of ZKARMA, plus a dummy end-to-end workflow that exercises
it before the real agent, website and client exist.

**What the PKI is for:** it implements the security model's assumption that
_"the website gets the client's and issuer's verification information over an
authentic channel that doesn't involve any agent."_ For each party it answers
one question: "how do I know this public key really belongs to X, without
trusting the agent?"

| Verifier | Whose key    | How the PKI provides it                                      |
| -------- | ------------ | ------------------------------------------------------------ |
| Website  | Issuer (DMV) | Issuer-role cert, checked against the trust bundle           |
| Website  | Agent        | Agent-role cert (short-lived, revocable)                     |
| Website  | Client       | Pairwise per-site key, registered directly (no agent)        |
| Client   | Website      | Website-role cert, name must equal the site the _user_ chose |

## Quick start

```bash
pip install -r requirements.txt
python demo/run_demo.py          # dummy workflow + 18 attack scenarios
python -m pytest -q              # 44 tests
python demo/bench_pki.py         # PKI latency numbers
```

Running the test PKI by hand:

```bash
python -m zkarma_pki.cli init pki_out            # root, 3 CAs, demo entities
python -m zkarma_pki.cli issue pki_out agent agent-7
python -m zkarma_pki.cli revoke pki_out agent agent-7
python -m zkarma_pki.cli show pki_out

ZKARMA_PKI_DIR=pki_out ZKARMA_ADMIN_TOKEN=change-me \
  uvicorn zkarma_pki.directory:app --port 8400   # directory service
```

## Layout

```
zkarma_pki/
  canonical.py   canonical JSON (RFC 8785 subset): THE encoding for anything signed
  keys.py        P-256 keys, key IDs, PEM helpers
  roles.py       issuer / website / agent roles (EKU OIDs)
  ca.py          root + 3 intermediate CAs, issuance, revocation, CRLs, trust bundle
  trust.py       TrustStore.verify(): chain, role, validity, CRL, identity
  signing.py     signed envelopes (sign / verify / verify_with_cert) with purpose separation
  registry.py    pairwise client keys: ClientKeyring (wallet), ClientKeyRegistry (website)
  directory.py   FastAPI directory service (certs, CRLs, admin issue/revoke)
  cli.py         command-line tool
demo/
  mock_parties.py   MOCK issuer, Longfellow, client, agent, website  ("PKI HOOK" = real calls)
  run_demo.py       dummy workflow + adversarial scenarios + acceptance-rate metrics
  bench_pki.py      latency micro-benchmark
tests/test_pki.py
```

## Design decisions (worth agreeing on as a team)

1. **Hierarchy.** One test root and three intermediates (Issuer CA, Website CA,
   Agent CA). A leaf is only accepted if it was issued by _the CA for the
   expected role_ and carries exactly that role in its Extended Key Usage, so
   an agent cert can never pass as a website cert.
2. **Trust bundle out of band.** `pki_out/trust_bundle/` is installed into
   the client and website config. It is never fetched through an agent.
   Certificates and CRLs may travel any route (they're signed); the root may not.
3. **No certified client key.** The wallet makes **one key per website** and
   registers it directly (QR code or link), self-signed as proof of possession
   and naming the site. Sites can't link a user across sites by key.
   _(Open question for P & T: how registration works in your UI.)_
4. **Short-lived agent certs (24 h) + CRLs.** These cover adaptive corruption. Verification
   fails closed if a CRL is missing, stale, forged or rolled back.
5. **Signed envelopes with purpose separation.** Every protocol message is
   `sign(key, purpose, payload)`. The purpose is inside the signature, so a
   challenge signature can't be replayed as an authorization.
6. **One algorithm: ECDSA P-256 / ES256**, raw r‖s signatures (JWS/WebCrypto
   compatible). P-256 is what mDLs and Longfellow use.
7. **Canonical encoding.** No floats (use integer cents / Unix seconds).
   Non-Python teammates can use any RFC 8785 library and get identical bytes.

## Message flow in the dummy workflow

```
0. setup      PKI issues certs; client registers per-site key with website (direct)
1. agent  -> website   sign(agent, "agent-request", {site, operation})        + agent cert
2. website-> agent     sign(website, "challenge", {challenge_id, site, operation,
                             predicate, agent_id, agent_kid, nonce, expires_at}) + website cert
3. agent  -> client    forwards challenge
4. client              verify website cert == site user chose; show operation; user approves
                       sign(client_site_key, "authorization", {challenge_id, challenge_hash,
                             site, agent_id, agent_kid, decision})
                       proof = ZK(age_over_18, bound to hash(authorization))
5. agent  -> website   sign(agent, "presentation", {site, authorization, proof}) + agent cert
6. website             agent cert + sig -> site -> client key registered -> challenge ours &
                       unmodified -> presenter == authorized agent -> not expired -> proof
                       -> challenge unused AND action not yet executed (ledger) -> execute
```

## Integration guide for each teammate

Everything is importable from `zkarma_pki`. Each party loads its own
`TrustStore.from_bundle("<trust_bundle>")` at startup.

**T (website).**

```python
from zkarma_pki import *
trust = TrustStore.from_bundle(BUNDLE)
registry = ClientKeyRegistry("https://shop.test")
# incoming agent request
req, agent = verify_with_cert(env, trust, Role.AGENT, PURPOSE_AGENT_REQUEST)
# outgoing challenge
challenge_env = sign(site_key, PURPOSE_CHALLENGE, challenge, cert=site_cert)
# presentation
pres, presenter = verify_with_cert(env, trust, Role.AGENT, PURPOSE_PRESENTATION)
auth = verify(pres["authorization"], registry.get(pres["authorization"]["kid"]),
              PURPOSE_AUTHORIZATION)
# issuer key for Longfellow verifier
issuer = trust.verify(issuer_cert_pem, Role.ISSUER)   # issuer.public_key
```

See `MockWebsite` for the full check order, the action ledger and the lock
that makes concurrent replay safe.

**P (client/wallet).**

```python
ring = ClientKeyring("wallet_keys/")
registration = ring.registration_for(site)           # give to the site DIRECTLY
ch, site = verify_with_cert(ch_env, trust, Role.WEBSITE, PURPOSE_CHALLENGE,
                            expected_name=user_chosen_site)   # never trust the msg's own site
auth_env = sign(ring.key_for(site.name), PURPOSE_AUTHORIZATION, auth)
bind = canonical_hash(auth)                          # feed into the Longfellow proof's nonce
```

**V (agent).**

```python
env = sign(agent_key, PURPOSE_AGENT_REQUEST, {"site": ..., "operation": ...}, cert=agent_cert)
pres = sign(agent_key, PURPOSE_PRESENTATION, {"site": ..., **client_response}, cert=agent_cert)
```

Get a cert with `cli issue pki_out agent <id> --pubkey <pem>` or
`POST /admin/issue`. If you follow Web Bot Auth (RFC 9421 HTTP message
signatures), the same agent key/cert works there.

**Longfellow integration (whoever owns it).** Replace `mock_zk_prove` /
`mock_zk_verify`. The PKI supplies (a) the verified issuer public key and
(b) `canonical_hash(authorization)` as the value the device key signs in
place of the verifier nonce. The issuer key format Longfellow expects still
needs checking against its repo/test vectors.

## Current results

Dummy workflow: legitimate acceptance 100% (3/3 scenarios), unauthorized
acceptance 0% (18 attack scenarios, 36 attempts). Stopped by reason: replay,
concurrent replay, semantic replay, wrong_site, agent_mismatch, bad_key (stolen
cert), bad_chain (rogue CA, fake DMV), revoked, bad_signature (tampering
before/after signing), user_declined (unrequested operation), wrong_role (cert
confusion), name_mismatch (wrong site's challenge), proof_unbound, expired,
predicate_false.

PKI latency (dev container, median): sign 0.04 ms, full cert-chain + CRL +
signature check 0.2 ms; envelope with cert ~1.2 KB. That's negligible next to ZK
proving.

## Known limitations / next steps

- **ZK proof is a mock that reveals the credential**, including a device key that
  would link users. Longfellow fixes this; the PKI calls stay the same.
- Agent and website identities in the mock are fixed per run. Proposal Table 1's
  "no permanent agent-user link" needs per-site agent keys. That's easy to add via
  `cli issue` with a site-scoped name, but it's a design call for V.
- The directory service has no TLS and uses one shared admin token (fine for the lab).
- CRL distribution is pull-based; a malicious agent can delay but not forge a CRL.
  Website-side freshness comes from the 1-day `next_update`; shorten it for experiments.
- Formal model: the trust-bundle assumption, role separation and purpose
  separation should appear as explicit lemmas or assumptions in the write-up.
