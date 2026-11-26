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
  mdl.py         test mDLs (ISO 18013-5 mdoc) from the test DMV, for real Longfellow proofs
  cli.py         command-line tool
demo/
  mock_parties.py   MOCK issuer, Longfellow, client, agent, website  ("PKI HOOK" = real calls)
  run_demo.py       dummy workflow + adversarial scenarios + acceptance-rate metrics
  bench_pki.py      latency micro-benchmark
tests/test_pki.py
tests/test_mdl.py   mDL issuance/presentation/verification (no Longfellow needed)
```


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

**Longfellow integration.** Done with real proofs: see "Test mDLs" below.

## Test mDLs for real Longfellow proofs (`mdl.py`)

**Problem.** Longfellow proves facts about an mDL whose *device key* signed
DeviceAuthentication over a *session transcript*. The test mDLs shipped with
Longfellow were signed over their own fixed transcripts, and we don't have
their issuer or device private keys, so they can't be bound to a ZKARMA
challenge. `demo/mock_parties.py` only had a JSON mock credential.

**What this adds.** A real ISO/IEC 18013-5 mdoc whose Mobile Security Object
is signed (COSE_Sign1, ES256, x5chain) by the test DMV's **issuer-role key
from this PKI**, holding a **device key the wallet controls**. For each
challenge the wallet signs DeviceAuthentication over
`spec.build_transcript(origin, nonce, agent_jkt, operation_hash)` and hands
the DeviceResponse to `client/zkage.py`. The website verifies with its
unchanged `website/proofs.py` and the DMV key from the PKI-verified issuer
certificate.

```bash
cd pki
python -m zkarma_pki.cli init pki_out                                   # includes test-dmv
python -m zkarma_pki.cli mdl-issue pki_out ../wallet_mdl.json           # adult (born 2000-01-01)
python -m zkarma_pki.cli mdl-issue pki_out ../minor_mdl.json --birth-date 2012-06-01
python -m zkarma_pki.cli mdl-issuer-pub pki_out ../trust/issuer_pub.json   # for website/proofs.py
python -m zkarma_pki.cli mdl-show ../wallet_mdl.json
```

```python
from zkarma_pki.mdl import Mdl, MdlIssuer
issuer = MdlIssuer.from_pki(pki)                    # test-dmv key + cert from pki_out
mdl = issuer.issue_to_new_device()                  # or issuer.issue(device_public_key) -> IssuerSigned
mdoc = mdl.present(transcript)                      # DeviceResponse, DeviceAuth over THIS transcript
proof_hex, metrics = zkage.prove(mdoc, **...)       # see integration/mdl_adapters.make_wallet_prover
```

**What each module changes**

| Module | Change |
|---|---|
| Wallet (`client/prover.py`) | `prove(transcript, now, claim)` keeps its signature. Body becomes `return make_wallet_prover(Mdl.load(MDL_PATH))(transcript, now, claim)` (`integration/mdl_adapters.py`). The wallet stores the `mdl-issue` JSON file. |
| Website, `main` (`site_pki.py`) | **Nothing.** It already reads `pki_out/issued/issuer/test-dmv/cert.pem`, the same key `mdl-issue` signs with. Tested: `integration/test_main_website_mdl.py`. |
| Website, without PKI mode | Write `trust/issuer_pub.json` with `mdl-issuer-pub`; `proofs.py` unchanged. |
| Agent | Nothing: it never sees the mDL, only the proof. |

**Format.** Field order and encodings match Longfellow's own test mDLs byte for
byte (`tests/test_mdl.py::test_layout_matches_longfellow_vectors`). The
reference verifier `verify_device_response()` also accepts all three of
Longfellow's vectors, so the DeviceAuthentication bytes are proven compatible
with an independent implementation. `validFrom` is backdated 1 minute
(`CLOCK_SKEW`), like the CA's certificates, because Longfellow rejects
`now < validFrom`.

**Measured limit.** Longfellow's v1 circuit hashes the whole MSO in the proof:
7 data elements (MSO 553 B) prove, 8 (588 B) fail with an opaque
`GeneralFailure`. `MdlIssuer` refuses more than 7 (`MAX_ELEMENTS`). The default
mDL has 6: family_name, given_name, birth_date, issuing_country, age_over_18,
age_over_21.

**Results (Intel Xeon 2.1 GHz, 4 vCPU, `target-cpu=native`, n=30):** 30/30
proved, 30/30 accepted by `website/proofs.py`, 30/30 rejected when replayed
under another nonce. Issue 0.5 ms, DeviceAuth signature 0.14 ms, prove 726 ms
median (p95 781), website verify 280 ms (p95 312, includes subprocess), proof
361 KB, mdoc 1.45 KB. Raw: `integration/results/mdl_longfellow.json`.

**Limits.** The wallet's device key is stored in a JSON file (test only; a real
device key lives in secure hardware). Issuer certificates don't carry the ISO
DS EKU or IACA chain; Longfellow doesn't check them, our PKI does the
equivalent with the issuer role.

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

- The dummy workflow in `demo/` still uses the JSON mock credential. Real mDLs and
  Longfellow proofs are in `mdl.py` and `integration/` (see "Test mDLs" above).
- Agent and website identities in the mock are fixed per run. Proposal Table 1's
  "no permanent agent-user link" needs per-site agent keys. That's easy to add via
  `cli issue` with a site-scoped name, but it's a design call for V.
- The directory service has no TLS and uses one shared admin token (fine for the lab).
- CRL distribution is pull-based; a malicious agent can delay but not forge a CRL.
  Website-side freshness comes from the 1-day `next_update`; shorten it for experiments.
- Formal model: the trust-bundle assumption, role separation and purpose
  separation should appear as explicit lemmas or assumptions in the write-up.
