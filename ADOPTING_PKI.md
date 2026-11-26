# Adopting the PKI and real Longfellow proofs in your module

Everything new lives on the `pki-integration` branch:

| Where | What | Owner |
|---|---|---|
| `pki/` | PKI, plus `zkarma_pki/mdl.py`: test mDLs (ISO 18013-5) from the test DMV, for real Longfellow proofs | Kaustubh |
| `integration/` | Adapters (`pki_adapters.py`, `mdl_adapters.py`), end-to-end tests, `main_hooks.patch` | Kaustubh |
| `zk/`, `client/zkage.py` | Prithvi's Longfellow wrapper, copied unchanged | Prithvi |

No other module's code is changed on this branch. To use the PKI and real
proofs, each module adds a few small hooks. They are already written and tested
in [`integration/main_hooks.patch`](integration/main_hooks.patch). Every hook
does nothing unless its environment variable is set, so dev mode keeps working
exactly as before.

## 1. Get the code into your checkout

Merge `pki-integration` into your branch (or `main`), then apply the hooks:

```bash
git merge pki-integration
git apply integration/main_hooks.patch
```

The patch was made against `main` (its `client/` and `agent/` are identical to
the safe-agent branch's). It touches only these four files:

| Module | File | What the hook adds | Switched on by |
|---|---|---|---|
| Wallet (Prithvi) | `client/prover.py` | Real Longfellow proof from the wallet's test mDL, same `prove(transcript, now, claim)` signature (+10 lines) | `ZKARMA_MDL` |
| Wallet (Prithvi) | `client/validate.py` | Verify the website's PKI signature on challenges and status instead of `spec.stub_verify` (+28) | `ZKARMA_TRUST_BUNDLE` |
| Wallet (Prithvi) | `client/wallet.py` | Verify the agent's signed requests instead of the dev header (+15) | `ZKARMA_TRUST_BUNDLE` |
| Agent (Vijay) | `agent/__main__.py` | Sign every request with the agent's certificate (+11) | `ZKARMA_AGENT_KEY`, `ZKARMA_AGENT_CERT` |
| Website (Torence) | none | `main`'s `website/site_pki.py` already does its side, including the DMV key | `ZKARMA_PKI_DIR` |

Without the two `validate.py` / `wallet.py` hooks, the wallet rejects every
challenge from a website in PKI mode with `bad_website_signature`, because it
still checks the old stub signature.

## 2. One-time setup

```bash
pip install -r pki/requirements.txt -r website/requirements.txt -r client/requirements.txt -r agent/requirements.txt

# Longfellow (once per machine; needs rustup, ~1 min)
cd zk && cargo build --release && target/release/zkage circuits --out circuits-1attr.bin && cd ..

# PKI: root, CAs, test-dmv, the website's and the agent's certificates
cd pki
python -m zkarma_pki.cli init pki_out
python -m zkarma_pki.cli issue pki_out website http://localhost:5050
python -m zkarma_pki.cli issue pki_out agent safe-agent

# The DMV issues the user's mDL (the file holds the wallet's device key: test use only)
python -m zkarma_pki.cli mdl-issue pki_out ../wallet_mdl.json        # adult, born 2000-01-01
cd ..

# Wallet: allow the site, pair the agent by its certificate thumbprint
python client/wallet.py allow-origin http://localhost:5050
python client/wallet.py pair "$(cd pki && python -m zkarma_pki.cli thumbprint pki_out/issued/agent/safe-agent/cert.pem)" --name "Safe agent"
```

## 3. Run: PKI everywhere, dev mode off, real proofs

Three terminals, from the repo root:

```bash
# 1. Website
ZKARMA_PKI_DIR=pki/pki_out python website/app.py

# 2. Wallet (answer the prompt)
ZKARMA_TRUST_BUNDLE=$PWD/pki/pki_out/trust_bundle ZKARMA_MDL=$PWD/wallet_mdl.json \
  python client/wallet.py serve

# 3. Agent
ZKARMA_AGENT_KEY=pki/pki_out/issued/agent/safe-agent/key.pem \
ZKARMA_AGENT_CERT=pki/pki_out/issued/agent/safe-agent/cert.pem \
  python -m agent --site http://localhost:5050 --item wine-001
```

Expected: the wallet shows the checkout as website-signed, you approve, the
wallet proves with Longfellow (~1 s), and the agent prints `"status": "placed"`.

Try the failure cases too:

| Change | Expected |
|---|---|
| `mdl-issue pki_out ../minor.json --birth-date 2012-06-01` and use it as `ZKARMA_MDL` | Agent: `Wallet could not generate the proof` |
| An mDL from another PKI (`init other_pki`, then `mdl-issue other_pki ...`) | Agent: `HTTP 403: proof_invalid` |
| Run the agent without `ZKARMA_AGENT_KEY` | Agent: `HTTP 401: bad_signature` |

## 4. Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `ZKARMA_PKI_DIR` | website | PKI directory; turns on the website's PKI mode |
| `ZKARMA_TRUST_BUNDLE` | wallet | `pki_out/trust_bundle`; turns on PKI checks of the website and agent |
| `ZKARMA_MDL` | wallet | Test mDL file from `mdl-issue`; turns on real Longfellow proofs |
| `ZKARMA_AGENT_KEY` / `ZKARMA_AGENT_CERT` | agent | Agent's PKI key and certificate; turns on request signing |
| `ZKAGE_BIN` / `ZKAGE_CIRCUITS` | wallet, website | Override the default `zk/target/release/zkage` and `zk/circuits-1attr.bin` |
| `ZKARMA_DEV=1` | all | Old dev mode (dev header, unsigned challenges, `dev-proof`); not needed above |

## 5. Check it works in your checkout

```bash
(cd pki && python -m pytest -q)                      # PKI + mDL unit tests
python -m pytest -q integration                      # end to end, binding stand-in proof
ZKARMA_PROOF=real python -m pytest -q integration    # end to end, real Longfellow proofs
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| Wallet: `bad_website_signature` | `client/validate.py` hook missing, or `ZKARMA_TRUST_BUNDLE` not set for the wallet |
| Wallet: `agent_not_paired` | Pair the agent by its thumbprint (`cli thumbprint`), not by its name |
| Website/wallet: `bad_signature` (401) | The agent isn't signing (`ZKARMA_AGENT_KEY/CERT`), or its certificate is expired/revoked (agent certs last 24 h; re-issue) |
| zkage: `GeneralFailure` | The mDL isn't valid at the challenge time, the wallet's key doesn't match the mDL, or the mDL has more than 7 elements (Longfellow's limit; `mdl-issue` won't create such an mDL) |
| Website: `proof_invalid` | The mDL wasn't issued by the `test-dmv` in the website's `ZKARMA_PKI_DIR` |

Details: [`pki/README.md`](pki/README.md) (PKI and mDLs),
[`integration/README.md`](integration/README.md) (tests and adapters).
