# integration/: preliminary test of the PKI with the current system

This folder runs the PKI (`pki/zkarma_pki`) **together with the real
website (`website/app.py`), wallet (`client/wallet.py`) and safe agent
(`agent/`)** over real HTTP on 127.0.0.1. No file outside `integration/` is
changed: the adapters are installed at the stubs that `spec/README.md`
already lists as "to swap out later".

| Stub today | Replaced in PKI mode by |
|---|---|
| `X-Dev-Agent-Thumbprint` header (website and wallet) | agent certificate + per-request signature (`AgentRequestSigner` / `RequestVerifier`) |
| `spec.stub_sign` / `stub_verify` (challenge signature) | website certificate signature, name checked against the user's allowed site |
| hand-made `trust/issuer_pub.json` | `issuer_pub_json()` from a PKI-verified issuer certificate |
| `"dev-proof"` | **still a stand-in**, but a binding one: `"bind:" + SHA-256(transcript)` |

With the PKI installed, `ZKARMA_DEV` is **off** in both the website and the
wallet. The only remaining stub is the zero-knowledge proof itself.

## Run

From the repository root:

```bash
pip install -r website/requirements.txt -r client/requirements.txt -r pki/requirements.txt pytest

python -m pytest -q integration                     # 55 tests, PKI mode must be 100% correct
ZKARMA_PROOF=real python -m pytest -q integration   # same, with REAL Longfellow proofs (needs zkage)
ZKARMA_MAIN_REPO=../ZKARMA-main \
  python -m pytest -q integration/test_main_website_mdl.py   # main's own website, real proofs
python integration/bench_mdl.py                     # real-proof reliability and timings

python integration/run_preliminary.py \
    --main-website ../path/to/main/website/app.py   # optional: also tests main's /enter website
# -> integration/results/preliminary_results.{md,json}
```

## Three configurations

| Mode | Agent identity | Challenge | Proof |
|---|---|---|---|
| `pki` | PKI cert + signed request | PKI website signature (required) | binding stand-in |
| `nopki` | dev header | unsigned (dev mode) | binding stand-in |
| `dev` | dev header | unsigned (dev mode) | `"dev-proof"` (today's system) |

`pki` vs `nopki` isolates what the PKI contributes. `dev` is the system as it runs today.

**Real proofs.** `System(..., proof="real")`, or `ZKARMA_PROOF=real` for every
test, replaces the binding stand-in in `pki` and `nopki` mode. The wallet then
holds a test mDL issued by the PKI's test DMV (`pki/zkarma_pki/mdl.py`) and
proves with `client/zkage.py`. The website checks with its own
`website/proofs.py`, with the DMV key from the PKI-verified certificate. All 25
scenarios pass this way, against this branch's website and against `main`'s.

## Files

| File | What it does |
|---|---|
| `pki_adapters.py` | Request signing/verification, website message signing/verification, RFC 7638 agent thumbprint, issuer key export |
| `harness.py` | `System`: boots website + wallet servers, installs adapters, auto-consent "user", agents |
| `scenarios.py` | 5 honest flows + 20 attacks (H1-H5, A1-A20) as functions over a `System` |
| `test_pki_integration.py` | pytest: every scenario in PKI mode + format/identity interop checks |
| `run_preliminary.py` | Runs everything in all modes, benchmarks, writes `results/` |
| `mdl_adapters.py` | `make_wallet_prover(mdl)`: drop-in for `client/prover.prove` using a PKI-issued mDL + Longfellow; `write_issuer_pub()` for `website/proofs.py` |
| `test_mdl_longfellow.py` | Real Longfellow: website accepts, proof bound to nonce/agent/operation/origin, retry gets a fresh proof, minor/expired/untrusted DMV/stolen mDL fail, full-system purchase |
| `test_main_website_mdl.py` | `main`'s website, unmodified, as its own process in PKI mode, with real proofs (needs `ZKARMA_MAIN_REPO`) |
| `main_hooks.patch` | The small hooks `main`'s wallet and agent need for PKI mode + real proofs (`git apply integration/main_hooks.patch` in a `main` checkout that has this branch's `pki/` and `integration/`). Inert unless `ZKARMA_TRUST_BUNDLE` / `ZKARMA_MDL` / `ZKARMA_AGENT_KEY` are set. |
| `bench_mdl.py` | n trials of issue -> DeviceAuth -> prove -> website verify, success rates and timings |

## Integration gaps found (need a team decision)

1. **Agent identifier.** The website and wallet key everything on `agent_jkt`
   (a key thumbprint), while `zkarma_pki.key_id` is SHA-256 of the SPKI DER.
   They are different strings for the same key. The adapter uses the RFC 7638
   JWK thumbprint of the *certified* key. Proposal: add `jwk_thumbprint()` to
   `zkarma_pki.keys` and use it everywhere `agent_jkt` appears.
2. **Request-signature format.** Website and wallet have no agent-signature
   check yet (`verify_agent_signature` returns `None` outside dev mode). The
   adapter's header covers method, full target URL, body hash, timestamp and
   a one-time nonce. A new purpose `zkarma/http-request` should be added to
   `zkarma_pki.signing` (or switch to RFC 9421 / Web Bot Auth using the same key).
3. **Website signing is not in `website/app.py` yet.** The harness wraps
   `challenge()` to add the signature. The website needs to load its key and
   cert and call `WebsiteMessageSigner` itself.
4. **Signed operation status (retries) is missing on the website.** With dev
   mode off, the wallet refuses every retry (`status_required`, scenario A19),
   including honest ones. The website needs the `zkarma-status-1` message
   from `spec/README.md`, signed with the same website key.
5. **Two canonical encoders.** `spec.canonical_json` (json.dumps, sorted keys)
   and `zkarma_pki.canonical_encode` (RFC 8785 subset) give identical bytes for
   every operation the website produces today, but differ on floats (PKI
   refuses), integers above 2^53 (PKI refuses), and non-BMP characters in keys
   (different order). Proposal: the spec imports `canonical_encode`.
6. **Website variants.** `main` has the `/enter` + 30-minute session website,
   while `safe-agent` has the public-catalog website. Both pass with the PKI
   (H5 runs on main's), but the team should pick one for the final system.
7. **Revocation distribution.** The harness pushes the new CRL into each
   party's trust store directly. Deployed parties need to pull CRLs (e.g. from
   `zkarma_pki.directory`) before the 1-day `next_update`, or they fail closed
   (A11 shows the fail-closed behaviour).
