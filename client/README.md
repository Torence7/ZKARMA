# ZKARMA client (wallet)

The user's **trusted** wallet. It holds the user's ID credential and shows the
user every operation an agent wants to run. It returns a zero-knowledge proof
only for operations the user approves. It never talks to the website directly:
everything goes through the (untrusted) agent.

```
 Website ──401 challenge──▶ Agent ──POST /authorize──▶ Client ──▶ user approves in terminal
 Website ◀──/redeem proof── Agent ◀──GET /authorize/id── Client ◀── proof bound to this
                                                                    site + nonce + agent + operation
```

## Quick start (dev mode)

```
pip install -r client/requirements.txt
python client/wallet.py allow-origin http://localhost:5050
python client/wallet.py pair test-agent --name "Test agent"

ZKARMA_DEV=1 python website/app.py          # terminal 1
ZKARMA_DEV=1 python client/wallet.py serve  # terminal 2: approve or deny here
python client/demo_agent.py                 # terminal 3: stand-in agent
```

Both the website and the wallet need `ZKARMA_DEV=1`. If either one runs
without it, every agent request gets `bad_signature`. The wallet prints
`dev=True` when it starts.

Other commands: `unpair`, `disallow-origin`, `show` (paired agents and allowed
sites), `history` (every approval and denial). State is saved to
`~/.zkarma/client_state.json`; set `ZKARMA_CLIENT_STATE` to use another file.
`ZKARMA_CLIENT_PORT` sets the port (default 5060).

## For agent authors: the API

The wallet listens on `127.0.0.1:5060`. Every request must identify the agent.
For now that's the dev header `X-Dev-Agent-Thumbprint: <agent key thumbprint>`,
the same one the website uses. The agent must be paired with the wallet first.

**`POST /authorize`** forwards the website's challenge exactly as received.
```json
{"challenge": { ...the "challenge" object from the website's 401... },
 "status":    { ...website-signed operation status, only for retries... }}
```
- `202 {"request_id", "status": "pending", "poll": "/authorize/<id>"}`
- `401 bad_signature`: no agent identity
- `403 agent_not_paired`
- `409 already_pending`: a prompt for this operation is already open
- `422 <reason>`: refused before the user was asked. The reasons are:
  - `origin_not_allowed`
  - `operation_hash_mismatch`
  - `operation_mismatch`
  - `unknown_action`
  - `bad_operation`
  - `bad_challenge`
  - `clock_skew`
  - `claim_not_supported`
  - `unsigned`
  - `bad_website_signature`
  - `status_required`

**`GET /authorize/<id>`** — poll until the status isn't `pending`. Only the
agent that made the request can poll it.
- `{"status": "approved", "op_id", "nonce", "proof", "metrics": {"prove_ms", "proof_bytes"}}`.
  Send `{"nonce", "proof"}` to the website's `/redeem`.
- `{"status": "denied"}`: the user said no.
- `{"status": "expired"}`: the challenge's nonce ran out. Get a fresh one from
  `/operations/<op_id>/challenge` and ask again.
- `{"status": "error", "error"}`: e.g. the prover failed.

**Retries.** If the user already approved an operation, asking again is a
retry. The user is asked again (the default answer is No) and shown whether the
website says it already ran. Forward the website's signed status in `"status"`.
Outside dev mode, a retry without a valid status is refused (`status_required`).

**What a proof is bound to.** The proof is bound to the site, the nonce, the
agent that called `/authorize`, and the operation the user saw. A proof is
therefore useless to any other agent, site or operation.

## For website authors: what the client expects

- A challenge in the shape `website/app.py` already sends: `op_id`,
  `operation`, `operation_hash`, `nonce` (64 hex characters), `now`, `origin`,
  `claim`, `expires_in` (at most 600 seconds).
- `operation` with `v: "zkarma-op-1"`, `site == origin`, and a known `action`:
  - `enter` needs `duration_s`
  - `checkout` needs `item_id`, `item_name`, `quantity`, `amount_cents` and `currency`
  - Add new actions in `ACTION_FIELDS` in `validate.py` and in `render()` in `consent.py`.
- Byte formats from `spec/zkarma_spec.py` (see `spec/README.md`):
  - planned: a `signature` on challenges
  - planned: a signed status message for retries

## What goes where

| File | Job |
|---|---|
| `wallet.py` | HTTP API, the request lifecycle (`Wallet`), the approval loop, CLI commands |
| `validate.py` | Every check on what the agent sends, before the user sees it |
| `consent.py` | The terminal screen (`render`, `TerminalConsent`); `ScriptedConsent` for tests |
| `prover.py` | Makes the proof from the transcript. **Stub.** |
| `store.py` | Paired agents, allowed sites, decision log (JSON file) |
| `config.py` | Settings and limits; imports `spec/` |
| `demo_agent.py` | Honest stand-in agent over real HTTP (not the real agent) |
| `tests/` | `test_spec.py` (bytes match the website), `test_validate.py`, `test_flow.py` (end to end with the real website app) |

Run the tests from the repo root:
```
ZKARMA_DEV=1 python -m unittest discover -s client/tests -v
```

## Stubs (to be replaced together, later)

| Stub | Where | Replaced by |
|---|---|---|
| Returns `"dev-proof"` | `prover.prove()` | common `zk/zkage` library (device-key signature + Longfellow proof) |
| `X-Dev-Agent-Thumbprint` header | `wallet.agent_identity()` | agent HTTP signatures (Web Bot Auth) |
| `stub_sign` / `stub_verify` (a plain hash, **no security**) | `spec/zkarma_spec.py` | website keys from the PKI |
| No credential stored yet | `store.py` | mDL + device key from the test DMV |

Outside dev mode (`ZKARMA_DEV` unset):
- **Proof stub:** the prover errors.
- **Agent identity:** every agent request gets a 401.
- **Unsigned challenges:** refused.

Stub signatures are still accepted outside dev mode, so don't treat a
non-dev run as secure until the PKI keys are in place.
