# ZKARMA safe agent

One sequential purchase per run. The agent browses the website's public JSON
catalog, uses DeepSeek to select a product and quantity from the user's task,
and relays restricted checkout challenges to the user's wallet. The user approves
in the wallet terminal. Unrestricted checkout completes without an age proof.

This is an API-based agent for this ZKARMA shop, not a browser for arbitrary
shopping websites. Orders are simulated: the website does not charge or ship.

## Setup

Run from the repository root with Python 3.10 or newer. Reuse an existing `.venv`
if present; otherwise create it:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r website/requirements.txt -r client/requirements.txt -r agent/requirements.txt
python client/wallet.py pair safe-agent --name "Safe agent"
python client/wallet.py allow-origin http://localhost:5050
python client/wallet.py show
```

The wallet saves pairing, allowed origins, and approval history in
`~/.zkarma/client_state.json`. For an isolated state file, set
`ZKARMA_CLIENT_STATE` to the same path for all wallet setup and serve commands.
The agent keeps its handles only in memory.

Use the exact same website origin in the wallet allowlist and agent command.
`localhost` and `127.0.0.1` are different origins. To change the website origin
or port, set `ZKARMA_ORIGIN` and `ZKARMA_PORT` when launching it, then update the
wallet allowlist and agent `--site` accordingly.

## Run in three terminals

Activate `.venv` in each terminal, from the repository root.

Terminal 1 — website:

```bash
source .venv/bin/activate
ZKARMA_DEV=1 python website/app.py
```

Terminal 2 — wallet, where you answer the approval prompt:

```bash
source .venv/bin/activate
ZKARMA_DEV=1 python client/wallet.py serve
```

Terminal 3 — interactive agent:

```bash
source .venv/bin/activate
python -m agent
```

The agent asks for the website, purchase task, and a hidden API key if
`DEEPSEEK_API_KEY` is not already set. The key is never saved by the application.
For repeated runs, set the environment variable in your shell or secret manager.
In zsh, enter it without putting its value in shell history:

```zsh
read -s 'DEEPSEEK_API_KEY?DeepSeek API key: '
export DEEPSEEK_API_KEY
```

The application does not automatically load `.env` files. `.env` patterns are
ignored by Git to reduce accidental credential commits.

Example with a task and a hard $25 total budget:

```bash
python -m agent --site http://localhost:5050 \
  --task "Buy one bottle of red wine under 25 USD" --max-total-cents 2500
```

For a deterministic run without DeepSeek or an API key:

```bash
python -m agent --site http://localhost:5050 --item wine-001 --quantity 1
python -m agent --site http://localhost:5050 --item water-001 --quantity 2
```

Wine and vape items are restricted; sparkling water is unrestricted. Browsing
never contacts the wallet. Restricted checkout normally prompts once. A nonce
expires after 120 seconds; an expired authorization may cause another approval
prompt for the same operation. Denial ends the purchase.

Options: `--wallet`, `--agent`, `--model`, `--approval-timeout` (default 180
seconds), and `--max-refreshes` (default 1). `DEEPSEEK_MODEL` sets the model default
(otherwise `deepseek-flash`). `--quantity` is for `--item`; natural-language
quantities come from `--task`. One product type is supported per purchase.

## Model and relay responsibilities

DeepSeek uses the [Chat Completions tool-call API](https://api-docs.deepseek.com/guides/tool_calls/)
at `https://api.deepseek.com`. It receives the task, public catalog, and limits,
then returns `select_product` or `clarify_task`. Python validates the selection
and executes the protocol in order. Invalid or ambiguous responses do not start
checkout. No proofs, wallet state, or API key are sent in model messages.

Natural-language constraints are interpreted by the model. The explicit
`--max-total-cents` limit is enforced independently by Python; a model-extracted
budget can tighten but cannot raise it. The website owns prices and restriction
policy. A restricted challenge must match the selected product, quantity, price,
and origin before the agent forwards it to the wallet.

`SafeAgent` exposes reusable methods:

| Method | Behavior |
|---|---|
| `browse_products()` | Public `GET /products`; validates and remembers catalog. |
| `request_operation(item_id, quantity)` | `POST /checkout`; returns an order result or an operation ID and challenge handle. |
| `request_fresh_challenge(op_id)` | Refreshes an expired challenge for the same operation. |
| `request_wallet_authorization(challenge_handle)` | Forwards the original challenge, polls approval, and returns a proof handle on approval. |
| `redeem(nonce, proof_handle, agent_id=None, site_id=None)` | Sends the stored proof to its original website with the fixed agent identity. |
| `purchase(item_id, quantity)` | Runs the complete relay with bounded expiration recovery. |

Handles are process-local references, not a persistent cache. Proof handles are
single-use and removed before a redemption attempt. The agent does not recover
operations across process restarts. HTTP requests have timeouts, do not follow
redirects, and are not retried automatically. If checkout or redemption loses a
response, the outcome may be unknown: inspect the website before starting a new
purchase. The website has no operation-status endpoint yet. A wallet polling
timeout can leave its terminal prompt open; no further request is issued by that
agent run. Close or deny that prompt before trying again.

## Development mode

Both services currently require `ZKARMA_DEV=1`. This trusts a development agent
identity header, lets the wallet accept unsigned website challenges, and replaces
the real proof with the literal string `dev-proof`. That string is not evidence
of age or approval and is not cryptographically bound to the operation. Nonce,
ownership, and consumed-operation checks still run. These runs demonstrate an
honest workflow, not security against malicious agents.

PKI remains untouched. Real request signing, signed website challenges/status,
and real wallet proof generation are separate integration work. Disabling dev
mode does not make the unfinished components operational or secure.

## Tests

```bash
ZKARMA_DEV=1 python -m unittest discover -s client/tests -v
ZKARMA_DEV=1 python -m unittest discover -s agent/tests -v
```

Tests cover public browsing, checkout policy, wallet approval and denial,
expiration, replay, handle mismatches, budgets, malformed model responses, and
lost responses after an order is placed. The HTTP integration test starts local
website and wallet servers on temporary ports and runs the CLI as a subprocess,
with scripted consent. Model tests mock the DeepSeek API, so normal test runs
need no API key or paid requests. Transcript-binding tests use a test double,
not real zero-knowledge proofs.
