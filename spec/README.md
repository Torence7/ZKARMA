# spec/ — shared ZKARMA formats (proposal)

Nothing in `website/` uses this yet. It's a proposal for the group, starting
with the `TODO: move into spec/` in `website/app.py`.

## 1. One copy of the byte formats
`zkarma_spec.py` has `operation_hash()` and `build_transcript()` and gives
exactly the same bytes as the copies in `website/app.py`. `client/tests/test_spec.py`
checks this against `test_vectors.json` (regenerate with `python spec/make_vectors.py`).
Proposal: the website, client and agent all import from here, so the formats
can't drift apart.

## 2. Website-signed challenges
Add a `"signature"` field to the 401 challenge, covering every other field
(`signed_payload()`). The client then knows the nonce, time and operation came
from the site and not from the agent. The client already checks it and, in dev
mode, accepts challenges without one. The key comes from the PKI; until then
`stub_sign` / `stub_verify` stand in (a plain hash, so **no security**).

## 3. Signed operation status (for retries)
When an agent asks the wallet again for an operation the user already approved,
the wallet asks the user again and shows what the website says about it:

```json
{"v": "zkarma-status-1", "site": "http://localhost:5050", "op_id": "...",
 "status": "placed", "consumed": true, "issued_at": 1794100000, "signature": "..."}
```

Suggested place: in the `/operations/<op_id>/challenge` response (next to the
new challenge), or a `GET /operations/<op_id>/status` route. Outside dev mode
the wallet refuses a retry that comes without a valid one.

## Stubs to swap out later, all at once
| Stub | Where | Replaced by |
|---|---|---|
| `"dev-proof"` | `client/prover.py`, `website/app.py` | common `zk/zkage` library |
| `X-Dev-Agent-Thumbprint` header | `client/wallet.py`, `website/app.py` | agent HTTP signatures (Web Bot Auth) |
| `stub_sign` / `stub_verify` | `spec/zkarma_spec.py` | website keys from the PKI |
