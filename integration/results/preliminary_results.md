# ZKARMA: preliminary PKI integration results

Run 2026-11-19 18:47:12 UTC on Linux-6.18.44-fc-v653-x86_64-with-glibc2.39 (Python 3.13.18).

## Headline (PKI mode, dev mode off)

* Honest flows completed: **5/5**
* Attacks refused: **20/20**
* Attacks refused before the user was asked: **17/20**
* Where attacks stopped: {'website': 13, 'wallet': 7}

## Contrast: same scenario, three configurations

| ID | Scenario | pki | nopki (binding proof, no PKI) | dev (today) |
|---|---|---|---|---|
| A1 | Request with no signature, only the dev identity header | refused @website: bad_signature (missing_signature) | **SUCCEEDS** (website accepted the claimed identity) | **SUCCEEDS** (website accepted the claimed identity) |
| A2 | Unpaired agent claims to be the user's paired agent at the wallet | refused @wallet: agent_not_paired | **SUCCEEDS** (wallet produced a proof for the impostor) | **SUCCEEDS** (wallet produced a proof for the impostor) |
| A8 | Exact replay of a captured signed request | refused @website: bad_signature (replay) | **SUCCEEDS** (replayed request created a second operation) | **SUCCEEDS** (replayed request created a second operation) |
| A9 | Request body changed in transit (quantity 1 -> 10) | refused @website: bad_signature (body_mismatch) | **SUCCEEDS** (website accepted the altered body) | **SUCCEEDS** (website accepted the altered body) |
| A12 | Agent rewrites the challenge's amount (and recomputes its hash) | refused @wallet: website_sig_bad_signature | **SUCCEEDS** (user was shown amount_cents=1; website then answered 403 proof_invalid) | **SUCCEEDS** (user was shown amount_cents=1; website then answered 200 placed) |
| A16 | Another agent redeems a proof the user approved for agent-1 | refused @website: wrong_agent | **SUCCEEDS** (thief's order was placed) | **SUCCEEDS** (thief's order was placed) |
| A17 | Same proof redeemed twice | refused @website: nonce_invalid_or_used | refused @website: nonce_invalid_or_used | refused @website: nonce_invalid_or_used |
| A18 | Proof for one order redeemed against a bigger order | refused @website: proof_invalid | refused @website: proof_invalid | **SUCCEEDS** (bigger order placed with the small order's proof) |
| A19 | Re-run an order that already ran (fresh challenge for the same op_id) | refused @wallet: status_required | refused @website: already_consumed | refused @website: already_consumed |
| H1 | Safe agent buys an age-restricted item (wine) | completed | completed | completed |
| H2 | Safe agent buys an unrestricted item (no proof needed) | completed | completed | completed |
| H3 | A second, separately certified agent buys for the same user | completed | completed | completed |
| H5 | Main-branch website: enter (session) -> browse -> checkout | completed | completed | completed |

nopki: attacks refused 3/9

dev: attacks refused 2/9

## All PKI-mode scenarios

| ID | Kind | Scenario | Result | Stopped at | Reason | User asked? |
|---|---|---|---|---|---|---|
| H1 | honest | Safe agent buys an age-restricted item (wine) | completed | - | placed | yes |
| H2 | honest | Safe agent buys an unrestricted item (no proof needed) | completed | - | placed | no |
| H3 | honest | A second, separately certified agent buys for the same user | completed | - | placed | yes |
| H4 | honest | Revoking agent-1 does not affect agent-2 | completed | - | placed | yes |
| H5 | honest | Main-branch website: enter (session) -> browse -> checkout | completed | - | placed | yes |
| A1 | attack | Request with no signature, only the dev identity header | refused | website | bad_signature (missing_signature) | no |
| A2 | attack | Unpaired agent claims to be the user's paired agent at the wallet | refused | wallet | agent_not_paired | no |
| A3 | attack | Agent certificate forged by an attacker-run CA | refused | website | bad_signature (bad_chain) | no |
| A4 | attack | Stolen agent certificate presented without its private key | refused | website | bad_signature (bad_key) | no |
| A5 | attack | Agent revoked after compromise keeps sending requests | refused | website | bad_signature (revoked) | no |
| A6 | attack | Agent certificate past its expiry | refused | website | bad_signature (expired) | no |
| A7 | attack | Website certificate used as an agent certificate (role confusion) | refused | website | bad_signature (wrong_role) | no |
| A8 | attack | Exact replay of a captured signed request | refused | website | bad_signature (replay) | no |
| A9 | attack | Request body changed in transit (quantity 1 -> 10) | refused | website | bad_signature (body_mismatch) | no |
| A10 | attack | Request signed for the wallet replayed to the website | refused | website | bad_signature (wrong_target) | no |
| A11 | attack | Website's agent CRL is stale (no fresh revocation info) | refused | website | bad_signature (stale_crl) | no |
| A12 | attack | Agent rewrites the challenge's amount (and recomputes its hash) | refused | wallet | website_sig_bad_signature | no |
| A13 | attack | Agent forges a challenge and signs it with its own agent certificate | refused | wallet | website_sig_wrong_role | no |
| A14 | attack | Challenge signed by a different certified website, relabelled as the user's site | refused | wallet | website_sig_name_mismatch | no |
| A15 | attack | Agent strips the website's signature from the challenge (downgrade) | refused | wallet | unsigned | no |
| A16 | attack | Another agent redeems a proof the user approved for agent-1 | refused | website | wrong_agent | yes |
| A17 | attack | Same proof redeemed twice | refused | website | nonce_invalid_or_used | yes |
| A18 | attack | Proof for one order redeemed against a bigger order | refused | website | proof_invalid | yes |
| A19 | attack | Re-run an order that already ran (fresh challenge for the same op_id) | refused | wallet | status_required | no |
| A20 | attack | Revoked agent asks the wallet directly for a proof | refused | wallet | bad_signature (revoked) | no |

## Cost of the PKI

| Operation | median ms | p95 ms |
|---|---|---|
| agent request sign | 0.123 | 0.206 |
| agent request verify | 0.404 | 0.591 |
| challenge sign | 0.084 | 0.126 |
| challenge verify | 0.285 | 0.354 |

* HTTP `POST /checkout` round trip: pki 2.814 ms vs nopki 1.718 ms median (n=300), overhead **1.096 ms**
* Full restricted purchase (SafeAgent, wallet auto-approve): pki 12.419 ms, nopki 7.464 ms, dev 7.411 ms median (n=50); overhead **4.955 ms**; signed requests per purchase: 4.0
* Sizes (bytes): {'agent_request_signature_header': 1595, 'challenge_signature_field': 1460, 'challenge_json_unsigned': 553, 'challenge_json_signed': 2028}

## Format compatibility

* spec.canonical_json vs PKI canonical_encode on spec test vectors: 3/3
* ... on restricted-order operations generated by the running website: 67/67
* Edge cases: {'float': 'PKI rejects (CanonicalEncodingError)', 'astral_key_order': 'DIFFERENT bytes', 'unsafe_int': 'PKI rejects (CanonicalEncodingError)', 'non_ascii_value': 'same'}

## Existing suites on this branch (unchanged)

* pki (unit): 44 passed, 1 warning in 1.16s
* client: 48 passed, 6 subtests passed in 0.17s
* agent: 20 passed in 1.28s
* pki demo (mock parties): Legitimate acceptance rate:   100.0%  (3 scenarios) | Unauthorized acceptance rate:   0.0%  (18 scenarios, 36 attempts)
