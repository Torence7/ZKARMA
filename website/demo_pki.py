"""Live demo of the website's PKI mode. This script plays the agent (signing
every request with its PKI certificate) and the wallet's signature check,
against the real running website.

One-time setup is at the top of website/app.py. Then, from the repo root:
  Terminal 1:  ZKARMA_PKI_DIR=pki/pki_out ZKARMA_DEV=1 python website/app.py
  Terminal 2:  python website/demo_pki.py

ZKARMA_DEV=1 lets the order finish with "dev-proof", since real proofs aren't
ready yet. Leave it out and the site also refuses the old dev header.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request

import site_pki  # puts pki/ and spec/ on the path
from spec.zkarma_spec import signed_payload
from zkarma_pki import (PKI, Role, TrustStore, canonical_encode, load_cert, load_private_key, sign,
                        verify_with_cert)
from zkarma_pki.keys import b64u, b64u_decode
from zkarma_pki.signing import PURPOSE_CHALLENGE

SITE = os.environ.get("ZKARMA_ORIGIN", "http://localhost:5050")
PKI_DIR = os.environ.get("ZKARMA_PKI_DIR", "pki/pki_out")
WINE = {"item_id": "wine-001", "quantity": 1}


def agent(name):
    d = f"{PKI_DIR}/issued/agent/{name}"
    return load_cert(f"{d}/cert.pem"), load_private_key(f"{d}/key.pem")


def signed(who, method, path, body=b""):
    """The ZKARMA-Agent-Signature header an agent sends with a request."""
    cert, key = who
    payload = {"method": method, "target": SITE + path, "body_sha256": hashlib.sha256(body).hexdigest(),
               "created": int(time.time()), "nonce": secrets.token_hex(16)}
    return {site_pki.SIGNATURE_HEADER: b64u(canonical_encode(sign(key, site_pki.PURPOSE_HTTP_REQUEST,
                                                                    payload, cert=cert)))}


def send(method, path, body=None, who=None, headers=None):
    """One HTTP request. Signs it as `who`, unless `headers` are given."""
    raw = b"" if body is None else json.dumps(body).encode()
    h = headers if headers is not None else (signed(who, method, path, raw) if who else {})
    req = urllib.request.Request(SITE + path, data=raw or None, method=method,
                                 headers={**h, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        text = e.read()
        try:
            return e.code, json.loads(text)
        except ValueError:
            return e.code, {"error": "server error, see terminal 1"}
    except urllib.error.URLError:
        raise SystemExit(f"Can't reach {SITE}. Start the website first (see the top of this file).") from None


def wallet_trusts(message) -> bool:
    """The wallet's check: signed by this site's certificate, and unchanged."""
    try:
        env = json.loads(b64u_decode(message["signature"]))
        payload, _ = verify_with_cert(env, trust, Role.WEBSITE, PURPOSE_CHALLENGE, expected_name=SITE)
    except Exception:  # noqa: BLE001 - any failure means "don't trust it"
        return False
    return payload["msg_sha256"] == hashlib.sha256(signed_payload(message)).hexdigest()


def step(n, title, result, expected):
    code, body = result if isinstance(result, tuple) else (None, result)
    shown = f"{code} {json.dumps(body)}" if code else str(body)
    print(f"\n{n}. {title}\n   -> {shown[:110]}\n   {'ok' if expected else 'UNEXPECTED'}")


trust = TrustStore.from_bundle(f"{PKI_DIR}/trust_bundle")
a1, a2 = agent("agent-1"), agent("agent-2")
code, health = send("GET", "/health")
print(f"Website {SITE}: pki={health['pki']}, dev={health['dev']}")
if not health["pki"]:
    raise SystemExit("PKI mode is off. Start the site with ZKARMA_PKI_DIR=pki/pki_out (see the top).")

r = send("POST", "/checkout", WINE)
step(1, "An agent sends a request with no signature", r, r[1].get("reason") == "missing")

if not health["dev"]:
    r = send("POST", "/checkout", WINE, headers={"X-Dev-Agent-Thumbprint": "agent-1"})
    step("1b", "An agent uses the old dev header", r, r[1].get("reason") == "missing")

raw = json.dumps(WINE).encode()
first = signed(a1, "POST", "/checkout", raw)
code, body = send("POST", "/checkout", WINE, headers=first)
ch = body["challenge"]
step(2, "agent-1 signs its checkout for 1 red wine", (code, {"error": body["error"], "op_id": ch["op_id"]}),
     body["error"] == "age_check_required")

step(3, "The wallet checks the website's signature on the challenge",
     f"signed by {SITE}: {wallet_trusts(ch)}", wallet_trusts(ch))

changed = {**ch, "operation": {**ch["operation"], "quantity": 10}}
step(4, "The agent changes the challenge to 10 bottles before the wallet sees it",
     f"wallet trusts it: {wallet_trusts(changed)}", not wallet_trusts(changed))

r = send("POST", "/checkout", WINE, headers=first)
step(5, "Someone replays agent-1's exact signed request", r, r[1].get("reason") == "replay")

r = send("POST", "/checkout", {"item_id": "wine-001", "quantity": 10}, headers=signed(a1, "POST", "/checkout", raw))
step(6, "The body is changed after signing (1 -> 10 bottles)", r, r[1].get("reason") == "body_mismatch")

r = send("POST", "/redeem", {"nonce": ch["nonce"], "proof": "dev-proof"}, who=a2)
step(7, "agent-2 tries to redeem agent-1's order", r, r[1].get("error") == "wrong_agent")

code, body = send("POST", f"/operations/{ch['op_id']}/challenge", who=a1)
ch, status = body["challenge"], body["status"]
step(8, "agent-1 gets a fresh challenge (step 7 burned the old nonce), with a signed status",
     {k: status[k] for k in ("status", "consumed")} | {"signed": wallet_trusts(status)},
     status["consumed"] is False and wallet_trusts(status))

r = send("POST", "/redeem", {"nonce": ch["nonce"], "proof": "dev-proof"}, who=a1)
if health["dev"]:
    step(9, "agent-1 redeems with the stand-in proof", r, r[1].get("status") == "placed")
    code, body = send("POST", f"/operations/{ch['op_id']}/challenge", who=a1)
    step(10, "The wallet asks about the same order again: the signed status says it already ran",
         {k: body["status"][k] for k in ("status", "consumed")}, body["status"]["consumed"] is True)
    r = send("POST", "/redeem", {"nonce": body["challenge"]["nonce"], "proof": "dev-proof"}, who=a1)
    step(11, "Redeeming the same order again", r, r[1].get("error") == "already_consumed")
else:
    step(9, "agent-1 redeems with the stand-in proof (dev mode off, so a real proof is needed)",
         r, r[0] >= 403)

pki = PKI.load(PKI_DIR)
temp = pki.issue(Role.AGENT, f"demo-agent-{secrets.token_hex(3)}")
before = send("POST", "/checkout", WINE, who=temp)
pki.revoke(Role.AGENT, temp[0])
r = send("POST", "/checkout", WINE, who=temp)
step(12, "A new agent works, then gets revoked in the PKI while the site is running",
     r, before[1].get("error") == "age_check_required" and r[1].get("reason") == "revoked")
print()
