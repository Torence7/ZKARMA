"""A stand-in agent for trying the client against the website over real HTTP.
Not the real agent (that's Vijay's part): it just relays, honestly.

    ZKARMA_DEV=1 python website/app.py         # terminal 1
    ZKARMA_DEV=1 python client/wallet.py serve # terminal 2, answer the prompts
    python client/demo_agent.py                # terminal 3

Flow: enter the site, list products, buy one, then retry the same purchase
(the wallet should ask again and flag it as a retry; the site refuses it).
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request


def call(method: str, url: str, agent: str, body=None, session=None):
    headers = {"X-Dev-Agent-Thumbprint": agent, "Content-Type": "application/json"}
    if session:
        headers["Authorization"] = f"ZKARMA {session}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def get_proof(wallet: str, agent: str, challenge: dict, status=None) -> dict:
    code, body = call("POST", f"{wallet}/authorize", agent,
                      {"challenge": challenge, "status": status})
    print(f"  wallet /authorize -> {code} {body}")
    if code != 202:
        return body
    print("  waiting for the user to answer in the wallet terminal...")
    poll = f"{wallet}{body['poll']}"
    while True:
        _, result = call("GET", poll, agent)
        if result["status"] != "pending":
            return result
        time.sleep(0.5)


def run(site: str, wallet: str, agent: str, session_holder: dict) -> None:
    def authorize_and_redeem(challenge, status=None):
        result = get_proof(wallet, agent, challenge, status)
        print(f"  wallet answer -> {result.get('status')} {result.get('metrics', '')}")
        if result.get("status") != "approved":
            return None
        code, body = call("POST", f"{site}/redeem", agent,
                          {"nonce": result["nonce"], "proof": result["proof"]},
                          session_holder.get("token"))
        print(f"  site /redeem -> {code} {body}")
        return body if code == 200 else None

    print("1. Enter the site")
    _, body = call("POST", f"{site}/enter", agent)
    entered = authorize_and_redeem(body["challenge"])
    if not entered:
        return
    session_holder["token"] = entered["session_token"]

    print("2. Browse")
    _, body = call("GET", f"{site}/products", agent, session=session_holder["token"])
    print(f"  {body}")

    print("3. Buy 1 x wine-001")
    _, body = call("POST", f"{site}/checkout", agent, {"item_id": "wine-001", "quantity": 1},
                   session_holder["token"])
    op_id = body["challenge"]["op_id"]
    authorize_and_redeem(body["challenge"])

    print("4. Retry the same purchase (should be flagged as a retry, and refused by the site)")
    _, body = call("POST", f"{site}/operations/{op_id}/challenge", agent,
                   session=session_holder["token"])
    # The website doesn't issue signed status messages yet, so nothing to forward.
    authorize_and_redeem(body["challenge"], status=None)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--site", default="http://localhost:5050")
    p.add_argument("--wallet", default="http://127.0.0.1:5060")
    p.add_argument("--agent", default="test-agent")
    args = p.parse_args()
    run(args.site, args.wallet, args.agent, {})


if __name__ == "__main__":
    main()
