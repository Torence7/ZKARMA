r"""ZKARMA client (the user's wallet).

Trusted. Holds the user's credential, shows the user each operation an agent
wants to run, and returns a proof only for the ones the user approves. It
never talks to the website: every message goes through the (untrusted) agent.

Agent API (HTTP, on 127.0.0.1):
  POST /authorize       {"challenge": <the website's 401 challenge>,
                         "status": <website status message, for retries>}
                        -> 202 {"request_id", "status": "pending", "poll"}
                        -> 4xx {"error": <reason>} if refused before asking
  GET  /authorize/<id>  -> {"status": "pending"}
                           {"status": "approved", "op_id", "nonce", "proof", "metrics"}
                           {"status": "denied" | "expired" | "error", ...}

Retries: if the user already approved this op_id, they are asked again, and
shown what the website says about the operation (did it already run?). Outside
dev mode a retry without a valid website status is refused.

Stubs, to be replaced: the agent's signature (dev header, like the website),
the website's signatures (spec.stub_sign), and the prover (prover.py).

Run:
    pip install -r client/requirements.txt
    python client/wallet.py allow-origin http://localhost:5050
    python client/wallet.py pair test-agent --name "Test agent"
    ZKARMA_DEV=1 python client/wallet.py serve   # asks for approval in this terminal

    # with the website running (ZKARMA_DEV=1 python website/app.py):
    python client/demo_agent.py
    # Both the website and the wallet need ZKARMA_DEV=1, or every agent
    # request gets "bad_signature".

Test:
    python -m unittest discover -s client/tests -t .
"""
from __future__ import annotations

import argparse
import calendar
import logging
import queue
import threading
import time
import uuid

from flask import Flask, g, jsonify, request

from config import DEV, PORT, STATE_PATH, spec
from consent import ConsentRequest, TerminalConsent
from prover import prove
from store import Store
from validate import Refused, check_status, validate_challenge


def agent_identity(req) -> str | None:
    """STUB, same as the website: dev mode takes the agent's key thumbprint
    from a header. Real agents will sign requests (Web Bot Auth)."""
    if DEV:
        return req.headers.get("X-Dev-Agent-Thumbprint") or None
    return None


class Wallet:
    def __init__(self, store: Store):
        self.store = store
        self.requests: dict[str, dict] = {}
        self.pending: queue.Queue[str] = queue.Queue()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # From the agent
    # ------------------------------------------------------------------
    def authorize(self, agent_jkt: str, body) -> tuple[dict, int]:
        agent = self.store.agent(agent_jkt)
        if agent is None:
            return {"error": "agent_not_paired"}, 403
        if not isinstance(body, dict):
            return {"error": "bad_request"}, 400
        ch = body.get("challenge")
        try:
            signed = validate_challenge(ch, self.store.origins)
        except Refused as e:
            return {"error": e.reason}, 422

        origin, op_id = ch["origin"], ch["op_id"]
        prior = self.store.decisions(origin, op_id)
        status = None
        if any(d["decision"] == "approved" for d in prior):
            status = check_status(body.get("status"), origin, op_id)
            if not status["ok"] and not DEV:
                # The user can't tell whether it already ran, so don't ask.
                return {"error": "status_required"}, 422

        challenge_time = calendar.timegm(time.strptime(ch["now"], "%Y-%m-%dT%H:%M:%SZ"))
        rid = uuid.uuid4().hex
        with self._lock:
            if any(r["state"] == "pending" and r["origin"] == origin and r["op_id"] == op_id
                   for r in self.requests.values()):
                return {"error": "already_pending"}, 409  # one prompt per operation
            self.requests[rid] = {
                "id": rid, "agent_jkt": agent_jkt, "agent_name": agent["name"],
                "challenge": ch, "origin": origin, "op_id": op_id, "signed": signed,
                "prior": prior, "status_check": status, "state": "pending",
                "deadline": challenge_time + ch["expires_in"], "result": {},
            }
        self.pending.put(rid)
        return {"request_id": rid, "status": "pending", "poll": f"/authorize/{rid}"}, 202

    def poll(self, agent_jkt: str, rid: str) -> tuple[dict, int]:
        rec = self.requests.get(rid)
        if rec is None or rec["agent_jkt"] != agent_jkt:
            return {"error": "unknown_request"}, 404
        return {"status": rec["state"], **rec["result"]}, 200

    # ------------------------------------------------------------------
    # From the user
    # ------------------------------------------------------------------
    def next_request(self, timeout: float | None = None) -> str | None:
        try:
            return self.pending.get(timeout=timeout)
        except queue.Empty:
            return None

    def decide(self, rid: str, consent) -> str:
        """Ask the user about one request, then prove if approved. Returns the
        request's final state."""
        rec = self.requests[rid]
        if time.time() > rec["deadline"]:
            rec["state"] = "expired"  # don't bother the user with a dead nonce
            return rec["state"]

        ch = rec["challenge"]
        approved = consent.decide(ConsentRequest(
            request_id=rid, agent_jkt=rec["agent_jkt"], agent_name=rec["agent_name"],
            challenge=ch, signed=rec["signed"], prior=rec["prior"], status=rec["status_check"]))
        op_hash = spec.operation_hash(ch["operation"])
        self.store.record_decision(rec["origin"], rec["op_id"], {
            "decision": "approved" if approved else "denied", "at": int(time.time()),
            "agent_jkt": rec["agent_jkt"], "action": ch["operation"]["action"],
            "operation_hash": op_hash.hex()})

        if not approved:
            rec["state"] = "denied"
        elif time.time() > rec["deadline"]:
            rec["state"] = "expired"  # the agent can get a fresh nonce and ask again
        else:
            transcript = spec.build_transcript(rec["origin"], bytes.fromhex(ch["nonce"]),
                                               rec["agent_jkt"], op_hash)
            start = time.perf_counter()
            try:
                proof = prove(transcript, ch["now"], ch["claim"])
            except Exception as e:  # noqa: BLE001  (report, don't crash the wallet)
                rec["state"], rec["result"] = "error", {"error": f"prover_failed: {e}"}
                return rec["state"]
            rec["state"] = "approved"
            rec["result"] = {"op_id": rec["op_id"], "nonce": ch["nonce"], "proof": proof,
                             "metrics": {"prove_ms": round((time.perf_counter() - start) * 1000, 3),
                                         "proof_bytes": None if DEV else len(proof) // 2}}
        return rec["state"]


def create_app(wallet: Wallet) -> Flask:
    app = Flask(__name__)

    @app.before_request
    def gate():
        if request.endpoint == "health":
            return None
        g.agent_jkt = agent_identity(request)
        if not g.agent_jkt:
            return jsonify(error="bad_signature"), 401
        return None

    @app.get("/health")
    def health():
        return jsonify(ok=True, dev=DEV)

    @app.post("/authorize")
    def authorize():
        body, code = wallet.authorize(g.agent_jkt, request.get_json(silent=True))
        return jsonify(body), code

    @app.get("/authorize/<rid>")
    def poll(rid: str):
        body, code = wallet.poll(g.agent_jkt, rid)
        return jsonify(body), code

    return app


def serve(store: Store, port: int) -> None:
    from werkzeug.serving import make_server

    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # keep the prompt readable
    wallet = Wallet(store)
    server = make_server("127.0.0.1", port, create_app(wallet), threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"ZKARMA wallet on http://127.0.0.1:{port}  (dev={DEV})")
    print(f"Allowed sites: {', '.join(store.origins) or '(none: use allow-origin)'}")
    print(f"Paired agents: {', '.join(store.data['agents']) or '(none: use pair)'}")
    print("Waiting for requests. Ctrl-C to stop.")
    consent = TerminalConsent()
    try:
        while True:
            rid = wallet.next_request(timeout=0.5)
            if rid:
                print(f"-> {wallet.decide(rid, consent)}")
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        server.shutdown()


def main() -> None:
    p = argparse.ArgumentParser(description="ZKARMA wallet (client)")
    p.add_argument("--state", default=STATE_PATH, help=f"state file (default {STATE_PATH})")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the wallet and ask for approvals here")
    s.add_argument("--port", type=int, default=PORT)
    s = sub.add_parser("pair", help="let an agent ask this wallet for proofs")
    s.add_argument("agent_jkt")
    s.add_argument("--name", required=True)
    sub.add_parser("unpair").add_argument("agent_jkt")
    sub.add_parser("allow-origin").add_argument("origin")
    sub.add_parser("disallow-origin").add_argument("origin")
    sub.add_parser("show", help="paired agents and allowed sites")
    sub.add_parser("history", help="every approval and denial")
    args = p.parse_args()

    store = Store(args.state)
    if args.cmd == "serve":
        serve(store, args.port)
    elif args.cmd == "pair":
        store.pair_agent(args.agent_jkt, args.name)
    elif args.cmd == "unpair":
        print("removed" if store.unpair_agent(args.agent_jkt) else "not paired")
    elif args.cmd == "allow-origin":
        store.allow_origin(args.origin)
    elif args.cmd == "disallow-origin":
        print("removed" if store.disallow_origin(args.origin) else "not allowed")
    elif args.cmd == "show":
        for jkt, a in store.data["agents"].items():
            print(f"agent  {jkt}  {a['name']}")
        for origin in store.origins:
            print(f"site   {origin}")
    elif args.cmd == "history":
        for key, e in store.history():
            print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['at']))}  "
                  f"{e['decision']:8}  {e['action']:8}  {key}  agent={e['agent_jkt']}")


if __name__ == "__main__":
    main()
