"""main's website, unmodified and in its own PKI mode, accepts real Longfellow
proofs from a test mDL issued by this PKI's test DMV.

main's website/site_pki.py reads the DMV key from
pki_out/issued/issuer/test-dmv/cert.pem; `zkarma_pki.cli mdl-issue` signs
with that same entity's key, so no website change is needed.

The website runs as a separate process (ZKARMA_PKI_DIR=..., dev mode off). This
test plays the agent (signed requests via integration/pki_adapters.py) and the
wallet (zkarma_pki.mdl + client/zkage.py). Skipped unless ZKARMA_MAIN_REPO
points at a checkout of main and zkage is built:

    ZKARMA_MAIN_REPO=../ZKARMA-main python -m pytest -q integration/test_main_website_mdl.py
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import date
from pathlib import Path

import pytest

import integration.harness  # noqa: F401  (import paths)
import zkage
from integration.mdl_adapters import make_wallet_prover
from integration.pki_adapters import AgentRequestSigner, jwk_thumbprint
from spec.zkarma_spec import build_transcript, operation_hash
from zkarma_pki import PKI, Role
from zkarma_pki.mdl import MdlIssuer

MAIN = Path(os.environ.get("ZKARMA_MAIN_REPO", "/nonexistent"))
pytestmark = pytest.mark.skipif(
    not ((MAIN / "website" / "site_pki.py").exists() and zkage.available()),
    reason="set ZKARMA_MAIN_REPO to a main checkout (with website/site_pki.py) and build zkage")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http(method, url, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    d = tmp_path_factory.mktemp("main")
    port = free_port()
    origin = f"http://127.0.0.1:{port}"
    pki = PKI.create(d / "pki_out")
    pki.issue(Role.WEBSITE, origin)
    pki.issue(Role.ISSUER, "test-dmv")
    agent_cert, agent_key = pki.issue(Role.AGENT, "safe-agent")
    env = {k: v for k, v in os.environ.items() if k not in ("ZKARMA_DEV", "ZKARMA_ENTRY_CHECK")}
    env.update(ZKARMA_PKI_DIR=str(pki.base), ZKARMA_ORIGIN=origin, ZKARMA_PORT=str(port),
               ZKAGE_BIN=str(zkage.ZKAGE), ZKAGE_CIRCUITS=str(zkage.CIRCUITS))
    proc = subprocess.Popen([sys.executable, str(MAIN / "website" / "app.py")], env=env,
                            cwd=MAIN, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(100):
        try:
            if http("GET", origin + "/health")[0] == 200:
                break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("main website did not start:\n" + proc.stdout.read())
    yield {"origin": origin, "pki": pki, "signer": AgentRequestSigner(agent_key, agent_cert),
           "jkt": jwk_thumbprint(agent_cert.public_key())}
    proc.terminate()
    proc.wait(timeout=10)


def signed(site, method, path, body=None):
    raw = b"" if body is None else json.dumps(body).encode()
    url = site["origin"] + path
    return http(method, url, body, site["signer"].headers(method, url, raw))


def checkout_and_redeem(site, mdl, quantity=1):
    code, r = signed(site, "POST", "/checkout", {"item_id": "wine-001", "quantity": quantity})
    assert code == 401 and "signature" in r["challenge"], (code, r)
    ch = r["challenge"]
    tr = build_transcript(ch["origin"], bytes.fromhex(ch["nonce"]), site["jkt"],
                          operation_hash(ch["operation"]))
    proof = make_wallet_prover(mdl, zkage)(tr, ch["now"], ch["claim"])
    return signed(site, "POST", "/redeem", {"nonce": ch["nonce"], "proof": proof}), proof, ch


def test_main_website_places_order_with_real_proof(site):
    status = http("GET", site["origin"] + "/health")[1]
    assert status["pki"] is True and status["dev"] is False
    mdl = MdlIssuer.from_pki(site["pki"]).issue_to_new_device(birth_date=date(2000, 1, 1))
    (code, r), _, _ = checkout_and_redeem(site, mdl)
    assert code == 200 and r["status"] == "placed", r


def test_main_website_rejects_proof_for_another_challenge(site):
    mdl = MdlIssuer.from_pki(site["pki"]).issue_to_new_device()
    _, proof, _ = checkout_and_redeem(site, mdl)
    code, r = signed(site, "POST", "/checkout", {"item_id": "wine-001", "quantity": 1})
    code, r = signed(site, "POST", "/redeem", {"nonce": r["challenge"]["nonce"], "proof": proof})
    assert code == 403 and r["error"] == "proof_invalid", r


def test_main_website_rejects_untrusted_dmv(site, tmp_path):
    evil = MdlIssuer.from_pki(PKI.create(tmp_path / "evil")).issue_to_new_device()
    (code, r), _, _ = checkout_and_redeem(site, evil)
    assert code == 403 and r["error"] == "proof_invalid", r
