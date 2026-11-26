"""Glue between the PKI's test mDL (pki/zkarma_pki/mdl.py) and the existing
wallet and website code, so neither needs more than a few lines changed.

Wallet (client/prover.py). Today prove(transcript, now, claim) returns
"dev-proof". make_wallet_prover() returns a function with the SAME signature
that produces a real Longfellow proof:

    from integration.mdl_adapters import make_wallet_prover
    from zkarma_pki.mdl import Mdl
    prove = make_wallet_prover(Mdl.load("wallet_mdl.json"))   # e.g. in prover.py
    proof_hex = prove(transcript, now, "age_over_18")

  Per challenge it (1) signs DeviceAuth over `transcript` with the wallet's
  device key, (2) runs client/zkage.prove on the resulting DeviceResponse.

Website (website/proofs.py). Unchanged. It reads the DMV key from
ISSUER_PUB (trust/issuer_pub.json); write that file from the PKI with

    python -m zkarma_pki.cli mdl-issuer-pub pki_out trust/issuer_pub.json

or call write_issuer_pub() below. Either way the key is taken only from an
issuer-role certificate that chains to the trust bundle.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from zkarma_pki import TrustStore
from zkarma_pki.mdl import NAMESPACE, Mdl, verified_issuer_coords

# The claims the website can ask for, as zkage attribute lists (CBOR true = f5).
CLAIMS = {
    "age_over_18": [{"namespace": NAMESPACE, "id": "age_over_18", "cbor_value_hex": "f5"}],
    "age_over_21": [{"namespace": NAMESPACE, "id": "age_over_21", "cbor_value_hex": "f5"}],
}


def make_wallet_prover(mdl: Mdl, zkage=None,
                       on_metrics: Callable[[dict], None] | None = None) -> Callable[[bytes, str, str], str]:
    """A drop-in for client/prover.prove(transcript, now, claim) -> proof_hex."""
    if zkage is None:
        import zkage  # client/zkage.py
    coords = mdl.issuer_coords()   # the prover's input; the website uses its own trusted copy

    def prove(transcript: bytes, now: str, claim: str) -> str:
        if claim not in CLAIMS:
            raise ValueError(f"unsupported claim {claim!r}")
        mdoc = mdl.present(transcript, reveal=(claim,))
        proof_hex, metrics = zkage.prove(mdoc, coords["issuer_pkx"], coords["issuer_pky"],
                                         transcript, now, CLAIMS[claim], mdl.doc_type)
        if on_metrics:
            on_metrics(metrics)
        return proof_hex

    return prove


def website_issuer_pub(trust: TrustStore, issuer_cert) -> dict:
    """{"pkx", "pky"} for website/proofs.py, only from a trusted issuer certificate."""
    c = verified_issuer_coords(issuer_cert, trust)
    return {"pkx": c["issuer_pkx"], "pky": c["issuer_pky"], "issuer": c["issuer"]}


def write_issuer_pub(path, trust: TrustStore, issuer_cert) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(website_issuer_pub(trust, issuer_cert), indent=2) + "\n")
    return p
