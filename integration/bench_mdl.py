"""Reliability and cost of real Longfellow proofs over PKI-issued test mDLs.

    python integration/bench_mdl.py [--n 30] [--json out.json]

Each trial uses a fresh device key and a fresh ZKARMA challenge (new nonce),
so it also exercises ECDSA randomness on both the issuer and device sides.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import integration.harness  # noqa: E402,F401  (import paths)
import proofs as website_proofs  # noqa: E402
import zkage  # noqa: E402
from integration.mdl_adapters import CLAIMS, write_issuer_pub  # noqa: E402
from spec.zkarma_spec import build_transcript, operation_hash  # noqa: E402
from zkarma_pki import PKI, TrustStore  # noqa: E402
from zkarma_pki.mdl import MdlIssuer  # noqa: E402


def med(xs):
    xs = sorted(xs)
    return {"median": round(statistics.median(xs), 2), "p95": round(xs[int(0.95 * (len(xs) - 1))], 2),
            "min": round(xs[0], 2), "max": round(xs[-1], 2)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--json")
    a = ap.parse_args()
    if not zkage.available():
        sys.exit("zkage not built; see zk/README.md")
    d = Path(tempfile.mkdtemp())
    pki = PKI.create(d / "pki")
    trust = TrustStore.from_bundle(pki.base / "trust_bundle")
    issuer = MdlIssuer.from_pki(pki)
    website_proofs.ZKAGE, website_proofs.CIRCUITS = zkage.ZKAGE, zkage.CIRCUITS
    website_proofs.ISSUER_PUB = write_issuer_pub(d / "issuer_pub.json", trust, issuer.cert)
    op = {"v": "zkarma-op-1", "site": "http://127.0.0.1:5050", "action": "checkout", "op_id": "a" * 32,
          "item_id": "wine-001", "item_name": "Red wine, 750 ml", "quantity": 1,
          "amount_cents": 1999, "currency": "USD"}
    t = {"issue_ms": [], "device_sign_ms": [], "prove_ms": [], "website_verify_ms": []}
    sizes, ok_prove, ok_verify, wrong_nonce_rejected = [], 0, 0, 0
    import secrets
    for _ in range(a.n):
        s = time.perf_counter()
        mdl = issuer.issue_to_new_device()
        t["issue_ms"].append((time.perf_counter() - s) * 1000)
        tr = build_transcript(op["site"], secrets.token_bytes(32), "agent-jkt", operation_hash(op))
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        s = time.perf_counter()
        mdoc = mdl.present(tr)
        t["device_sign_ms"].append((time.perf_counter() - s) * 1000)
        c = mdl.issuer_coords()
        try:
            proof, m = zkage.prove(mdoc, c["issuer_pkx"], c["issuer_pky"], tr, now, CLAIMS["age_over_18"])
        except zkage.ZkageError:
            continue
        ok_prove += 1
        t["prove_ms"].append(m["prove_ms"])
        sizes.append(m["proof_bytes"])
        s = time.perf_counter()
        ok_verify += website_proofs.verify(proof, tr, now)
        t["website_verify_ms"].append((time.perf_counter() - s) * 1000)
        other = build_transcript(op["site"], secrets.token_bytes(32), "agent-jkt", operation_hash(op))
        wrong_nonce_rejected += not website_proofs.verify(proof, other, now)
    res = {"n": a.n, "proved": ok_prove, "website_accepted": ok_verify,
           "rejected_for_other_nonce": wrong_nonce_rejected,
           "timings_ms": {k: med(v) for k, v in t.items() if v},
           "proof_bytes": med(sizes) if sizes else None,
           "mdoc_bytes": len(mdoc), "issuer_signed_bytes": len(mdl.issuer_signed),
           "machine": f"{platform.machine()} {platform.processor() or ''}".strip(),
           "note": "prove_ms is zkage's own timer; website_verify_ms includes the subprocess"}
    print(json.dumps(res, indent=2))
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
