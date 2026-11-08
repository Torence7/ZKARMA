"""Micro-benchmark of the PKI operations on the critical path.

    python demo/bench_pki.py [--n 500]

Reports median and p95 in milliseconds. These are the PKI share of the
"proof verification time" and "end-to-end latency" metrics; Longfellow's
proving/verification cost is measured separately once it is integrated.
"""
from __future__ import annotations

import argparse
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zkarma_pki import (PKI, PURPOSE_CHALLENGE, Role, TrustStore, canonical_encode,  # noqa: E402
                        sign, verify, verify_with_cert)
from zkarma_pki.keys import cert_to_pem  # noqa: E402


def bench(fn, n):
    for _ in range(min(20, n)):
        fn()
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t) * 1000)
    ts.sort()
    return statistics.median(ts), ts[int(0.95 * (n - 1))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=500)
    n = ap.parse_args().n
    with tempfile.TemporaryDirectory() as d:
        pki = PKI.create(d)
        cert, key = pki.issue(Role.WEBSITE, "https://shop.test")
        trust = TrustStore.from_bundle(Path(d) / "trust_bundle")
        payload = {"challenge_id": "a" * 32, "site": "https://shop.test",
                   "operation": {"type": "purchase", "item": "x", "qty": 1},
                   "agent_id": "agent-1", "nonce": "b" * 32, "expires_at": 1_800_000_000}
        env = sign(key, PURPOSE_CHALLENGE, payload, cert=cert)
        pem = cert_to_pem(cert)
        rows = [
            ("canonical_encode (challenge)", lambda: canonical_encode(payload)),
            ("sign (ES256)", lambda: sign(key, PURPOSE_CHALLENGE, payload)),
            ("verify (known key)", lambda: verify(env, key.public_key(), PURPOSE_CHALLENGE)),
            ("trust.verify (cert chain+CRL)", lambda: trust.verify(pem, Role.WEBSITE)),
            ("verify_with_cert (full)", lambda: verify_with_cert(env, trust, Role.WEBSITE,
                                                                 PURPOSE_CHALLENGE)),
            ("issue leaf certificate", lambda: pki.cas[Role.AGENT].issue("bench", key.public_key())),
        ]
        print(f"{'operation':34}{'median ms':>11}{'p95 ms':>10}   (n={n})")
        for name, fn in rows:
            med, p95 = bench(fn, n if "issue" not in name else min(n, 100))
            print(f"{name:34}{med:11.3f}{p95:10.3f}")
        import json
        print(f"\nenvelope size: {len(json.dumps(env))} bytes "
              f"(of which certificate PEM: {len(env['cert'])} bytes)")


if __name__ == "__main__":
    main()
