"""The wallet's side of zkage (zk/, Rust, wraps Google's Longfellow ZK).

zkage runs as a subprocess: JSON request on stdin, one JSON line on stdout.
The website's verifier (website/proofs.py) calls the same binary with
`verify`; the fields here must match what it sends.

Build once (see zk/README.md):
    cargo build --release --manifest-path zk/Cargo.toml
    zk/target/release/zkage circuits --out zk/circuits-1attr.bin

Config (env vars, with defaults, same as website/proofs.py):
  ZKAGE_BIN       zk/target/release/zkage
  ZKAGE_CIRCUITS  zk/circuits-1attr.bin
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ZKAGE = Path(os.environ.get("ZKAGE_BIN", ROOT / "zk" / "target" / "release" / "zkage"))
CIRCUITS = Path(os.environ.get("ZKAGE_CIRCUITS", ROOT / "zk" / "circuits-1attr.bin"))

DOC_TYPE = "org.iso.18013.5.1.mDL"
# CBOR true is 0xf5.
AGE_OVER_18 = [{"namespace": "org.iso.18013.5.1", "id": "age_over_18", "cbor_value_hex": "f5"}]


class ZkageError(RuntimeError):
    pass


def available() -> bool:
    return ZKAGE.exists() and CIRCUITS.exists()


def _run(command: str, request: dict, timeout: float = 120) -> dict:
    if not available():
        raise ZkageError(f"Missing {ZKAGE} or {CIRCUITS}. See zk/README.md to build them.")
    try:
        out = subprocess.run([str(ZKAGE), command, "--circuits", str(CIRCUITS)],
                             input=json.dumps(request), capture_output=True, text=True,
                             timeout=timeout)
        answer = json.loads(out.stdout.strip().splitlines()[-1])
    except (subprocess.TimeoutExpired, IndexError, ValueError) as e:
        raise ZkageError(f"zkage {command} failed: {e!r}") from e
    if answer.get("ok") is not True:
        raise ZkageError(f"zkage {command}: {answer.get('error', 'unknown error')}")
    return answer


def prove(mdoc: bytes, issuer_pkx: str, issuer_pky: str, transcript: bytes, now: str,
          attributes: list[dict] = AGE_OVER_18, doc_type: str = DOC_TYPE) -> tuple[str, dict]:
    """Longfellow proof that `mdoc` has `attributes`, valid at `now`, presented
    over `transcript`. The mdoc's device signature must already cover
    `transcript`. Returns (proof_hex, metrics)."""
    answer = _run("prove", {
        "mdoc_hex": mdoc.hex(),
        "issuer_pkx": issuer_pkx,
        "issuer_pky": issuer_pky,
        "transcript_hex": transcript.hex(),
        "attributes": attributes,
        "now": now,
        "doc_type": doc_type,
    })
    metrics = {"prove_ms": answer["prove_ms"], "proof_bytes": answer["proof_bytes"]}
    return answer["proof_hex"], metrics


def verify(proof_hex: str, issuer_pkx: str, issuer_pky: str, transcript: bytes, now: str,
           attributes: list[dict] = AGE_OVER_18, doc_type: str = DOC_TYPE) -> bool:
    """For the wallet's own self-checks; the website has its own copy in proofs.py."""
    try:
        _run("verify", {
            "proof_hex": proof_hex,
            "issuer_pkx": issuer_pkx,
            "issuer_pky": issuer_pky,
            "transcript_hex": transcript.hex(),
            "attributes": attributes,
            "now": now,
            "doc_type": doc_type,
        })
        return True
    except ZkageError:
        return False
