"""Longfellow proof check for the website.

Calls the zkage tool (zk/, Rust, wraps Google's Longfellow ZK). A proof that
passes shows that a DMV the site trusts signed an mDL with age_over_18 == true,
that the mDL is valid at `now`, and that the phone's device key signed this
exact transcript. Nothing else about the user is revealed.

Config (env vars, with defaults):
  ZKAGE_BIN          zk/target/release/zkage
  ZKAGE_CIRCUITS     zk/circuits-1attr.bin
  ZKARMA_ISSUER_PUB  trust/issuer_pub.json   the test DMV's public key, {"pkx": "0x..", "pky": "0x.."}
                     (only used with the PKI off; with it on, app.py passes the
                     key in from the DMV's certificate)
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ZKAGE = Path(os.environ.get("ZKAGE_BIN", ROOT / "zk" / "target" / "release" / "zkage"))
CIRCUITS = Path(os.environ.get("ZKAGE_CIRCUITS", ROOT / "zk" / "circuits-1attr.bin"))
ISSUER_PUB = Path(os.environ.get("ZKARMA_ISSUER_PUB", ROOT / "trust" / "issuer_pub.json"))

DOC_TYPE = "org.iso.18013.5.1.mDL"
# The one fact the site asks for, age_over_18 == true. CBOR true is 0xf5.
AGE_OVER_18 = [{"namespace": "org.iso.18013.5.1", "id": "age_over_18", "cbor_value_hex": "f5"}]


def verify(proof_hex: str, transcript: bytes, now: str, issuer: dict | None = None) -> bool:
    """True only if Longfellow accepts the proof for this transcript, time and
    DMV key. `issuer` is the DMV key; if it's not given, it's read from ISSUER_PUB."""
    for path in (ZKAGE, CIRCUITS) if issuer else (ZKAGE, CIRCUITS, ISSUER_PUB):
        if not path.exists():
            raise RuntimeError(f"Missing {path}. See zk/README.md (zkage) or the PKI setup in website/app.py.")
    issuer = issuer or json.loads(ISSUER_PUB.read_text())
    request = {
        "proof_hex": proof_hex,
        "issuer_pkx": issuer["pkx"],
        "issuer_pky": issuer["pky"],
        "transcript_hex": transcript.hex(),
        "attributes": AGE_OVER_18,
        "now": now,
        "doc_type": DOC_TYPE,
    }
    try:
        out = subprocess.run([str(ZKAGE), "verify", "--circuits", str(CIRCUITS)],
                             input=json.dumps(request), capture_output=True, text=True, timeout=60)
        return json.loads(out.stdout.strip().splitlines()[-1])["ok"] is True
    except (subprocess.TimeoutExpired, IndexError, KeyError, ValueError):
        return False  # zkage hung, crashed or printed junk. Fail closed.
