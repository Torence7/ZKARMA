"""Shared test setup. Import this before any client module: it turns on dev
mode and puts client/, website/ and the repo root on the import path."""
import hashlib
import os
import sys
from pathlib import Path

os.environ["ZKARMA_DEV"] = "1"
ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "client", ROOT / "website"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


def binding_proof(transcript: bytes) -> str:
    """Test-only stand-in for a real proof that, unlike "dev-proof", is bound
    to the transcript, so tests can show a proof fails for any other site,
    nonce, agent or operation."""
    return "bind:" + hashlib.sha256(transcript).hexdigest()
