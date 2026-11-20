"""Proof generation for the wallet. STUB, like website/proofs.py's real
counterpart will be: once the common zk/zkage library exists, prove() will

  1. sign the transcript with the mDL's device key (the mdoc
     DeviceAuthentication over this SessionTranscript), and
  2. run the Longfellow prover over the mDL for `claim`, valid at `now`,

and return the proof as hex, which the website's proofs.verify() checks.

The transcript is already built for real (spec.build_transcript), so only
this function changes when the library lands.
"""
from __future__ import annotations

from config import DEV

DEV_PROOF = "dev-proof"  # what the website accepts in dev mode


def prove(transcript: bytes, now: str, claim: str) -> str:
    if DEV:
        return DEV_PROOF
    raise NotImplementedError(
        "Real proofs wait on the shared zk/zkage library. Run with ZKARMA_DEV=1 for now.")
