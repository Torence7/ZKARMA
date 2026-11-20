"""Client settings, and the import path for the shared spec/ module."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from spec import zkarma_spec as spec  # noqa: E402  (needs the path above)

# Dev mode, same switch as the website. It fakes the agent's signature with a
# header, accepts challenges the website hasn't signed yet, and returns the
# fake proof "dev-proof".
DEV = os.environ.get("ZKARMA_DEV") == "1"
PORT = int(os.environ.get("ZKARMA_CLIENT_PORT", "5060"))
STATE_PATH = Path(os.environ.get("ZKARMA_CLIENT_STATE",
                                 Path.home() / ".zkarma" / "client_state.json"))

SUPPORTED_CLAIMS = {"age_over_18"}
MAX_CLOCK_SKEW_S = 300      # how far the challenge's "now" may be from ours
MAX_CHALLENGE_TTL_S = 600   # refuse challenges that claim to live longer
STATUS_MAX_AGE_S = 120      # how old a website status message may be
