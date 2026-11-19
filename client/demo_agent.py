"""Deterministic honest relay demo, using the same implementation as the agent.

Run python client/demo_agent.py --site http://localhost:5050 --item wine-001
The wallet must be paired with safe-agent. Approve the checkout in its terminal.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.__main__ import main

if __name__ == "__main__":
    if "--item" not in sys.argv and "--task" not in sys.argv:
        sys.argv.extend(["--item", "wine-001"])
    raise SystemExit(main())
