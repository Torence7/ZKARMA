"""The wallet's saved state: paired agents, allowed sites, and every decision
the user made. One JSON file, rewritten atomically on each change.

The credential and device key will live here too once the test DMV and the
shared zk/zkage library exist. Until then the prover is a stub.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path


class Store:
    def __init__(self, path: Path | str | None = None):
        """path=None keeps everything in memory (tests)."""
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self.data = {"agents": {}, "origins": [], "decisions": {}}
        if self.path and self.path.exists():
            self.data.update(json.loads(self.path.read_text()))

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state-")
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)

    # Agents the user has paired with this wallet. Only these can ask for proofs.
    def pair_agent(self, agent_jkt: str, name: str) -> None:
        with self._lock:
            self.data["agents"][agent_jkt] = {"name": name, "paired_at": int(time.time())}
            self._save()

    def unpair_agent(self, agent_jkt: str) -> bool:
        with self._lock:
            found = self.data["agents"].pop(agent_jkt, None) is not None
            self._save()
            return found

    def agent(self, agent_jkt: str) -> dict | None:
        return self.data["agents"].get(agent_jkt)

    # Sites the user lets agents prove to.
    def allow_origin(self, origin: str) -> None:
        with self._lock:
            if origin not in self.data["origins"]:
                self.data["origins"].append(origin)
                self._save()

    def disallow_origin(self, origin: str) -> bool:
        with self._lock:
            found = origin in self.data["origins"]
            if found:
                self.data["origins"].remove(origin)
                self._save()
            return found

    @property
    def origins(self) -> list[str]:
        return list(self.data["origins"])

    # Every decision, keyed by site and op_id (op_ids are only unique per site).
    @staticmethod
    def op_key(origin: str, op_id: str) -> str:
        return f"{origin} {op_id}"

    def decisions(self, origin: str, op_id: str) -> list[dict]:
        return list(self.data["decisions"].get(self.op_key(origin, op_id), []))

    def record_decision(self, origin: str, op_id: str, entry: dict) -> None:
        with self._lock:
            self.data["decisions"].setdefault(self.op_key(origin, op_id), []).append(entry)
            self._save()

    def history(self) -> list[tuple[str, dict]]:
        return [(key, e) for key, entries in self.data["decisions"].items() for e in entries]
