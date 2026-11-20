"""Showing the user what an agent wants to do, and asking yes or no.

What the user sees here is exactly what the proof gets bound to: the
operation shown is the one whose hash goes into the transcript.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field


@dataclass
class ConsentRequest:
    request_id: str
    agent_jkt: str
    agent_name: str
    challenge: dict
    signed: bool                     # website signature checked (False only in dev mode)
    prior: list = field(default_factory=list)   # earlier decisions for this op
    status: dict | None = None       # validate.check_status() result, for retries

    @property
    def operation(self) -> dict:
        return self.challenge["operation"]

    @property
    def is_retry(self) -> bool:
        return any(d["decision"] == "approved" for d in self.prior)


def _money(cents: int, currency: str) -> str:
    return f"{cents / 100:.2f} {currency}"


def _when(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def render(req: ConsentRequest) -> str:
    op = req.operation
    lines = ["", "=" * 64, "  AGE CHECK REQUEST", "=" * 64,
             f"  Site:    {req.challenge['origin']}",
             f"  Agent:   {req.agent_name}  ({req.agent_jkt})",
             f"  Proves:  {req.challenge['claim']}  (nothing else about you is shared)"]
    if op["action"] == "enter":
        lines.append(f"  Action:  ENTER the site for {op['duration_s'] // 60} minutes")
    elif op["action"] == "checkout":
        lines.append(f"  Action:  BUY {op['quantity']} x {op['item_name']} ({op['item_id']})")
        lines.append(f"  Total:   {_money(op['amount_cents'], op['currency'])}")
    if not req.signed:
        lines.append("  !! Challenge is NOT signed by the website (dev mode only).")

    if req.is_retry:
        lines += ["", "  !! RETRY: you already approved this exact operation:"]
        lines += [f"       {_when(d['at'])}  {d['decision']}  (agent {d['agent_jkt']})"
                  for d in req.prior]
        s = req.status or {}
        if s.get("ok"):
            tag = "signed" if s["signed"] else "UNSIGNED, dev mode"
            lines.append(f"     Website status ({tag}): {s['status']}, "
                         f"{'ALREADY RAN' if s['consumed'] else 'has not run'}")
            if s["consumed"]:
                lines.append("     It already ran. The site will refuse it again; "
                             "the agent has no reason to retry.")
        else:
            lines.append(f"     No usable website status ({s.get('problem', 'none provided')}). "
                         "Cannot confirm whether it already ran.")

    lines += ["", "  Full operation (this is what you sign):"]
    lines += ["    " + l for l in json.dumps(op, indent=2, sort_keys=True).splitlines()]
    lines.append("=" * 64)
    return "\n".join(lines)


class TerminalConsent:
    """Asks on the terminal. Retries default to No."""

    def __init__(self, input_fn=input, output_fn=print):
        self.input, self.output = input_fn, output_fn

    def decide(self, req: ConsentRequest) -> bool:
        self.output(render(req))
        prompt = "Approve? [y/N] " if req.is_retry else "Approve? [y/n] "
        while True:
            answer = self.input(prompt).strip().lower()
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no") or (answer == "" and req.is_retry):
                return False


class ScriptedConsent:
    """For tests: decides with a function and keeps everything it was shown."""

    def __init__(self, decide_fn):
        self.decide_fn, self.seen = decide_fn, []

    def decide(self, req: ConsentRequest) -> bool:
        self.seen.append(req)
        return self.decide_fn(req)
