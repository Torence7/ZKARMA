"""Writes spec/test_vectors.json: fixed inputs and the exact bytes every
party (website, client, agent) must produce. Run: python spec/make_vectors.py"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from spec import zkarma_spec as spec  # noqa: E402

CASES = [
    {"origin": "http://localhost:5050", "nonce": "00" * 32, "agent_jkt": "test-agent",
     "operation": {"v": "zkarma-op-1", "site": "http://localhost:5050", "action": "enter",
                   "op_id": "0" * 32, "duration_s": 1800}},
    {"origin": "http://localhost:5050", "nonce": "ab" * 32, "agent_jkt": "agent-2",
     "operation": {"v": "zkarma-op-1", "site": "http://localhost:5050", "action": "checkout",
                   "op_id": "f" * 32, "item_id": "wine-001", "item_name": "Red wine, 750 ml",
                   "quantity": 2, "amount_cents": 3998, "currency": "USD"}},
    {"origin": "https://shop.example", "nonce": "5a" * 32, "agent_jkt": "agent-é",
     "operation": {"v": "zkarma-op-1", "site": "https://shop.example", "action": "checkout",
                   "op_id": "1" * 32, "item_id": "vape-001", "item_name": "Café kit",
                   "quantity": 1, "amount_cents": 2499, "currency": "EUR"}},
]


def build():
    out = []
    for c in CASES:
        h = spec.operation_hash(c["operation"])
        out.append({**c, "canonical_operation": spec.canonical_json(c["operation"]).decode(),
                    "operation_hash": h.hex(),
                    "transcript": spec.build_transcript(c["origin"], bytes.fromhex(c["nonce"]),
                                                        c["agent_jkt"], h).hex()})
    return out


if __name__ == "__main__":
    (HERE / "test_vectors.json").write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {HERE / 'test_vectors.json'}")
