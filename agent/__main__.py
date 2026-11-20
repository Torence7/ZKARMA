"""Run with python -m agent. Secrets are read only from the environment or TTY."""
import argparse
import getpass
import json
import os

from .llm import DeepSeekSelector
from .runtime import AgentError, SafeAgent


def main():
    parser = argparse.ArgumentParser(description="ZKARMA safe shopping agent (development protocol)")
    parser.add_argument("--site", help="Website origin; prompted if omitted")
    parser.add_argument("--task", help="Natural-language purchase task; prompted if omitted")
    parser.add_argument("--wallet", default="http://127.0.0.1:5060")
    parser.add_argument("--agent", default="safe-agent", help="Identity paired in the wallet")
    parser.add_argument("--model", default=os.environ.get("DEEPSEEK_MODEL", "deepseek-flash"))
    parser.add_argument("--item", help="Exact catalog ID for a deterministic run without DeepSeek")
    parser.add_argument("--quantity", type=int, default=1, help="Quantity for --item")
    parser.add_argument("--max-total-cents", type=int, help="Hard USD budget enforced by Python")
    parser.add_argument("--approval-timeout", type=float, default=180)
    parser.add_argument("--max-refreshes", type=int, default=1)
    args = parser.parse_args()
    if args.item and args.task:
        parser.error("Choose --item or --task")
    try:
        site = args.site or input("Website [http://localhost:5050]: ").strip() or "http://localhost:5050"
        agent = SafeAgent(site, args.wallet, args.agent, approval_timeout=args.approval_timeout,
                          max_refreshes=args.max_refreshes, max_total_cents=args.max_total_cents)
        products = agent.browse_products()
        if args.item:
            item_id, quantity = args.item, args.quantity
        else:
            task = args.task or input("What would you like to buy? ").strip()
            if not task:
                raise AgentError("A purchase task is required")
            key = os.environ.get("DEEPSEEK_API_KEY") or getpass.getpass("DeepSeek API key (hidden, not saved): ")
            selector = DeepSeekSelector(key, args.model)
            for _ in range(3):
                selected = selector.select(task, products, agent.max_quantity, agent.max_total_cents)
                if selected["status"] == "selected":
                    item_id, quantity = selected["item_id"], selected["quantity"]
                    budgets = [b for b in (agent.max_total_cents, selected["max_total_cents"]) if b is not None]
                    agent.max_total_cents = min(budgets) if budgets else None
                    break
                answer = input(selected["question"] + " ").strip()
                if not answer:
                    raise AgentError("Purchase cancelled")
                task += "\nUser clarification: " + answer
            else:
                raise AgentError("Task is still ambiguous; no checkout was started")
        total = agent.validate_selection(item_id, quantity)
        print(f"Selected {quantity} x {agent.catalog[item_id]['name']}: ${total / 100:.2f} USD")
        result = agent.purchase(item_id, quantity)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "placed" else 1
    except (AgentError, EOFError, KeyboardInterrupt) as error:
        print(f"Stopped: {error or 'cancelled'}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
