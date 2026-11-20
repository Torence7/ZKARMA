"""Real local sockets and the real CLI, with a scripted wallet user."""
import logging
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "client" / "tests"))
import helpers  # noqa: E402,F401
import app as website  # noqa: E402
from consent import ScriptedConsent  # noqa: E402
from store import Store  # noqa: E402
from wallet import Wallet, create_app  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402


class HTTPFlow(unittest.TestCase):
    def test_cli_restricted_and_unrestricted_over_http(self):
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        for table in (website.OPERATIONS, website.NONCES, website.CONSUMED):
            table.clear()
        servers, threads = [], []
        stop = threading.Event()
        try:
            site = make_server("127.0.0.1", 0, website.app, threaded=True)
            servers.append(site)
            site_url = f"http://127.0.0.1:{site.server_port}"
            store = Store(None)
            store.allow_origin(site_url)
            store.pair_agent("safe-agent", "Safe agent")
            wallet = Wallet(store)
            consent = ScriptedConsent(lambda _: True)
            wallet_server = make_server("127.0.0.1", 0, create_app(wallet), threaded=True)
            servers.append(wallet_server)
            wallet_url = f"http://127.0.0.1:{wallet_server.server_port}"

            def approve():
                while not stop.is_set():
                    rid = wallet.next_request(0.05)
                    if rid:
                        wallet.decide(rid, consent)

            with patch.object(website, "ORIGIN", site_url):
                for target in (site.serve_forever, wallet_server.serve_forever, approve):
                    thread = threading.Thread(target=target, daemon=True)
                    thread.start()
                    threads.append(thread)
                for item in ("wine-001", "water-001"):
                    result = subprocess.run([sys.executable, "-m", "agent", "--site", site_url,
                        "--wallet", wallet_url, "--item", item], cwd=ROOT, capture_output=True,
                        text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('"status": "placed"', result.stdout)
                    self.assertNotIn("dev-proof", result.stdout)
                self.assertEqual(len(consent.seen), 1)
                self.assertEqual(consent.seen[0].operation["action"], "checkout")
                self.assertEqual(len(website.CONSUMED), 2)
        finally:
            stop.set()
            for server in servers:
                if threads:
                    server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
