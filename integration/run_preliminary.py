"""Preliminary evaluation: the PKI integrated with the current website, wallet and agent.

    python integration/run_preliminary.py [--main-website PATH] [--runs N] [--out DIR]

Writes <out>/preliminary_results.json and <out>/preliminary_results.md and
prints the summary. Three configurations are compared:

  pki    PKI adapters installed, dev mode OFF in website and wallet
  nopki  dev identity header + unsigned challenges, same binding proof as pki
  dev    the system exactly as it runs today (dev header, unsigned, "dev-proof")
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integration.harness import REPO, System  # noqa: E402
from integration.scenarios import SCENARIOS, run  # noqa: E402

from spec import zkarma_spec as spec  # noqa: E402
from zkarma_pki import canonical_encode  # noqa: E402

from integration.pki_adapters import (SIGNATURE_HEADER, verify_website_message)  # noqa: E402

MODES = ("pki", "nopki", "dev")


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))]


def summary(xs):
    return {"n": len(xs), "median_ms": round(statistics.median(xs), 3), "p95_ms": round(pct(xs, 0.95), 3),
            "mean_ms": round(statistics.mean(xs), 3)}


# ---------------------------------------------------------------------------
def run_scenarios(main_website):
    rows = []
    for sc in SCENARIOS:
        website = None
        if sc.needs == "enter+session":
            if not main_website:
                continue
            website = main_website
        for mode in (MODES if sc.contrast else ("pki",)):
            with tempfile.TemporaryDirectory() as d:
                r = run(sc, Path(d), mode, website)
            rows.append(r.row())
    return rows


def micro_bench(n):
    with tempfile.TemporaryDirectory() as d, System(d) as s:
        creds = s.agents["safe-agent"]
        signer = creds.signer()
        url, body = s.origin + "/checkout", json.dumps({"item_id": "wine-001", "quantity": 1}).encode()
        sign_ms, verify_ms, toks = [], [], []
        for _ in range(n):
            t = time.perf_counter()
            h = signer.headers("POST", url, body)
            sign_ms.append((time.perf_counter() - t) * 1000)
            toks.append(h[SIGNATURE_HEADER])
        for tok in toks:
            t = time.perf_counter()
            s.site_verifier.verify("POST", "/checkout", body, tok)
            verify_ms.append((time.perf_counter() - t) * 1000)

        code, b = s.raw_agent().site("POST", "/checkout", {"item_id": "wine-001", "quantity": 1})
        ch = b["challenge"]
        unsigned = {k: v for k, v in ch.items() if k != "signature"}
        csign, cverify = [], []
        for _ in range(n):
            t = time.perf_counter()
            sig = s.msg_signer.sign_message(unsigned)
            csign.append((time.perf_counter() - t) * 1000)
        for _ in range(n):
            t = time.perf_counter()
            verify_website_message(ch, ch["signature"], s.trust_wallet, s.origin, spec.signed_payload)
            cverify.append((time.perf_counter() - t) * 1000)
        return {
            "agent_request_sign": summary(sign_ms),
            "agent_request_verify": summary(verify_ms),
            "challenge_sign": summary(csign),
            "challenge_verify": summary(cverify),
            "sizes_bytes": {
                "agent_request_signature_header": len(toks[0]),
                "challenge_signature_field": len(ch["signature"]),
                "challenge_json_unsigned": len(json.dumps(unsigned, separators=(",", ":"))),
                "challenge_json_signed": len(json.dumps(ch, separators=(",", ":"))),
            },
        }


def http_bench(n):
    out = {}
    for mode in ("pki", "nopki"):
        with tempfile.TemporaryDirectory() as d, System(d, mode=mode) as s:
            a = s.raw_agent()
            for _ in range(10):  # warm up
                a.site("POST", "/checkout", {"item_id": "wine-001", "quantity": 1})
            xs = []
            for _ in range(n):
                t = time.perf_counter()
                code, _ = a.site("POST", "/checkout", {"item_id": "wine-001", "quantity": 1})
                xs.append((time.perf_counter() - t) * 1000)
                assert code == 401
            out[mode] = summary(xs)
    out["pki_overhead_median_ms"] = round(out["pki"]["median_ms"] - out["nopki"]["median_ms"], 3)
    return out


def purchase_bench(n):
    out = {}
    for mode in MODES:
        with tempfile.TemporaryDirectory() as d, System(d, mode=mode) as s:
            xs, placed = [], 0
            for i in range(n + 3):
                a = s.safe_agent()
                a.browse_products()
                t = time.perf_counter()
                r = a.purchase("wine-001")
                dt = (time.perf_counter() - t) * 1000
                if i >= 3:  # first runs are warm-up
                    xs.append(dt)
                    placed += r["status"] == "placed"
            out[mode] = {**summary(xs), "placed": placed}
            if mode == "pki":
                out["pki_signed_requests_per_purchase"] = round(
                    (s.site_verifier.accepted + s.wallet_verifier.accepted) / (n + 3), 2)
    out["pki_overhead_median_ms"] = round(out["pki"]["median_ms"] - out["nopki"]["median_ms"], 3)
    return out


def canonical_check(n_ops):
    vectors = json.loads((REPO / "spec" / "test_vectors.json").read_text(encoding="utf-8"))
    vec_ok = sum(spec.canonical_json(v["operation"]) == canonical_encode(v["operation"]) for v in vectors)
    ops_ok = total = 0
    with tempfile.TemporaryDirectory() as d, System(d) as s:
        a = s.raw_agent()
        items = list(s.website.CATALOG)
        for i in range(n_ops):
            item = items[i % len(items)]
            qty = 1 + i % s.website.MAX_QUANTITY
            code, b = a.site("POST", "/checkout", {"item_id": item, "quantity": qty})
            if code != 401:
                continue
            op = b["challenge"]["operation"]
            total += 1
            ops_ok += spec.canonical_json(op) == canonical_encode(op)
    edge = {}
    for name, obj in {"float": {"x": 1.5}, "astral_key_order": {"\U0001F600": 1, "｡": 2},
                      "unsafe_int": {"x": 2**60}, "non_ascii_value": {"x": "café"}}.items():
        try:
            same = spec.canonical_json(obj) == canonical_encode(obj)
            edge[name] = "same" if same else "DIFFERENT bytes"
        except Exception as e:  # noqa: BLE001
            edge[name] = f"PKI rejects ({type(e).__name__})"
    return {"spec_vectors": f"{vec_ok}/{len(vectors)}", "website_operations": f"{ops_ok}/{total}",
            "edge_cases": edge}


def regression():
    """Each teammate's existing suite, unchanged, on this branch."""
    suites = {"pki (unit)": (["-m", "pytest", "-q", "tests"], REPO / "pki"),
              "client": (["-m", "pytest", "-q", "client/tests"], REPO),
              "agent": (["-m", "pytest", "-q", "agent/tests"], REPO)}
    out = {}
    for name, (args, cwd) in suites.items():
        p = subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True)
        last = [line for line in p.stdout.strip().splitlines() if "passed" in line or "failed" in line]
        out[name] = last[-1] if last else f"exit {p.returncode}"
    p = subprocess.run([sys.executable, "demo/run_demo.py"], cwd=REPO / "pki", capture_output=True, text=True)
    out["pki demo (mock parties)"] = " | ".join(l.strip() for l in p.stdout.splitlines() if "rate" in l)
    return out


# ---------------------------------------------------------------------------
def to_markdown(res) -> str:
    L = ["# ZKARMA: preliminary PKI integration results", "",
         f"Run {res['meta']['date']} on {res['meta']['platform']} (Python {res['meta']['python']}).", ""]
    rows = res["scenarios"]
    pki = [r for r in rows if r["mode"] == "pki"]
    hon = [r for r in pki if r["kind"] == "honest"]
    att = [r for r in pki if r["kind"] == "attack"]
    L += ["## Headline (PKI mode, dev mode off)", "",
          f"* Honest flows completed: **{sum(r['accepted'] for r in hon)}/{len(hon)}**",
          f"* Attacks refused: **{sum(not r['accepted'] for r in att)}/{len(att)}**",
          f"* Attacks refused before the user was asked: "
          f"**{sum(not r['accepted'] and not r['user_prompted'] for r in att)}/{len(att)}**",
          f"* Where attacks stopped: {dict(Counter(r['stopped_at'] for r in att))}", ""]
    contrast_ids = sorted({r["id"] for r in rows if r["mode"] != "pki"}, key=lambda x: (x[0], int(x[1:])))
    L += ["## Contrast: same scenario, three configurations", "",
          "| ID | Scenario | pki | nopki (binding proof, no PKI) | dev (today) |", "|---|---|---|---|---|"]
    for i in contrast_ids:
        by = {r["mode"]: r for r in rows if r["id"] == i}
        def cell(r):
            if r is None:
                return "-"
            if r["kind"] == "honest":
                return "completed" if r["accepted"] else f"FAILED ({r['reason']})"
            return f"refused @{r['stopped_at']}: {r['reason']}" if not r["accepted"] else f"**SUCCEEDS** ({r['note']})"
        L.append(f"| {i} | {by['pki']['title']} | {cell(by.get('pki'))} | {cell(by.get('nopki'))} | {cell(by.get('dev'))} |")
    for mode in ("nopki", "dev"):
        a = [r for r in rows if r["mode"] == mode and r["kind"] == "attack"]
        if a:
            L.append(f"\n{mode}: attacks refused {sum(not r['accepted'] for r in a)}/{len(a)}")
    L += ["", "## All PKI-mode scenarios", "", "| ID | Kind | Scenario | Result | Stopped at | Reason | User asked? |",
          "|---|---|---|---|---|---|---|"]
    for r in pki:
        res_ = ("completed" if r["accepted"] else "FAILED") if r["kind"] == "honest" else (
            "refused" if not r["accepted"] else "SUCCEEDED")
        L.append(f"| {r['id']} | {r['kind']} | {r['title']} | {res_} | {r['stopped_at']} | {r['reason']} | "
                 f"{'yes' if r['user_prompted'] else 'no'} |")
    m, h, p = res["micro"], res["http"], res["purchase"]
    L += ["", "## Cost of the PKI", "",
          "| Operation | median ms | p95 ms |", "|---|---|---|"]
    for k in ("agent_request_sign", "agent_request_verify", "challenge_sign", "challenge_verify"):
        L.append(f"| {k.replace('_', ' ')} | {m[k]['median_ms']} | {m[k]['p95_ms']} |")
    L += ["", f"* HTTP `POST /checkout` round trip: pki {h['pki']['median_ms']} ms vs nopki "
          f"{h['nopki']['median_ms']} ms median (n={h['pki']['n']}), overhead **{h['pki_overhead_median_ms']} ms**",
          f"* Full restricted purchase (SafeAgent, wallet auto-approve): pki {p['pki']['median_ms']} ms, nopki "
          f"{p['nopki']['median_ms']} ms, dev {p['dev']['median_ms']} ms median (n={p['pki']['n']}); "
          f"overhead **{p['pki_overhead_median_ms']} ms**; signed requests per purchase: "
          f"{p['pki_signed_requests_per_purchase']}",
          f"* Sizes (bytes): {m['sizes_bytes']}", "",
          "## Format compatibility", "",
          f"* spec.canonical_json vs PKI canonical_encode on spec test vectors: {res['canonical']['spec_vectors']}",
          f"* ... on restricted-order operations generated by the running website: "
          f"{res['canonical']['website_operations']}",
          f"* Edge cases: {res['canonical']['edge_cases']}", "",
          "## Existing suites on this branch (unchanged)", ""]
    L += [f"* {k}: {v}" for k, v in res["regression"].items()]
    return "\n".join(L) + "\n"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--main-website", help="path to main's website/app.py (enables H5)")
    p.add_argument("--runs", type=int, default=50, help="purchases per mode")
    p.add_argument("--http-runs", type=int, default=300)
    p.add_argument("--micro-runs", type=int, default=1000)
    p.add_argument("--out", default=str(REPO / "integration" / "results"))
    args = p.parse_args()

    res = {"meta": {"date": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "platform": platform.platform(),
                    "python": platform.python_version()}}
    print("scenarios ...", flush=True)
    res["scenarios"] = run_scenarios(args.main_website)
    print("micro benchmark ...", flush=True)
    res["micro"] = micro_bench(args.micro_runs)
    print("http benchmark ...", flush=True)
    res["http"] = http_bench(args.http_runs)
    print("purchase benchmark ...", flush=True)
    res["purchase"] = purchase_bench(args.runs)
    print("format checks ...", flush=True)
    res["canonical"] = canonical_check(100)
    print("existing suites ...", flush=True)
    res["regression"] = regression()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "preliminary_results.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    md = to_markdown(res)
    (out / "preliminary_results.md").write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
