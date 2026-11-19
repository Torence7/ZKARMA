"""Command-line tool for running the test PKI.

    python -m zkarma_pki.cli init  pki_out            # root + 3 CAs + demo entities
    python -m zkarma_pki.cli issue pki_out agent agent-7
    python -m zkarma_pki.cli issue pki_out website https://news.test
    python -m zkarma_pki.cli issue pki_out agent agent-8 --pubkey agent8_pub.pem
    python -m zkarma_pki.cli revoke pki_out agent agent-7
    python -m zkarma_pki.cli show  pki_out
"""
from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .ca import PKI
from .roles import Role

DEMO_ENTITIES = [
    (Role.ISSUER, "test-dmv"),
    (Role.WEBSITE, "https://shop.test"),
    (Role.WEBSITE, "https://other.test"),
    (Role.AGENT, "agent-1"),
    (Role.AGENT, "agent-2"),
]


def _cert_path(pki: PKI, role: Role, name: str) -> Path:
    return pki.base / "issued" / role.value / name.replace("://", "_").replace(":", "_") / "cert.pem"


def cmd_init(a):
    pki = PKI.create(a.dir)
    print(f"Created root and intermediate CAs in {pki.base}")
    if not a.no_demo:
        for role, name in DEMO_ENTITIES:
            pki.issue(role, name)
            print(f"  issued {role.value:8s} {name}")
    print(f"Trust bundle: {pki.export_trust_bundle()}  (install this out of band)")


def cmd_issue(a):
    pki = PKI.load(a.dir)
    role = Role(a.role)
    pub = None
    if a.pubkey:
        pub = serialization.load_pem_public_key(Path(a.pubkey).read_bytes())
    ttl = timedelta(hours=a.ttl_hours) if a.ttl_hours else None
    cert, priv = pki.issue(role, a.name, pub, ttl)
    print(f"issued {role.value} {a.name} serial={cert.serial_number} "
          f"until {cert.not_valid_after_utc.isoformat()}")
    print(f"  -> {_cert_path(pki, role, a.name)}" + ("  (+ key.pem)" if priv else ""))


def cmd_revoke(a):
    from .keys import load_cert
    pki = PKI.load(a.dir)
    role = Role(a.role)
    cert = load_cert(_cert_path(pki, role, a.name))
    pki.revoke(role, cert)
    print(f"revoked {role.value} {a.name} serial={cert.serial_number}; CRL + trust bundle updated")


def cmd_show(a):
    pki = PKI.load(a.dir)
    for role, ca in pki.cas.items():
        idx = ca._index()
        print(f"[{role.value} CA]  CRL #{idx['crl_number'] - 1}")
        for serial, info in idx["issued"].items():
            flag = "REVOKED" if serial in idx["revoked"] else "ok"
            print(f"   {info['name']:24s} {flag:8s} serial={serial[:12]}...")
    print(json.dumps({"trust_bundle": str(pki.base / 'trust_bundle')}))


def main(argv=None):
    p = argparse.ArgumentParser(prog="zkarma-pki")
    sub = p.add_subparsers(required=True)
    s = sub.add_parser("init"); s.add_argument("dir"); s.add_argument("--no-demo", action="store_true")
    s.set_defaults(fn=cmd_init)
    s = sub.add_parser("issue"); s.add_argument("dir"); s.add_argument("role", choices=[r.value for r in Role])
    s.add_argument("name"); s.add_argument("--pubkey", help="PEM public key (else a key pair is generated)")
    s.add_argument("--ttl-hours", type=float); s.set_defaults(fn=cmd_issue)
    s = sub.add_parser("revoke"); s.add_argument("dir"); s.add_argument("role", choices=[r.value for r in Role])
    s.add_argument("name"); s.set_defaults(fn=cmd_revoke)
    s = sub.add_parser("show"); s.add_argument("dir"); s.set_defaults(fn=cmd_show)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
