"""Command-line tool for running the test PKI.

    python -m zkarma_pki.cli init  pki_out            # root + 3 CAs + demo entities
    python -m zkarma_pki.cli issue pki_out agent agent-7
    python -m zkarma_pki.cli issue pki_out website https://news.test
    python -m zkarma_pki.cli issue pki_out agent agent-8 --pubkey agent8_pub.pem
    python -m zkarma_pki.cli revoke pki_out agent agent-7
    python -m zkarma_pki.cli show  pki_out

Test mDLs (ISO 18013-5 mdoc) from the test DMV, for real Longfellow proofs:
    python -m zkarma_pki.cli mdl-issue      pki_out wallet_mdl.json [--birth-date 2000-01-01]
    python -m zkarma_pki.cli mdl-issue      pki_out wallet_mdl.json --device-pubkey dev_pub.pem
    python -m zkarma_pki.cli mdl-issuer-pub pki_out trust/issuer_pub.json   # for website/proofs.py
    python -m zkarma_pki.cli mdl-show       wallet_mdl.json

Wallet pairing id (agent_jkt = RFC 7638 thumbprint of the agent's certified key):
    python -m zkarma_pki.cli thumbprint pki_out/issued/agent/safe-agent/cert.pem
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


def cmd_mdl_issue(a):
    from datetime import date
    from .mdl import Mdl, MdlIssuer, default_elements
    from .keys import generate_key
    pki = PKI.load(a.dir)
    issuer = MdlIssuer.from_pki(pki, a.issuer)
    elements = default_elements(birth_date=date.fromisoformat(a.birth_date),
                                family_name=a.family_name, given_name=a.given_name)
    kw = {"valid_for": timedelta(days=a.valid_days)}
    if a.device_pubkey:
        # The wallet made its own device key and sent only the public half.
        pub = serialization.load_pem_public_key(Path(a.device_pubkey).read_bytes())
        Path(a.out).write_bytes(issuer.issue(pub, elements, **kw))
        print(f"wrote IssuerSigned (CBOR) for the given device key -> {a.out}")
        return
    device_key = generate_key()
    mdl = Mdl(issuer.issue(device_key.public_key(), elements, **kw), device_key)
    mdl.save(a.out)
    v = mdl.validity()
    print(f"issued test mDL from {a.issuer}: age_over_18={elements['age_over_18']} "
          f"valid {v['validFrom']} .. {v['validUntil']}")
    print(f"  -> {a.out}  (contains the wallet's device private key: test use only)")


def cmd_mdl_issuer_pub(a):
    from .mdl import verified_issuer_coords
    from .trust import TrustStore
    pki = PKI.load(a.dir)
    trust = TrustStore.from_bundle(pki.base / "trust_bundle")
    cert = (pki.base / "issued" / Role.ISSUER.value / a.issuer / "cert.pem").read_bytes()
    c = verified_issuer_coords(cert, trust, expected_name=a.issuer)
    out = {"pkx": c["issuer_pkx"], "pky": c["issuer_pky"], "issuer": c["issuer"]}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {a.out} (issuer {a.issuer}, checked against the trust bundle)")


def cmd_mdl_show(a):
    from .mdl import Mdl
    mdl = Mdl.load(a.file)
    print(json.dumps({"doc_type": mdl.doc_type, "issuer": mdl.issuer_cert.subject.rfc4514_string(),
                      "validity": mdl.validity(), "elements": mdl.elements(),
                      **mdl.issuer_coords()}, indent=2))


def cmd_thumbprint(a):
    import base64
    import hashlib
    from .keys import load_cert
    n = load_cert(Path(a.cert)).public_key().public_numbers()
    b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()  # noqa: E731
    jwk = json.dumps({"crv": "P-256", "kty": "EC", "x": b64(n.x), "y": b64(n.y)}, separators=(",", ":"))
    print(base64.urlsafe_b64encode(hashlib.sha256(jwk.encode()).digest()).rstrip(b"=").decode())


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
    s = sub.add_parser("mdl-issue", help="issue a test mDL from the test DMV")
    s.add_argument("dir"); s.add_argument("out")
    s.add_argument("--issuer", default="test-dmv")
    s.add_argument("--birth-date", default="2000-01-01")
    s.add_argument("--family-name", default="Doe"); s.add_argument("--given-name", default="Alex")
    s.add_argument("--valid-days", type=int, default=365)
    s.add_argument("--device-pubkey", help="wallet's PEM device public key (else one is generated)")
    s.set_defaults(fn=cmd_mdl_issue)
    s = sub.add_parser("mdl-issuer-pub", help="DMV key as issuer_pub.json, for website/proofs.py")
    s.add_argument("dir"); s.add_argument("out"); s.add_argument("--issuer", default="test-dmv")
    s.set_defaults(fn=cmd_mdl_issuer_pub)
    s = sub.add_parser("mdl-show", help="show a test mDL file")
    s.add_argument("file"); s.set_defaults(fn=cmd_mdl_show)
    s = sub.add_parser("thumbprint", help="agent_jkt (RFC 7638) of a certificate, for wallet pairing")
    s.add_argument("cert"); s.set_defaults(fn=cmd_thumbprint)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
