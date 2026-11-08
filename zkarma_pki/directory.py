"""PKI directory service (FastAPI).

Run:
    ZKARMA_PKI_DIR=pki_out ZKARMA_ADMIN_TOKEN=change-me \
        uvicorn zkarma_pki.directory:app --port 8400

Public endpoints (read-only):
    GET  /trust/root                  root certificate (PEM)
    GET  /trust/ca/{role}             intermediate CA certificate (PEM)
    GET  /trust/crl/{role}            current CRL for that CA (PEM, signed)
    GET  /agents/{agent_id}/cert      an agent's current certificate (PEM)
    GET  /websites/cert?origin=...    a website's certificate (PEM)
    GET  /health

Admin endpoints (header  X-Admin-Token: ...):
    POST /admin/issue    {"role": "agent", "name": "agent-9", "public_key_pem": "..."}
    POST /admin/revoke   {"role": "agent", "name": "agent-9"}

Security note: fetching certificates and CRLs from here is safe over any
channel because they are signed by the CAs. The ROOT certificate is the one
exception: it must be installed out of band (config file), not trusted just
because this service returned it.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from .ca import PKI
from .keys import cert_to_pem, load_cert
from .roles import Role

PEM = "application/x-pem-file"


class IssueRequest(BaseModel):
    role: Role
    name: str
    public_key_pem: str
    ttl_hours: float | None = None


class RevokeRequest(BaseModel):
    role: Role
    name: str


def create_app(pki_dir: Path | str, admin_token: str) -> FastAPI:
    pki = PKI.load(pki_dir)
    app = FastAPI(title="ZKARMA PKI directory", version="0.1.0")

    def leaf_path(role: Role, name: str) -> Path:
        return pki.base / "issued" / role.value / name.replace("://", "_").replace(":", "_") / "cert.pem"

    def pem(path: Path) -> PlainTextResponse:
        if not path.exists():
            raise HTTPException(404, "not found")
        return PlainTextResponse(path.read_text(), media_type=PEM)

    def require_admin(token: str | None):
        if not token or not hmac.compare_digest(token, admin_token):
            raise HTTPException(401, "bad admin token")

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/trust/root")
    def root():
        return PlainTextResponse(cert_to_pem(pki.root_cert), media_type=PEM)

    @app.get("/trust/ca/{role}")
    def ca(role: Role):
        return PlainTextResponse(cert_to_pem(pki.cas[role].cert), media_type=PEM)

    @app.get("/trust/crl/{role}")
    def crl(role: Role):
        return pem(pki.cas[role].dir / "crl.pem")

    @app.get("/agents/{agent_id}/cert")
    def agent_cert(agent_id: str):
        return pem(leaf_path(Role.AGENT, agent_id))

    @app.get("/websites/cert")
    def website_cert(origin: str):
        return pem(leaf_path(Role.WEBSITE, origin))

    @app.post("/admin/issue")
    def issue(req: IssueRequest, x_admin_token: str | None = Header(default=None)):
        require_admin(x_admin_token)
        try:
            pub = serialization.load_pem_public_key(req.public_key_pem.encode())
            from datetime import timedelta
            ttl = timedelta(hours=req.ttl_hours) if req.ttl_hours else None
            cert, _ = pki.issue(req.role, req.name, pub, ttl)
        except (ValueError, TypeError) as e:
            raise HTTPException(400, str(e)) from e
        pki.export_trust_bundle()
        return {"serial": str(cert.serial_number), "cert_pem": cert_to_pem(cert),
                "not_after": cert.not_valid_after_utc.isoformat()}

    @app.post("/admin/revoke")
    def revoke(req: RevokeRequest, x_admin_token: str | None = Header(default=None)):
        require_admin(x_admin_token)
        p = leaf_path(req.role, req.name)
        if not p.exists():
            raise HTTPException(404, "no such certificate")
        cert = load_cert(p)
        pki.revoke(req.role, cert)
        return {"revoked_serial": str(cert.serial_number)}

    return app


def _app_from_env() -> FastAPI | None:
    d = os.environ.get("ZKARMA_PKI_DIR")
    if not d:
        return None
    return create_app(d, os.environ.get("ZKARMA_ADMIN_TOKEN", "change-me"))


app = _app_from_env()
