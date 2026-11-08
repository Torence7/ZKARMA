"""Certificate roles and the OIDs that mark them.

Each leaf certificate carries exactly one ZKARMA role in its Extended Key Usage
extension. Verification always checks the expected role, so an agent
certificate can never be accepted where a website certificate is required
(certificate-type confusion).

The OIDs live under 1.3.6.1.4.1.99999, a placeholder private-enterprise arc
for the prototype. Swap it for a registered arc if this ever leaves the lab.
"""
from __future__ import annotations

from enum import Enum

from cryptography.x509.oid import ObjectIdentifier

ZKARMA_ARC = "1.3.6.1.4.1.99999"


class Role(str, Enum):
    ISSUER = "issuer"     # DMV document signer: signs user credentials
    WEBSITE = "website"   # relying website: signs challenges
    AGENT = "agent"       # AI agent: signs the requests it relays


ROLE_EKU = {
    Role.ISSUER: ObjectIdentifier(f"{ZKARMA_ARC}.1.1"),
    Role.WEBSITE: ObjectIdentifier(f"{ZKARMA_ARC}.1.2"),
    Role.AGENT: ObjectIdentifier(f"{ZKARMA_ARC}.1.3"),
}
EKU_ROLE = {v: k for k, v in ROLE_EKU.items()}

# Which intermediate CA is allowed to issue which role.
CA_NAME = {
    Role.ISSUER: "ZKARMA Issuer CA",
    Role.WEBSITE: "ZKARMA Website CA",
    Role.AGENT: "ZKARMA Agent CA",
}

ROOT_NAME = "ZKARMA Test Root CA"

# URI scheme placed in the Subject Alternative Name of agent certificates.
AGENT_URI_PREFIX = "agent://"
ISSUER_URI_PREFIX = "issuer://"
