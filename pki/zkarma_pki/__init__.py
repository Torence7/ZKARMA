"""ZKARMA public key infrastructure.

Public API (import everything from here):

    from zkarma_pki import (PKI, Role, TrustStore, VerificationError,
                            sign, verify, verify_with_cert,
                            canonical_encode, canonical_hash,
                            ClientKeyring, ClientKeyRegistry, generate_key, key_id)
"""
from .ca import PKI, IntermediateCA
from .canonical import CanonicalEncodingError, canonical_encode, canonical_hash
from .keys import (cert_from_pem, cert_to_pem, generate_key, key_id, load_cert,
                   load_private_key, public_key_from_b64, public_key_to_b64)
from .registry import ClientKeyRegistry, ClientKeyring
from .roles import Role
from .signing import (PURPOSE_AGENT_REQUEST, PURPOSE_AUTHORIZATION, PURPOSE_CHALLENGE,
                      PURPOSE_CLIENT_REGISTRATION, PURPOSE_CREDENTIAL, PURPOSE_PRESENTATION,
                      sign, verify, verify_with_cert)
from .trust import TrustStore, VerificationError, VerifiedIdentity

__all__ = [n for n in dir() if not n.startswith("_")]
__version__ = "0.1.0"
