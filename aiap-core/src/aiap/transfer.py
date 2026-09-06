# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Wang Lu
from __future__ import annotations
import base64, copy
from datetime import datetime, timezone
import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .validation import validate_document

DOMAIN = b"AIAP-TRANSFER-V0.3\n"

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def unsigned_certificate(cert: dict) -> dict:
    obj = copy.deepcopy(cert)
    obj["proof"]["signature"] = ""
    return obj

def signing_bytes(cert: dict) -> bytes:
    obj = unsigned_certificate(cert)
    return DOMAIN + jcs.canonicalize(obj)

def sign_certificate(cert: dict, private_key: Ed25519PrivateKey) -> dict:
    signed = copy.deepcopy(cert)
    signed["proof"]["algorithm"] = "Ed25519"
    signed["proof"]["signature"] = _b64u(private_key.sign(signing_bytes(signed)))
    return signed

def verify_certificate(cert: dict, public_key: Ed25519PublicKey) -> None:
    validate_document(cert, "transfer-certificate.schema.json")
    public_key.verify(_unb64u(cert["proof"]["signature"]), signing_bytes(cert))
    now = datetime.now(timezone.utc)
    issued = datetime.fromisoformat(cert["issued_at"].replace("Z","+00:00"))
    expires = datetime.fromisoformat(cert["expires_at"].replace("Z","+00:00"))
    if expires <= issued:
        raise ValueError("expires_at must be later than issued_at")
    if now > expires:
        raise ValueError("transfer certificate expired")
    if cert["status"] != "issued":
        raise ValueError("certificate is not in issued state")
