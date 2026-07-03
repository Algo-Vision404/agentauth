"""
HTTP verification service.

Turns the agentauth library into something a real agent runtime can call
over the network at every tool-invocation boundary, instead of only being
usable in-process. This is the missing piece flagged in the library's own
gap list: "no transport/wire protocol... this is a library, not a service."

SECURITY NOTE (see README): /principals/register returning the raw root
key over plain HTTP is a dev/demo convenience only. A real deployment
would provision root keys out-of-band (KMS, mTLS-authenticated admin
channel) and never transmit them over a request/response API.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..audit import AuditLog
from ..caveats import Caveat
from ..issuer import Issuer
from ..ledger import RevocationLedger
from ..token import Capability
from ..verifier import Verifier


# ---- request/response models ---------------------------------------------

class RegisterPrincipalResponse(BaseModel):
    principal_id: str
    root_key_hex: str


class MintRequest(BaseModel):
    root_principal: str
    to_principal: str
    caveats: list[dict[str, Any]] = []


class DelegateRequest(BaseModel):
    token: dict[str, Any]
    from_principal: str
    to_principal: str
    caveats: list[dict[str, Any]] = []


class VerifyRequest(BaseModel):
    token: dict[str, Any]
    context: dict[str, Any]


class VerifyResponse(BaseModel):
    allowed: bool
    reason: str


class RevokeRequest(BaseModel):
    token_id: str


class TokenResponse(BaseModel):
    token: dict[str, Any]
    holder: str


# ---- app factory (state is per-app-instance, not global, so tests can
# spin up isolated services) -------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(title="agentauth verification service", version="0.1.0")

    db_path = os.environ.get("AGENTAUTH_DB_PATH", ":memory:")

    issuer = Issuer()
    ledger = RevocationLedger(db_path=db_path)
    audit_log = AuditLog(db_path=db_path)
    verifier = Verifier(issuer, ledger=ledger, audit_log=audit_log)

    app.state.issuer = issuer
    app.state.ledger = ledger
    app.state.audit_log = audit_log
    app.state.verifier = verifier

    def _caveats_from_dicts(dicts: list[dict]) -> list[Caveat]:
        return [Caveat.from_dict(d) for d in dicts]

    @app.post("/principals/{principal_id}/register", response_model=RegisterPrincipalResponse)
    def register_principal(principal_id: str):
        key = issuer.register_principal(principal_id)
        return RegisterPrincipalResponse(principal_id=principal_id, root_key_hex=key.hex())

    @app.post("/tokens/mint", response_model=TokenResponse)
    def mint(req: MintRequest):
        try:
            caveats = _caveats_from_dicts(req.caveats)
            token = issuer.mint(req.root_principal, req.to_principal, caveats)
        except KeyError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return TokenResponse(token=token.to_dict(), holder=token.holder())

    @app.post("/tokens/delegate", response_model=TokenResponse)
    def delegate(req: DelegateRequest):
        try:
            token = Capability.from_dict(req.token)
            caveats = _caveats_from_dicts(req.caveats)
            new_token = token.delegate(req.from_principal, req.to_principal, caveats)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        return TokenResponse(token=new_token.to_dict(), holder=new_token.holder())

    @app.post("/verify", response_model=VerifyResponse)
    def verify(req: VerifyRequest):
        try:
            token = Capability.from_dict(req.token)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"malformed token: {e}")
        allowed, reason = verifier.verify(token, req.context)
        return VerifyResponse(allowed=allowed, reason=reason)

    @app.post("/revoke")
    def revoke(req: RevokeRequest):
        ledger.revoke(req.token_id)
        return {"token_id": req.token_id, "revoked": True}

    @app.get("/audit/trace/{token_id}")
    def audit_trace(token_id: str):
        records = audit_log.trace(token_id)
        return [
            {
                "ts": r.ts, "holder": r.holder, "allowed": r.allowed,
                "reason": r.reason, "context": r.context,
            }
            for r in records
        ]

    @app.get("/audit/who_authorized/{token_id}")
    def who_authorized(token_id: str):
        return {"chain": audit_log.who_authorized(token_id)}

    return app


app = create_app()
