"""
api.py -- the FastAPI verification service.

An agent runtime calls this at every tool-invocation boundary, so verification
happens over the network instead of only inside one Python process.

Changed in 1.1.0 (this was the "no auth on the service itself" gap):
  * every mutating endpoint requires an admin key
    (`X-AgentAuth-Admin-Key` or `Authorization: Bearer ...`); read-only
    verification does not, because a verifier legitimately needs no
    administrative credentials
  * POST /principals/{id}/register no longer returns raw root key material
    unless AGENTAUTH_ALLOW_KEY_EXPORT=1 (opt-in, for local demos)
  * new endpoints: key rotation/compromise, discharges, policy, ledger usage
  * delegate() runs the attenuation guard and records `widening_rejected`
  * ledger and audit logs default to files, so state survives a restart

Configuration (environment):
  AGENTAUTH_ADMIN_KEY        admin key for mutating endpoints (default: dev-admin-key)
  AGENTAUTH_LEDGER_DB        ledger sqlite path (default: agentauth-ledger.db)
  AGENTAUTH_AUDIT_DB         audit sqlite path (default: agentauth-audit.db)
  AGENTAUTH_ALLOW_KEY_EXPORT "1" to re-enable key export from the register route
  AGENTAUTH_SEED_DEMO        "1" to register alice/bob/planner_agent + discharge services
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from ..attenuation import check_narrowing
from ..audit import DELEGATE, KEY_ROTATE, MINT, REVOKE, WIDENING_REJECTED, AuditLog
from ..caveats import Caveat
from ..discharge import discharge_summary, mint_discharge
from ..issuer import Issuer, KeyStatus, UnknownPrincipal
from ..ledger import RevocationLedger
from ..policy import PolicyError, policy_from
from ..token import Capability
from ..verifier import Verifier
from .mcp_tools import TOOL_REGISTRY, call_tool, tool_catalogue

DEV_ADMIN_KEY = "dev-admin-key"
ADMIN_KEY_HEADER = "X-AgentAuth-Admin-Key"

# caveat kinds accepted from clients; anything else is a 400, not a crash
KNOWN_CAVEAT_KINDS = ("action", "resource", "time_window", "max_uses", "agg_budget", "claim", "third_party")


# ---------------------------------------------------------------------------
# request models
# ---------------------------------------------------------------------------

class RegisterPrincipalRequest(BaseModel):
    principal_id: str
    kind: str = "agent"
    note: str = ""
    provision_key: bool = False


class MintRequest(BaseModel):
    root_principal: str
    to_principal: str
    caveats: list[dict] = Field(default_factory=list)
    purpose: str = ""


class DelegateRequest(BaseModel):
    from_principal: str
    to_principal: str
    caveats: list[dict] = Field(default_factory=list)
    purpose: str = ""
    parent_token_id: Optional[str] = None
    token: Optional[dict | str] = None
    force: bool = False  # bypass the guard (unsafe; the HMAC chain still protects)


class VerifyRequest(BaseModel):
    token: dict | str
    context: dict = Field(default_factory=dict)
    discharges: list[dict | str] = Field(default_factory=list)


class RevokeRequest(BaseModel):
    token_id: str
    reason: str = ""
    revoked_by: str = "operator"


class RotateKeyRequest(BaseModel):
    principal_id: str
    note: str = "rotated"


class CompromiseKeyRequest(BaseModel):
    principal_id: str
    key_id: Optional[str] = None
    note: str = "reported leaked"


class DischargeRequest(BaseModel):
    location: str
    parent_token_id: str
    nonce: Optional[str] = None
    predicate: str = ""
    claims: dict[str, str] = Field(default_factory=dict)


class ToolCallRequest(BaseModel):
    token: dict | str
    arguments: dict = Field(default_factory=dict)
    discharges: list[dict | str] = Field(default_factory=list)
    workflow_id: Optional[str] = None


class PolicyRequest(BaseModel):
    ast: dict
    name: str = ""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _caveats(raw: list[dict]) -> list[Caveat]:
    caveats: list[Caveat] = []
    for item in raw:
        kind = item.get("kind")
        if kind not in KNOWN_CAVEAT_KINDS:
            raise HTTPException(
                status_code=400,
                detail=f"unknown caveat kind {kind!r}; known kinds: {list(KNOWN_CAVEAT_KINDS)}",
            )
        try:
            caveats.append(Caveat.from_dict(item))
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"malformed {kind} caveat: {exc}") from exc
    return caveats


def _service_db_path(env_var: str, filename: str) -> str:
    return os.environ.get(env_var, filename)


def create_app(
    *,
    issuer: Optional[Issuer] = None,
    verifier: Optional[Verifier] = None,
    ledger: Optional[RevocationLedger] = None,
    audit_log: Optional[AuditLog] = None,
    admin_key: Optional[str] = None,
    persist_state: bool = True,
) -> FastAPI:
    """Build the service. Inject issuer/verifier/ledger/audit in tests."""
    issuer = issuer or Issuer()
    ledger = ledger or RevocationLedger(_service_db_path("AGENTAUTH_LEDGER_DB", "agentauth-ledger.db"))
    audit_log = audit_log or AuditLog(_service_db_path("AGENTAUTH_AUDIT_DB", "agentauth-audit.db"))
    verifier = verifier or Verifier(issuer, ledger, audit_log)
    resolved_admin_key = admin_key if admin_key is not None else os.environ.get("AGENTAUTH_ADMIN_KEY", DEV_ADMIN_KEY)

    # in-process token registry: delegate-by-id is convenient for demos.
    # A multi-process deployment should resolve the parent from its own store.
    tokens: dict[str, Capability] = {}
    discharges: dict[str, dict] = {}
    tool_policies: dict[str, Any] = {}

    app = FastAPI(
        title="agentauth verification service",
        version="1.1.0",
        description=(
            "Scoped, delegatable, revocable, auditable capability tokens with a "
            "reference monitor at every tool-invocation boundary."
        ),
    )
    app.state.issuer = issuer
    app.state.verifier = verifier
    app.state.ledger = ledger
    app.state.audit_log = audit_log
    app.state.tokens = tokens
    app.state.discharges = discharges

    # ---- auth dependency ------------------------------------------------

    def require_admin(
        x_agentauth_admin_key: Optional[str] = Header(default=None, alias=ADMIN_KEY_HEADER),
        authorization: Optional[str] = Header(default=None),
    ) -> None:
        offered = x_agentauth_admin_key or ""
        if not offered and authorization and authorization.lower().startswith("bearer "):
            offered = authorization[7:].strip()
        if not resolved_admin_key:
            raise HTTPException(status_code=500, detail="service has no admin key configured")
        if offered != resolved_admin_key:
            raise HTTPException(
                status_code=401,
                detail=(
                    f"admin key required: send the {ADMIN_KEY_HEADER} header. "
                    "Verification (/verify, /tools/*) needs no admin key."
                ),
            )

    # ---- health / introspection ----------------------------------------

    @app.get("/health")
    def health() -> dict:
        return {
            "ok": True,
            "version": "1.1.0",
            "principals": len([k for k in issuer.list_keys()]),
            "tokens_known": len(tokens),
            "ledger": ledger.stats(),
            "audit": audit_log.stats(),
            "admin_key_required_for_mutations": True,
            "admin_key_is_dev_default": resolved_admin_key == DEV_ADMIN_KEY,
        }

    @app.get("/keys")
    def list_keys() -> dict:
        return {"keys": issuer.list_keys()}

    @app.get("/tools")
    def list_tools() -> dict:
        return {"tools": tool_catalogue(tool_policies)}

    # ---- principals ------------------------------------------------------

    @app.post("/principals", status_code=201, dependencies=[Depends(require_admin)])
    def register_principal(body: RegisterPrincipalRequest) -> dict:
        if body.kind not in ("human", "agent", "service", "discharge_service"):
            raise HTTPException(status_code=400, detail="kind must be human|agent|service|discharge_service")
        export = False
        provision = body.provision_key or body.kind in ("human", "discharge_service")
        key_id = None
        if provision or issuer.has_principal(body.principal_id):
            issuer.register_principal(body.principal_id, note=body.note, overwrite=issuer.has_principal(body.principal_id))
            key_id = issuer.active_key_id(body.principal_id)
        export = bool(os.environ.get("AGENTAUTH_ALLOW_KEY_EXPORT") == "1")
        return {
            "ok": True,
            "principal_id": body.principal_id,
            "kind": body.kind,
            "key_id": key_id,
            # the raw key is only ever returned when explicitly opted in for demos
            "key_exported": False,
            "note": (
                "Root keys are provisioned out of band (KMS, mTLS-authenticated admin channel). "
                "This endpoint deliberately does not return key material; set "
                "AGENTAUTH_ALLOW_KEY_EXPORT=1 only for local demos."
            )
            if not export
            else "key export enabled (AGENTAUTH_ALLOW_KEY_EXPORT=1)",
        }

    @app.post("/principals/{principal_id}/register", dependencies=[Depends(require_admin)])
    def legacy_register(principal_id: str, kind: str = Query(default="human")) -> dict:
        """Deprecated alias kept for <= 1.0.0 clients.

        The old route returned the raw root key in the response body; that is now
        opt-in via AGENTAUTH_ALLOW_KEY_EXPORT=1 and off by default.
        """
        issuer.register_principal(principal_id, overwrite=issuer.has_principal(principal_id))
        payload = {
            "ok": True,
            "principal_id": principal_id,
            "kind": kind,
            "key_id": issuer.active_key_id(principal_id),
            "deprecated": True,
        }
        if os.environ.get("AGENTAUTH_ALLOW_KEY_EXPORT") == "1":
            payload["root_key"] = issuer.root_key_for(principal_id).hex()
        else:
            payload["key_exported"] = False
            payload["note"] = "root key not returned (see UPGRADE_NOTES.md: breaking change in 1.1.0)"
        return payload

    # ---- mint / delegate / revoke ---------------------------------------

    @app.post("/tokens/mint", status_code=201, dependencies=[Depends(require_admin)])
    def mint(body: MintRequest) -> dict:
        try:
            token = issuer.mint(body.root_principal, body.to_principal, _caveats(body.caveats))
        except UnknownPrincipal as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        tokens[token.token_id] = token
        audit_log.record(
            token_id=token.token_id,
            root_principal=token.root_principal,
            holder=token.holder(),
            delegation_chain=token.delegation_chain(),
            context={"caveats": body.caveats, "purpose": body.purpose, "key_id": token.key_id},
            allowed=True,
            reason=f"minted with key generation {token.key_id}",
            event=MINT,
        )
        return _token_payload(token, {"purpose": body.purpose})

    @app.post("/tokens/delegate", status_code=201, dependencies=[Depends(require_admin)])
    def delegate(body: DelegateRequest) -> dict:
        parent = _resolve_parent(body, tokens)
        if parent is None:
            raise HTTPException(status_code=404, detail="parent token not found (pass token or parent_token_id)")

        if parent.holder() != body.from_principal:
            reason = (
                f"'{body.from_principal}' is not the current holder of this token "
                f"(holder is '{parent.holder()}')"
            )
            audit_log.record(
                token_id=parent.token_id,
                root_principal=parent.root_principal,
                holder=parent.holder(),
                delegation_chain=parent.delegation_chain(),
                context={"attempted_from": body.from_principal, "attempted_to": body.to_principal},
                allowed=False,
                reason=reason,
                event=DELEGATE,
                layer="ledger",
            )
            raise HTTPException(status_code=409, detail=reason)

        added = _caveats(body.caveats)
        report = check_narrowing(parent.caveats(), added)
        if not report.ok and not body.force:
            audit_log.record(
                token_id=parent.token_id,
                root_principal=parent.root_principal,
                holder=parent.holder(),
                delegation_chain=parent.delegation_chain(),
                context={
                    "attempted_caveats": body.caveats,
                    "violations": [v.to_dict() for v in report.violations],
                },
                allowed=False,
                reason="delegation refused: would widen permissions ("
                + "; ".join(v.detail for v in report.violations)
                + ")",
                event=WIDENING_REJECTED,
                layer="caveat",
            )
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "delegation refused by the attenuation guard",
                    "narrowing": report.to_dict(),
                    "hint": "delegation can only narrow; pass force=true to demonstrate the guard "
                            "being bypassed (the HMAC chain still protects the resource)",
                },
            )

        child = parent.delegate(body.from_principal, body.to_principal, added)
        tokens[child.token_id] = child
        audit_log.record(
            token_id=child.token_id,
            root_principal=child.root_principal,
            holder=body.to_principal,
            delegation_chain=child.delegation_chain(),
            context={
                "parent_token_id": parent.token_id,
                "added_caveats": body.caveats,
                "narrowing_guard": "passed" if report.ok else "bypassed",
                "purpose": body.purpose,
            },
            allowed=True,
            reason=f"hop {child.depth()}: {body.from_principal} -> {body.to_principal} "
                   f"({len(added)} added caveat(s))",
            event=DELEGATE,
        )
        return _token_payload(child, {"parent_token_id": parent.token_id, "narrowing": report.to_dict()})

    @app.post("/tokens/revoke", dependencies=[Depends(require_admin)])
    def revoke(body: RevokeRequest) -> dict:
        ledger.revoke(body.token_id, body.reason, body.revoked_by)
        known = tokens.get(body.token_id)
        audit_log.record(
            token_id=body.token_id,
            root_principal=known.root_principal if known else "",
            holder=known.holder() if known else "",
            delegation_chain=known.delegation_chain() if known else [],
            context={"reason": body.reason, "revoked_by": body.revoked_by},
            allowed=False,
            reason=f"revoked: {body.reason}",
            event=REVOKE,
            layer="ledger",
        )
        return {"ok": True, "token_id": body.token_id, "checked_at": "every verify() call"}

    # ---- verification ---------------------------------------------------

    @app.post("/verify")
    def verify(body: VerifyRequest) -> dict:
        """Public on purpose: a verifier needs the presented token and the shared
        ledger, not administrative credentials."""
        try:
            token = Capability.parse(body.token)
        except Exception as exc:
            return {"allowed": False, "reason": f"malformed token: {exc}", "layer": "cryptographic"}
        decision = verifier.verify_detailed(token, body.context, discharges=body.discharges)
        return decision.to_dict()

    @app.post("/tools/{name}")
    def invoke_tool(name: str, body: ToolCallRequest) -> dict:
        """Run a registry tool through the full enforcement path (token first)."""
        if name not in TOOL_REGISTRY:
            raise HTTPException(status_code=404, detail=f"unknown tool {name}")
        return call_tool(
            verifier,
            name,
            body.token,
            body.arguments,
            discharges=body.discharges,
            workflow_id=body.workflow_id,
            policies=tool_policies,
        )

    # ---- keys -----------------------------------------------------------

    @app.post("/keys/rotate", dependencies=[Depends(require_admin)])
    def rotate(body: RotateKeyRequest) -> dict:
        try:
            record = issuer.rotate_key(body.principal_id, body.note)
        except UnknownPrincipal as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit_log.record(
            token_id="",
            root_principal=body.principal_id,
            holder="",
            delegation_chain=[],
            context={"new_key_id": record.key_id, "note": body.note},
            allowed=True,
            reason=f"rotated to key generation {record.key_id}: previously issued tokens keep "
                   "verifying against their own generation",
            event=KEY_ROTATE,
        )
        return {"ok": True, **record.to_public_dict()}

    @app.post("/keys/compromise", dependencies=[Depends(require_admin)])
    def compromise(body: CompromiseKeyRequest) -> dict:
        try:
            record = issuer.compromise_key(body.principal_id, body.key_id, body.note)
        except UnknownPrincipal as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        audit_log.record(
            token_id="",
            root_principal=body.principal_id,
            holder="",
            delegation_chain=[],
            context={"key_id": record.key_id, "note": body.note},
            allowed=False,
            reason=f"key generation {record.key_id} marked compromised: every token seeded from it "
                   "is now rejected at the cryptographic layer",
            event=KEY_ROTATE,
            layer="cryptographic",
            signature_valid=False,
        )
        return {"ok": True, **record.to_public_dict()}

    # ---- discharges (third-party caveats) --------------------------------

    @app.post("/discharges", status_code=201, dependencies=[Depends(require_admin)])
    def create_discharge(body: DischargeRequest) -> dict:
        key = verifier.discharge_keys.get(body.location)
        if key is None:
            try:
                key = issuer.root_key_for(body.location)
            except (UnknownPrincipal, ValueError) as exc:
                raise HTTPException(
                    status_code=404,
                    detail=f"no root key registered for discharge service '{body.location}'",
                ) from exc

        parent = tokens.get(body.parent_token_id) or _token_from_ledger(ledger, body.parent_token_id)
        nonce = body.nonce
        predicate = body.predicate
        if parent is not None:
            matching = [
                c for c in parent.caveats()
                if c.kind == "third_party" and c.location == body.location
                and (nonce is None or c.nonce == nonce)
            ]
            if not matching:
                raise HTTPException(
                    status_code=400,
                    detail=f"token has no third-party caveat for '{body.location}'",
                )
            nonce = nonce or matching[0].nonce
            predicate = predicate or matching[0].predicate
        if not nonce:
            raise HTTPException(status_code=400, detail="nonce is required when the token is unknown here")

        discharge = mint_discharge(
            service_root_key=key,
            location=body.location,
            parent_token_id=body.parent_token_id,
            nonce=nonce,
            predicate=predicate,
            claims=body.claims,
        )
        discharges[discharge.discharge_id] = discharge.to_dict()
        audit_log.record(
            token_id=body.parent_token_id,
            root_principal=body.location,
            holder=body.location,
            delegation_chain=[],
            context={"nonce": nonce, "claims": body.claims},
            allowed=True,
            reason=f"discharge {discharge.discharge_id} issued by {body.location}",
            event="discharge_mint",
        )
        return {"ok": True, "discharge": discharge.to_dict(), "serialized": discharge.serialize()}

    @app.get("/discharges")
    def list_discharges(parent_token_id: Optional[str] = None) -> dict:
        items = [discharge_summary(d) for d in discharges.values()]
        if parent_token_id:
            items = [i for i in items if i["parent_token_id"] == parent_token_id]
        return {"discharges": items, "durable": False}

    # ---- audit / ledger --------------------------------------------------

    @app.get("/audit/trace/{token_id}")
    def audit_trace(token_id: str) -> dict:
        records = audit_log.trace(token_id)
        known = tokens.get(token_id)
        return {
            "token_id": token_id,
            "authorized_by": (audit_log.who_authorized(token_id) or [None])[0],
            "holder": known.holder() if known else None,
            "authorisation_path": audit_log.who_authorized(token_id),
            "chain_integrity": "not checked here; call POST /verify to recompute the chain",
            "decisions": [
                {
                    "ts": r.ts,
                    "event": r.event,
                    "allowed": r.allowed,
                    "reason": r.reason,
                    "layer": r.layer,
                    "holder": r.holder,
                    "signature_valid": r.signature_valid,
                    "latency_ms": r.latency_ms,
                }
                for r in records
            ],
        }

    @app.get("/audit/who_authorized/{token_id}")
    def who_authorized(token_id: str) -> dict:
        path = audit_log.who_authorized(token_id)
        return {
            "token_id": token_id,
            "authorized_by": path[0] if path else None,
            "path": path,
            "hops": max(len(path) - 1, 0),
        }

    @app.get("/audit/recent")
    def audit_recent(limit: int = 50, only_denied: bool = False, event: Optional[str] = None) -> dict:
        return {
            "records": [
                {
                    "id": r.id,
                    "ts": r.ts,
                    "event": r.event,
                    "token_id": r.token_id,
                    "holder": r.holder,
                    "allowed": r.allowed,
                    "layer": r.layer,
                    "reason": r.reason,
                    "signature_valid": r.signature_valid,
                }
                for r in audit_log.recent(limit=limit, only_denied=only_denied, event=event)
            ],
            "stats": audit_log.stats(),
            "denials_by_reason": audit_log.denials_by_reason(),
            "denials_by_layer": audit_log.denials_by_layer(),
        }

    @app.get("/ledger/usage")
    def ledger_usage(workflow_id: Optional[str] = None) -> dict:
        return {
            "stats": ledger.stats(),
            "use_counts": ledger.use_counts(),
            "revocations": ledger.revocations(),
            "budgets": ledger.budget_usage(workflow_id),
            "notes": {
                "revocation": "explicit revocations are checked synchronously on every verify() call",
                "use_counts": "incremented only after a fully authorized call, so denials cost nothing",
                "aggregation": "counts DISTINCT unit values per workflow; re-reading a unit is free",
            },
        }

    # ---- policy ----------------------------------------------------------

    @app.get("/policy")
    def get_policy() -> dict:
        return {
            "verifier_policy": verifier.policy.to_dict() if verifier.policy else None,
            "tool_policies": {
                name: (policy_from(source) or {}).to_dict()
                for name, source in tool_policies.items()
            },
            "tool_policy_defaults": {
                spec.name: {
                    "policy": policy_from(spec.policy).render() if spec.policy else None,
                    "note": spec.policy_note,
                }
                for spec in TOOL_REGISTRY.values()
            },
        }

    @app.put("/policy", dependencies=[Depends(require_admin)])
    def set_policy(body: PolicyRequest) -> dict:
        try:
            policy = policy_from(body.ast)
        except PolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        policy.name = body.name
        verifier.set_policy(policy)
        return {"ok": True, "policy": policy.to_dict()}

    @app.put("/policy/tools/{tool_name}", dependencies=[Depends(require_admin)])
    def set_tool_policy(tool_name: str, body: PolicyRequest) -> dict:
        if tool_name not in TOOL_REGISTRY:
            raise HTTPException(status_code=404, detail=f"unknown tool {tool_name}")
        try:
            policy = policy_from(body.ast)
        except PolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        tool_policies[tool_name] = policy.ast
        return {"ok": True, "tool": tool_name, "policy": policy.to_dict()}

    # ---- optional demo seed ---------------------------------------------

    if os.environ.get("AGENTAUTH_SEED_DEMO") == "1":
        seed_demo_state(app)

    return app


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------

def _resolve_parent(body: DelegateRequest, tokens: dict[str, Capability]) -> Optional[Capability]:
    if body.parent_token_id and body.parent_token_id in tokens:
        return tokens[body.parent_token_id]
    if body.token is not None:
        try:
            return Capability.parse(body.token)
        except Exception:
            return None
    return None


def _token_from_ledger(_ledger: RevocationLedger, _token_id: str) -> Optional[Capability]:
    """Hook for deployments that keep tokens in a store; in-process service has none."""
    return None


def _token_payload(token: Capability, extra: Optional[dict] = None) -> dict:
    payload = {
        "ok": True,
        "token": token.to_dict(),
        "token_id": token.token_id,
        "key_id": token.key_id,
        "holder": token.holder(),
        "depth": token.depth(),
        "serialized": token.serialize(),
        "compact": token.to_compact(),
    }
    payload.update(extra or {})
    return payload


def seed_demo_state(app: FastAPI) -> None:
    """Small fixture used by examples/demo_http_service.py."""
    issuer: Issuer = app.state.issuer
    for principal_id, kind in (
        ("alice", "human"),
        ("bob", "human"),
        ("hr-directory", "discharge_service"),
    ):
        issuer.register_principal(principal_id, note=f"demo {kind}")
    app.state.audit_log.record(
        token_id="",
        root_principal="system",
        holder="",
        delegation_chain=[],
        context={"seeded_at": time.time()},
        allowed=True,
        reason="demo principals seeded (AGENTAUTH_SEED_DEMO=1)",
        event=KEY_ROTATE,
    )
