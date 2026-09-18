"""
client.py -- AgentAuthClient, an httpx-based client SDK for the verification
service.

Changed in 1.1.0:
  * `admin_key=` support (mutating endpoints require it)
  * `verify()` still returns (allowed, reason) for <= 1.0.0 compatibility;
    `verify_detailed()` returns the full decision including the deciding layer
  * wrappers for key rotation/compromise, discharges, policy, audit and ledger
  * `delegate(..., force=False)` surfaces the attenuation report instead of
    silently succeeding
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

import httpx

from ..caveats import Caveat


class AgentAuthError(RuntimeError):
    """Raised for transport/HTTP failures; carries status + payload when known."""

    def __init__(self, message: str, status_code: Optional[int] = None, payload: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class AgentAuthClient:
    def __init__(
        self,
        base_url: str = "http://localhost:8811",
        admin_key: Optional[str] = None,
        timeout: float = 10.0,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.admin_key = admin_key
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)

    # ---- plumbing -------------------------------------------------------

    def _headers(self, admin: bool) -> dict:
        headers = {"content-type": "application/json"}
        if admin:
            if not self.admin_key:
                raise AgentAuthError("this endpoint requires an admin key; pass admin_key=... to AgentAuthClient")
            headers["X-AgentAuth-Admin-Key"] = self.admin_key
        return headers

    def _request(self, method: str, path: str, *, admin: bool = False, **kwargs) -> Any:
        response = self._client.request(method, path, headers=self._headers(admin), **kwargs)
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        if response.status_code >= 400:
            raise AgentAuthError(
                f"{method} {path} -> {response.status_code}: "
                f"{payload if isinstance(payload, str) else payload.get('detail', payload)}",
                status_code=response.status_code,
                payload=payload,
            )
        return payload

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AgentAuthClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- health / introspection ----------------------------------------

    def health(self) -> dict:
        return self._request("GET", "/health")

    def list_keys(self) -> dict:
        return self._request("GET", "/keys")

    def tools(self) -> dict:
        return self._request("GET", "/tools")

    # ---- principals ------------------------------------------------------

    def register_principal(self, principal_id: str, kind: str = "agent", provision_key: bool = False) -> dict:
        """Registers a principal. Returns metadata -- never key material."""
        return self._request(
            "POST",
            "/principals",
            admin=True,
            json={"principal_id": principal_id, "kind": kind, "provision_key": provision_key},
        )

    # ---- mint / delegate ------------------------------------------------

    def mint(
        self,
        root_principal: str,
        to_principal: str,
        caveats: Iterable[Caveat],
        purpose: str = "",
    ) -> dict:
        return self._request(
            "POST",
            "/tokens/mint",
            admin=True,
            json={
                "root_principal": root_principal,
                "to_principal": to_principal,
                "caveats": [c.to_dict() for c in caveats],
                "purpose": purpose,
            },
        )

    def delegate(
        self,
        parent_token_id: str,
        from_principal: str,
        to_principal: str,
        caveats: Iterable[Caveat],
        purpose: str = "",
        force: bool = False,
    ) -> dict:
        """Attempt a narrowing hop. Raises AgentAuthError(409) when the
        attenuation guard refuses, with the violation report in .payload."""
        return self._request(
            "POST",
            "/tokens/delegate",
            admin=True,
            json={
                "parent_token_id": parent_token_id,
                "from_principal": from_principal,
                "to_principal": to_principal,
                "caveats": [c.to_dict() for c in caveats],
                "purpose": purpose,
                "force": force,
            },
        )

    def revoke(self, token_id: str, reason: str = "", revoked_by: str = "operator") -> dict:
        return self._request(
            "POST",
            "/tokens/revoke",
            admin=True,
            json={"token_id": token_id, "reason": reason, "revoked_by": revoked_by},
        )

    # ---- verification ---------------------------------------------------

    def verify(
        self,
        token: dict | str,
        context: dict,
        discharges: Optional[Iterable[dict | str]] = None,
    ) -> tuple[bool, str]:
        """Backward-compatible: (allowed, reason)."""
        decision = self.verify_detailed(token, context, discharges=discharges)
        return bool(decision["allowed"]), decision.get("reason", "")

    def verify_detailed(
        self,
        token: dict | str,
        context: dict,
        discharges: Optional[Iterable[dict | str]] = None,
    ) -> dict:
        payload = {"token": token, "context": context}
        if discharges:
            payload["discharges"] = list(discharges)
        return self._request("POST", "/verify", json=payload)

    def call_tool(
        self,
        tool: str,
        token: dict | str,
        arguments: Optional[dict] = None,
        discharges: Optional[Iterable[dict | str]] = None,
        workflow_id: Optional[str] = None,
    ) -> dict:
        body: dict[str, Any] = {"token": token, "arguments": arguments or {}}
        if discharges:
            body["discharges"] = list(discharges)
        if workflow_id:
            body["workflow_id"] = workflow_id
        return self._request("POST", f"/tools/{tool}", json=body)

    # ---- keys -----------------------------------------------------------

    def rotate_key(self, principal_id: str, note: str = "rotated via client") -> dict:
        return self._request("POST", "/keys/rotate", admin=True, json={"principal_id": principal_id, "note": note})

    def compromise_key(self, principal_id: str, key_id: Optional[str] = None, note: str = "reported leaked") -> dict:
        return self._request(
            "POST",
            "/keys/compromise",
            admin=True,
            json={"principal_id": principal_id, "key_id": key_id, "note": note},
        )

    # ---- discharges ------------------------------------------------------

    def mint_discharge(
        self,
        location: str,
        parent_token_id: str,
        nonce: Optional[str] = None,
        predicate: str = "",
        claims: Optional[dict[str, str]] = None,
    ) -> dict:
        return self._request(
            "POST",
            "/discharges",
            admin=True,
            json={
                "location": location,
                "parent_token_id": parent_token_id,
                "nonce": nonce,
                "predicate": predicate,
                "claims": claims or {},
            },
        )

    def list_discharges(self, parent_token_id: Optional[str] = None) -> dict:
        params = {"parent_token_id": parent_token_id} if parent_token_id else None
        return self._request("GET", "/discharges", params=params)

    # ---- audit / ledger / policy ----------------------------------------

    def audit_trace(self, token_id: str) -> dict:
        return self._request("GET", f"/audit/trace/{token_id}")

    def who_authorized(self, token_id: str) -> dict:
        return self._request("GET", f"/audit/who_authorized/{token_id}")

    def audit_recent(self, limit: int = 50, only_denied: bool = False, event: Optional[str] = None) -> dict:
        params: dict[str, Any] = {"limit": limit, "only_denied": only_denied}
        if event:
            params["event"] = event
        return self._request("GET", "/audit/recent", params=params)

    def ledger_usage(self, workflow_id: Optional[str] = None) -> dict:
        params = {"workflow_id": workflow_id} if workflow_id else None
        return self._request("GET", "/ledger/usage", params=params)

    def get_policy(self) -> dict:
        return self._request("GET", "/policy")

    def set_policy(self, ast: dict, name: str = "") -> dict:
        return self._request("PUT", "/policy", admin=True, json={"ast": ast, "name": name})

    def set_tool_policy(self, tool_name: str, ast: dict, name: str = "") -> dict:
        return self._request("PUT", f"/policy/tools/{tool_name}", admin=True, json={"ast": ast, "name": name})
