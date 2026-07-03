"""
HTTP client SDK for the agentauth verification service. Mirrors the
in-process Issuer/Verifier method shapes so switching between in-process
and networked deployment is close to a drop-in change.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..caveats import Caveat
from ..token import Capability


class AgentAuthClient:
    def __init__(self, base_url: str, client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(base_url=self.base_url, timeout=10.0)

    def register_principal(self, principal_id: str) -> str:
        r = self._client.post(f"/principals/{principal_id}/register")
        r.raise_for_status()
        return r.json()["root_key_hex"]

    def mint(self, root_principal: str, to_principal: str, caveats: list[Caveat]) -> Capability:
        r = self._client.post("/tokens/mint", json={
            "root_principal": root_principal,
            "to_principal": to_principal,
            "caveats": [c.to_dict() for c in caveats],
        })
        r.raise_for_status()
        return Capability.from_dict(r.json()["token"])

    def delegate(self, token: Capability, from_principal: str, to_principal: str, caveats: list[Caveat] | None = None) -> Capability:
        r = self._client.post("/tokens/delegate", json={
            "token": token.to_dict(),
            "from_principal": from_principal,
            "to_principal": to_principal,
            "caveats": [c.to_dict() for c in (caveats or [])],
        })
        r.raise_for_status()
        return Capability.from_dict(r.json()["token"])

    def verify(self, token: Capability, context: dict[str, Any]) -> tuple[bool, str]:
        r = self._client.post("/verify", json={"token": token.to_dict(), "context": context})
        r.raise_for_status()
        body = r.json()
        return body["allowed"], body["reason"]

    def revoke(self, token_id: str) -> None:
        r = self._client.post("/revoke", json={"token_id": token_id})
        r.raise_for_status()

    def who_authorized(self, token_id: str) -> list[str]:
        r = self._client.get(f"/audit/who_authorized/{token_id}")
        r.raise_for_status()
        return r.json()["chain"]

    def close(self):
        self._client.close()
