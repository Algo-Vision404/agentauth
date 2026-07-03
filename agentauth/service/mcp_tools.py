"""
Tool-call enforcement logic, factored out of the FastMCP decorators so it
can be unit tested as plain Python functions.

This is the actual point of the exercise: a security scan of ~2,000 live
MCP servers found none of them had authentication. Every tool call here
requires a capability token and is checked against it BEFORE the tool's
business logic runs -- the reference-monitor pattern applied at the exact
boundary (every MCP tool invocation) the "Software for Agents" gap
identifies as unprotected today.
"""

from __future__ import annotations

import json
from typing import Any

from ..token import Capability
from ..verifier import Verifier

# a tiny mock "database" so the demo has something real to protect
_ORDERS: dict[str, dict] = {
    "42": {"order_id": "42", "customer_id": "C-42", "status": "pending", "total": 129.99},
    "43": {"order_id": "43", "customer_id": "C-43", "status": "shipped", "total": 54.50},
}


class ToolAuthError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _parse_token(token_json: str) -> Capability:
    try:
        return Capability.from_dict(json.loads(token_json))
    except Exception as e:
        raise ToolAuthError(f"malformed token: {e}")


def _require(verifier: Verifier, token_json: str, action: str, resource: str, extra_context: dict | None = None) -> Capability:
    token = _parse_token(token_json)
    context = {"action": action, "resource": resource, **(extra_context or {})}
    allowed, reason = verifier.verify(token, context)
    if not allowed:
        raise ToolAuthError(reason)
    return token


def get_order_impl(verifier: Verifier, token_json: str, order_id: str) -> dict[str, Any]:
    _require(
        verifier, token_json, action="read", resource=f"orders/{order_id}",
        extra_context={"customer_id": _ORDERS.get(order_id, {}).get("customer_id")},
    )
    if order_id not in _ORDERS:
        return {"error": f"no such order: {order_id}"}
    return dict(_ORDERS[order_id])


def update_order_impl(verifier: Verifier, token_json: str, order_id: str, status: str) -> dict[str, Any]:
    _require(
        verifier, token_json, action="write", resource=f"orders/{order_id}",
        extra_context={"customer_id": _ORDERS.get(order_id, {}).get("customer_id")},
    )
    if order_id not in _ORDERS:
        return {"error": f"no such order: {order_id}"}
    _ORDERS[order_id]["status"] = status
    return dict(_ORDERS[order_id])
