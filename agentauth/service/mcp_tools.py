"""
mcp_tools.py -- tool-call enforcement logic, factored out of the FastMCP
decorators so it can be unit tested as plain Python functions.

This is the actual point of the exercise: a security scan of ~2,000 live MCP
servers found none of them had authentication. Every tool call here requires a
capability token and is checked against it BEFORE the tool's business logic
runs -- the reference-monitor pattern applied at the exact boundary (every MCP
tool invocation) the "Software for Agents" gap identifies as unprotected today.

Changed in 1.1.0:
  * the tool table is data (TOOL_REGISTRY) instead of two hand-written
    functions, so tools can carry a declarative policy
  * each tool declares its action, resource template, required arguments and a
    server-side policy (agentauth.policy) evaluated after the token layers pass
  * four tools instead of two; the new ones exist to exercise the interesting
    cases (aggregation budgets, policy-bounded search)
  * new optional tools accept discharge tokens for third-party caveats
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..attenuation import check_narrowing  # noqa: F401  (re-exported for convenience)
from ..policy import Policy, policy_from
from ..token import Capability
from ..verifier import Verifier

# ---------------------------------------------------------------------------
# a small "database" so the demo has something real to protect
# ---------------------------------------------------------------------------

_ORDERS: dict[str, dict] = {
    "42": {"order_id": "42", "customer_id": "C-42", "status": "pending", "total": 129.99, "region": "eu-west"},
    "43": {"order_id": "43", "customer_id": "C-43", "status": "shipped", "total": 54.50, "region": "eu-west"},
    "44": {"order_id": "44", "customer_id": "C-42", "status": "delivered", "total": 320.00, "region": "us-east"},
    "45": {"order_id": "45", "customer_id": "C-44", "status": "pending", "total": 1899.00, "region": "us-east"},
    "46": {"order_id": "46", "customer_id": "C-45", "status": "shipped", "total": 7800.00, "region": "apac"},
    "47": {"order_id": "47", "customer_id": "C-43", "status": "cancelled", "total": 42.00, "region": "eu-west"},
}

_ORDER_STATUSES = ("pending", "shipped", "delivered", "cancelled", "refunded")

MAX_SEARCH_LIMIT = 100


class ToolAuthError(Exception):
    """Raised when a tool call is not authorized (never when the tool body fails)."""

    def __init__(self, reason: str, layer: str = "caveat"):
        self.reason = reason
        self.layer = layer
        super().__init__(reason)


class ToolArgumentError(ValueError):
    """Raised when arguments cannot form a resource the token could authorize."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    action: str
    resource_template: str
    required: tuple[str, ...] = ()
    parameters: dict = field(default_factory=dict)
    policy: Optional[dict] = None
    policy_note: str = ""


TOOL_REGISTRY: dict[str, ToolSpec] = {
    "get_order": ToolSpec(
        name="get_order",
        description="Read a single order. Requires a token allowing 'read' on orders/{order_id}.",
        action="read",
        resource_template="orders/{order_id}",
        required=("order_id",),
        parameters={"order_id": {"type": "string", "description": "order id, e.g. 42"}},
    ),
    "update_order": ToolSpec(
        name="update_order",
        description=(
            "Update an order's status. Requires 'write' on orders/{order_id} AND a "
            "server-side policy that bounds what this tool will ever do."
        ),
        action="write",
        resource_template="orders/{order_id}",
        required=("order_id", "status"),
        parameters={
            "order_id": {"type": "string"},
            "status": {"type": "string", "enum": list(_ORDER_STATUSES)},
            "approval_id": {"type": "string", "description": "required for cancelled/refunded"},
        },
        policy={
            "op": "and",
            "args": [
                {"op": "in", "field": "status", "value": list(_ORDER_STATUSES)},
                {
                    "op": "or",
                    "args": [
                        {"op": "nin", "field": "status", "value": ["cancelled", "refunded"]},
                        {"op": "exists", "field": "approval_id"},
                    ],
                },
                # money ceiling: no token, however scoped, can write past this
                {"op": "lte", "field": "order.total", "value": 5000},
            ],
        },
        policy_note=(
            "cancellation/refund requires an approval_id, and orders totalling more than "
            "5000 are never writable through this tool."
        ),
    ),
    "get_customer_insights": ToolSpec(
        name="get_customer_insights",
        description=(
            "Aggregate a single customer's order history. Each distinct customer counts toward "
            "the token's aggregation budget, so an agent cannot assemble a dataset one "
            "legitimate request at a time."
        ),
        action="read",
        resource_template="customers/{customer_id}/*",
        required=("customer_id",),
        parameters={"customer_id": {"type": "string", "description": "e.g. C-42"}},
    ),
    "search_orders": ToolSpec(
        name="search_orders",
        description="Search orders. Requires 'read' on orders/* plus a bounded page size.",
        action="read",
        resource_template="orders/*",
        parameters={
            "status": {"type": "string", "enum": list(_ORDER_STATUSES)},
            "limit": {"type": "number", "description": f"page size, capped at {MAX_SEARCH_LIMIT}"},
        },
        policy={
            "op": "and",
            "args": [
                {"op": "gte", "field": "limit", "value": 1},
                {"op": "lte", "field": "limit", "value": MAX_SEARCH_LIMIT},
            ],
        },
        policy_note="unbounded exports are refused: limit must be between 1 and 100.",
    ),
}


# ---------------------------------------------------------------------------
# enforcement
# ---------------------------------------------------------------------------

def _parse_token(token: str | dict) -> Capability:
    try:
        return Capability.parse(token)
    except Exception as exc:
        raise ToolAuthError(f"malformed token: {exc}", layer="cryptographic") from exc


def resource_for(spec_or_name: ToolSpec | str, arguments: dict) -> str:
    """Substitute the resource template, e.g. orders/{order_id} -> orders/42."""
    spec = TOOL_REGISTRY[spec_or_name] if isinstance(spec_or_name, str) else spec_or_name
    resource = spec.resource_template
    for key in spec.required:
        if arguments.get(key) in (None, ""):
            raise ToolArgumentError(
                f"missing required argument '{key}' for resource template '{spec.resource_template}'"
            )
    for placeholder in _placeholders(spec.resource_template):
        value = arguments.get(placeholder)
        if value in (None, ""):
            raise ToolArgumentError(f"missing argument '{placeholder}' for resource {spec.resource_template}")
        resource = resource.replace("{" + placeholder + "}", str(value))
    return resource


def _placeholders(template: str) -> list[str]:
    out, rest = [], template
    while "{" in rest:
        _, rest = rest.split("{", 1)
        name, rest = rest.split("}", 1)
        out.append(name)
    return out


def _enforce(
    verifier: Verifier,
    spec: ToolSpec,
    token: str | dict,
    resource: str,
    arguments: Optional[dict] = None,
    extra_context: Optional[dict] = None,
    discharges: Optional[list] = None,
    workflow_id: Optional[str] = None,
    policies: Optional[dict[str, Any]] = None,
) -> dict:
    """Token layers (crypto -> ledger -> discharge -> caveats) then policy.

    The call context is the tool arguments plus the prefetched resource data, so
    both caveats (aggregation unit fields, claims) and the server-side policy can
    constrain on either. `action`, `resource` and `tool` are written last so an
    argument can never spoof them.

    Returns the decision dict. Raises ToolAuthError on any denial so the tool
    body provably never runs.
    """
    parsed = _parse_token(token)
    context = {
        **(arguments or {}),
        **(extra_context or {}),
        "action": spec.action,
        "resource": resource,
        "tool": spec.name,
    }
    if workflow_id is not None:
        context["workflow_id"] = workflow_id

    policy_source = (policies or {}).get(spec.name, spec.policy)
    policy: Optional[Policy] = policy_from(policy_source) if policy_source else None

    decision = verifier.verify_detailed(parsed, context, discharges=discharges, policy=policy)
    if not decision.allowed:
        raise ToolAuthError(decision.reason, layer=decision.layer)

    return decision.to_dict()


def call_tool(
    verifier: Verifier,
    name: str,
    token: str | dict,
    arguments: Optional[dict] = None,
    discharges: Optional[list] = None,
    workflow_id: Optional[str] = None,
    policies: Optional[dict[str, Any]] = None,
) -> dict:
    """
    Single entry point used by the MCP server and the HTTP API.

    Never raises for authorization failures -- returns a structured outcome so a
    client always learns *why* (and from which layer) it was refused:

        {"tool", "allowed", "layer", "reason", "action", "resource",
         "result", "token_id", "holder", "caveats_checked", "discharges_used"}
    """
    arguments = dict(arguments or {})
    spec = TOOL_REGISTRY.get(name)
    if spec is None:
        return _outcome(name, False, "transport", f"unknown tool '{name}'")

    try:
        resource = resource_for(spec, arguments)
    except ToolArgumentError as exc:
        return _outcome(name, False, "transport", str(exc), action=spec.action)

    extra_context = _prefetch(name, arguments)

    try:
        decision = _enforce(
            verifier,
            spec,
            token,
            resource,
            arguments=arguments,
            extra_context=extra_context,
            discharges=discharges,
            workflow_id=workflow_id,
            policies=policies,
        )
    except ToolAuthError as exc:
        return _outcome(name, False, exc.layer, exc.reason, action=spec.action, resource=resource)

    # ---- authorized: only now does the tool body run ---------------------
    result = _HANDLERS[name](arguments, extra_context)
    return _outcome(
        name,
        True,
        "ok",
        "authorized",
        action=spec.action,
        resource=resource,
        result=result,
        token_id=decision.get("token_id", ""),
        holder=decision.get("holder", ""),
        caveats_checked=decision.get("caveats_checked", 0),
        discharges_used=decision.get("discharges_used", []),
    )


def _outcome(
    name: str,
    allowed: bool,
    layer: str,
    reason: str,
    action: str = "",
    resource: str = "",
    result: Any = None,
    token_id: str = "",
    holder: str = "",
    caveats_checked: int = 0,
    discharges_used: Optional[list] = None,
) -> dict:
    return {
        "tool": name,
        "allowed": allowed,
        "layer": layer,
        "reason": reason,
        "action": action,
        "resource": resource,
        "result": result,
        "token_id": token_id,
        "holder": holder,
        "caveats_checked": caveats_checked,
        "discharges_used": list(discharges_used or []),
    }


def _prefetch(name: str, arguments: dict) -> dict:
    """Context the token may constrain on (e.g. aggregation unit, policy fields)."""
    if name in {"get_order", "update_order"}:
        order = _ORDERS.get(str(arguments.get("order_id", "")))
        return {"order": order, "customer_id": order["customer_id"] if order else None}
    return {}


# ---------------------------------------------------------------------------
# handlers (the business logic that must never run unauthorized)
# ---------------------------------------------------------------------------

def _handle_get_order(arguments: dict, _context: dict) -> dict:
    order = _ORDERS.get(str(arguments["order_id"]))
    if order is None:
        return {"error": f"no such order: {arguments['order_id']}"}
    return dict(order)


def _handle_update_order(arguments: dict, _context: dict) -> dict:
    order = _ORDERS.get(str(arguments["order_id"]))
    if order is None:
        return {"error": f"no such order: {arguments['order_id']}"}
    order["status"] = str(arguments["status"])
    if arguments.get("approval_id"):
        order["approval_id"] = str(arguments["approval_id"])
    return dict(order)


def _handle_get_customer_insights(arguments: dict, _context: dict) -> dict:
    customer_id = str(arguments["customer_id"])
    orders = [o for o in _ORDERS.values() if o["customer_id"] == customer_id]
    return {
        "customer_id": customer_id,
        "orders": len(orders),
        "lifetime_value": round(sum(o["total"] for o in orders), 2),
        "statuses": [o["status"] for o in orders],
    }


def _handle_search_orders(arguments: dict, _context: dict) -> dict:
    status = arguments.get("status")
    limit = int(arguments.get("limit", 10))
    rows = [o for o in _ORDERS.values() if status is None or o["status"] == status]
    return {"count": len(rows), "limit": limit, "orders": [dict(r) for r in rows[:limit]]}


_HANDLERS: dict[str, Callable[[dict, dict], Any]] = {
    "get_order": _handle_get_order,
    "update_order": _handle_update_order,
    "get_customer_insights": _handle_get_customer_insights,
    "search_orders": _handle_search_orders,
}


# ---------------------------------------------------------------------------
# backward-compatible imperative API (<= 1.0.0 signatures preserved)
# ---------------------------------------------------------------------------

def get_order_impl(verifier: Verifier, token_json: str, order_id: str, discharges: Optional[list] = None) -> dict:
    outcome = call_tool(verifier, "get_order", token_json, {"order_id": order_id}, discharges=discharges)
    if not outcome["allowed"]:
        raise ToolAuthError(outcome["reason"], layer=outcome["layer"])
    return outcome["result"]


def update_order_impl(
    verifier: Verifier,
    token_json: str,
    order_id: str,
    status: str,
    approval_id: Optional[str] = None,
    discharges: Optional[list] = None,
) -> dict:
    arguments = {"order_id": order_id, "status": status}
    if approval_id is not None:
        arguments["approval_id"] = approval_id
    outcome = call_tool(verifier, "update_order", token_json, arguments, discharges=discharges)
    if not outcome["allowed"]:
        raise ToolAuthError(outcome["reason"], layer=outcome["layer"])
    return outcome["result"]


def get_customer_insights_impl(
    verifier: Verifier, token_json: str, customer_id: str, workflow_id: Optional[str] = None
) -> dict:
    outcome = call_tool(
        verifier, "get_customer_insights", token_json, {"customer_id": customer_id}, workflow_id=workflow_id
    )
    if not outcome["allowed"]:
        raise ToolAuthError(outcome["reason"], layer=outcome["layer"])
    return outcome["result"]


def search_orders_impl(
    verifier: Verifier, token_json: str, status: Optional[str] = None, limit: int = 10
) -> dict:
    arguments = {"limit": limit}
    if status is not None:
        arguments["status"] = status
    outcome = call_tool(verifier, "search_orders", token_json, arguments)
    if not outcome["allowed"]:
        raise ToolAuthError(outcome["reason"], layer=outcome["layer"])
    return outcome["result"]


# ---------------------------------------------------------------------------
# catalogue (what an MCP client / dashboard reads)
# ---------------------------------------------------------------------------

def tool_catalogue(policies: Optional[dict[str, Any]] = None) -> list[dict]:
    catalogue = []
    for spec in TOOL_REGISTRY.values():
        policy_source = (policies or {}).get(spec.name, spec.policy)
        policy = policy_from(policy_source) if policy_source else None
        properties = dict(spec.parameters)
        properties["token"] = {
            "type": "string",
            "description": "AgentAuth capability token (JSON or agentauth1_... compact form). Required.",
        }
        properties["workflow_id"] = {
            "type": "string",
            "description": "scopes aggregation budgets; not a security boundary",
        }
        catalogue.append(
            {
                "name": spec.name,
                "description": spec.description,
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": list(spec.required) + ["token"],
                },
                "annotations": {
                    "x-agentauth-action": spec.action,
                    "x-agentauth-resource": spec.resource_template,
                    "x-agentauth-auth-required": True,
                    "x-agentauth-policy": policy.render() if policy else None,
                    "x-agentauth-policy-note": spec.policy_note,
                },
            }
        )
    return catalogue


def orders_snapshot() -> list[dict]:
    """Read-only view of the mock data, for tests and demos."""
    return [dict(o) for o in _ORDERS.values()]


def reset_orders() -> None:
    """Restore the fixture data (tests mutate it)."""
    _ORDERS.clear()
    _ORDERS.update(
        {
            "42": {"order_id": "42", "customer_id": "C-42", "status": "pending", "total": 129.99, "region": "eu-west"},
            "43": {"order_id": "43", "customer_id": "C-43", "status": "shipped", "total": 54.50, "region": "eu-west"},
            "44": {"order_id": "44", "customer_id": "C-42", "status": "delivered", "total": 320.00, "region": "us-east"},
            "45": {"order_id": "45", "customer_id": "C-44", "status": "pending", "total": 1899.00, "region": "us-east"},
            "46": {"order_id": "46", "customer_id": "C-45", "status": "shipped", "total": 7800.00, "region": "apac"},
            "47": {"order_id": "47", "customer_id": "C-43", "status": "cancelled", "total": 42.00, "region": "eu-west"},
        }
    )


def parse_token_json(token_json: str) -> Capability:
    """Kept for callers that imported the old private helper name."""
    return Capability.parse(json.loads(token_json))
