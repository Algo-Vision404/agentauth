"""Enforcement on real MCP tool functions: an authorized read succeeds, an
out-of-scope read is denied, a write attempt on a read-only token is denied, a
server-side policy refusal is denied, and a tampered token is caught before the
tool body ever executes.

    python examples/demo_mcp_server.py

This exercises the same code path the FastMCP server in
agentauth/service/mcp_server.py uses (`call_tool`), so it runs without the mcp
package installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentauth import ActionCaveat, AggregationBudgetCaveat, AuditLog, Issuer, MaxUsesCaveat, ResourceCaveat, Verifier
from agentauth.ledger import RevocationLedger
from agentauth.service.mcp_tools import call_tool, reset_orders, tool_catalogue

NOW = 1_700_000_000.0


def show(label: str, outcome: dict) -> None:
    mark = "ALLOW" if outcome["allowed"] else "DENY "
    detail = outcome["reason"] if not outcome["allowed"] else str(outcome["result"])[:60]
    print(f"  [{mark}] {label:52s} layer={outcome['layer']:<13s} {detail}")


def main() -> None:
    reset_orders()
    issuer = Issuer()
    issuer.register_principal("alice")
    verifier = Verifier(issuer, RevocationLedger(":memory:"), AuditLog(":memory:"))

    planner = issuer.mint(
        "alice",
        "planner_agent",
        [ActionCaveat(("read", "write")), ResourceCaveat(("orders/*", "customers/*")), MaxUsesCaveat(30),
         AggregationBudgetCaveat("customers_touched", 2, "customer_id")],
        ts=NOW,
    )
    sub = planner.delegate(
        "planner_agent",
        "sub_agent",
        [ActionCaveat(("read",)), ResourceCaveat(("orders/42", "customers/*")), MaxUsesCaveat(6)],
        ts=NOW + 1,
    )

    print("tools exposed (each requires a capability token):")
    for entry in tool_catalogue():
        print(f"  - {entry['name']:22s} needs {entry['annotations']['x-agentauth-action']:5s} on "
              f"{entry['annotations']['x-agentauth-resource']}")
        if entry["annotations"]["x-agentauth-policy"]:
            print(f"      server-side policy: {entry['annotations']['x-agentauth-policy']}")

    print("\nenforcement:")
    show("unauthenticated call (no token at all)",
         call_tool(verifier, "get_order", "", {"order_id": "42"}))
    show("planner_agent reads order 42",
         call_tool(verifier, "get_order", planner.serialize(), {"order_id": "42"}))
    show("sub_agent reads order 42 (inside its delegation)",
         call_tool(verifier, "get_order", sub.serialize(), {"order_id": "42"}))
    show("sub_agent reads order 43 (outside its delegation)",
         call_tool(verifier, "get_order", sub.serialize(), {"order_id": "43"}))
    show("sub_agent writes (delegated read-only token)",
         call_tool(verifier, "update_order", sub.serialize(), {"order_id": "42", "status": "shipped"}))
    show("planner_agent refunds without an approval_id (policy)",
         call_tool(verifier, "update_order", planner.serialize(), {"order_id": "42", "status": "refunded"}))
    show("planner_agent refunds with an approval_id (policy)",
         call_tool(verifier, "update_order", planner.serialize(),
                   {"order_id": "42", "status": "refunded", "approval_id": "APR-1"}))
    show("write to a 7800 order (policy money ceiling)",
         call_tool(verifier, "update_order", planner.serialize(), {"order_id": "46", "status": "shipped"}))
    show("search with a 500-row page (policy cap)",
         call_tool(verifier, "search_orders", planner.serialize(), {"limit": 500}))

    print("\naggregation inference through individually-permitted calls:")
    for customer in ("C-42", "C-42", "C-43", "C-44"):
        outcome = call_tool(
            verifier, "get_customer_insights", sub.serialize(), {"customer_id": customer},
            workflow_id="wf-inference",
        )
        show(f"get_customer_insights(customer_id={customer})", outcome)

    print("\ntampered token (edited to grant itself more) -- caught before the body runs:")
    forged = planner.to_dict()
    forged["chain"].append({"type": "caveat", "kind": "resource", "allowed_patterns": ["*"]})
    show("forged token asks for order 46",
         call_tool(verifier, "get_order", forged, {"order_id": "46"}))

    print("\naudit summary:", verifier.audit_log.stats()["by_event"])


if __name__ == "__main__":
    main()
