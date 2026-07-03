"""
Demonstrates agentauth enforcing authorization on real MCP tool functions
(get_order / update_order from agentauth.service.mcp_server), the exact
boundary a 2026 scan found ~2,000 live MCP servers leave completely
unauthenticated.

Drives the tool functions in-process (no MCP client/transport needed to
demonstrate the enforcement logic) -- the same functions are registered
as real @mcp.tool()s in mcp_server.py and work identically over stdio
with any MCP client.

Run:
    python examples/demo_mcp_server.py
"""

import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentauth import Issuer, Verifier, RevocationLedger, AuditLog, ActionCaveat, ResourceCaveat
from agentauth.service import mcp_server as ms


def main():
    # Build our own Issuer/Verifier and point the MCP server at it, so the
    # tokens we mint here are the ones the server actually verifies.
    issuer = Issuer()
    issuer.register_principal("alice")
    ledger = RevocationLedger()
    audit_log = AuditLog()
    ms.configure(issuer, ledger, audit_log)

    print("-- alice mints a read-only token for support_agent, scoped to order 42 --")
    token = issuer.mint("alice", "support_agent", [
        ActionCaveat(("read",)),
        ResourceCaveat(("orders/42",)),
    ])
    token_json = json.dumps(token.to_dict())

    print("\nsupport_agent calls MCP tool get_order(42):")
    print(" ", ms.get_order(token_json, "42"))

    print("\nsupport_agent calls MCP tool get_order(43)  <- out of scope:")
    print(" ", ms.get_order(token_json, "43"))

    print("\nsupport_agent calls MCP tool update_order(42, 'shipped')  <- write not authorized:")
    print(" ", ms.update_order(token_json, "42", "shipped"))

    print("\n-- alice mints a broader token for ops_agent (read+write, all orders) --")
    ops_token = issuer.mint("alice", "ops_agent", [
        ActionCaveat(("read", "write")),
        ResourceCaveat(("orders/*",)),
    ])
    ops_token_json = json.dumps(ops_token.to_dict())

    print("\nops_agent calls MCP tool update_order(42, 'shipped'):")
    print(" ", ms.update_order(ops_token_json, "42", "shipped"))
    print("confirm via get_order(42):")
    print(" ", ms.get_order(ops_token_json, "42"))

    print("\n-- tampered token: an attacker who intercepts support_agent's token JSON")
    print("   and edits it to grant itself write access --")
    forged = json.loads(token_json)
    for entry in forged["chain"]:
        if entry.get("kind") == "action":
            entry["allowed_actions"] = ["read", "write"]
    print(" ", ms.update_order(json.dumps(forged), "42", "cancelled"))


if __name__ == "__main__":
    main()
