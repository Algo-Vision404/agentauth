"""
A real MCP server (usable by any MCP client -- Claude Desktop, etc.) whose
tools are enforced by agentauth capability tokens. Every tool call requires
a `token` argument (a serialized Capability JSON string) which is verified
BEFORE the tool's business logic runs.

Run standalone (stdio transport, for use with an MCP client config):
    python -m agentauth.service.mcp_server

The demo (examples/demo_mcp_server.py) drives this in-process instead,
which is easier to run in a sandbox without wiring up a real MCP client.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..audit import AuditLog
from ..issuer import Issuer
from ..ledger import RevocationLedger
from ..verifier import Verifier
from .mcp_tools import ToolAuthError, get_order_impl, update_order_impl

mcp = FastMCP("agentauth-protected-orders")

# Module-level shared state for the standalone-server case. A driving
# script that wants to mint/verify against the SAME state (as the demo
# does) should call `configure()` with its own Issuer/Verifier instead of
# relying on this default -- see examples/demo_mcp_server.py.
_issuer = Issuer()
_issuer.register_principal("alice")
_ledger = RevocationLedger()
_audit_log = AuditLog()
_verifier = Verifier(_issuer, ledger=_ledger, audit_log=_audit_log)


def configure(issuer: Issuer, ledger: RevocationLedger, audit_log: AuditLog) -> None:
    """Point this MCP server at externally-created state, so a driving
    script can mint tokens with the same Issuer this server verifies
    against. Must be called before any tool invocation."""
    global _issuer, _ledger, _audit_log, _verifier
    _issuer, _ledger, _audit_log = issuer, ledger, audit_log
    _verifier = Verifier(issuer, ledger=ledger, audit_log=audit_log)


@mcp.tool()
def get_order(token: str, order_id: str) -> dict:
    """Read an order by id. Requires a capability token authorizing
    action='read' on resource='orders/{order_id}'."""
    try:
        return get_order_impl(_verifier, token, order_id)
    except ToolAuthError as e:
        return {"error": f"authorization denied: {e.reason}"}


@mcp.tool()
def update_order(token: str, order_id: str, status: str) -> dict:
    """Update an order's status. Requires a capability token authorizing
    action='write' on resource='orders/{order_id}'."""
    try:
        return update_order_impl(_verifier, token, order_id, status)
    except ToolAuthError as e:
        return {"error": f"authorization denied: {e.reason}"}


if __name__ == "__main__":
    mcp.run()
