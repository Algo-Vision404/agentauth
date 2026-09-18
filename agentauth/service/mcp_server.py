"""
mcp_server.py -- a real MCP server (mcp.server.fastmcp.FastMCP) exposing four
token-enforced tools, each verified BEFORE the tool body runs: the exact boundary
a 2026 scan found ~2,000 live MCP servers leave completely unauthenticated.

    python -m agentauth.service.mcp_server     # stdio transport

Any tool call now requires a valid, scoped token:

    get_order(token=token_json, order_id="42")
    # -> {"allowed": false, "layer": "caveat", "reason": "..."} if the token
    #    doesn't authorize it, otherwise the actual tool result

Changed in 1.1.0: four tools instead of two, server-side policies are attached
per tool (see mcp_tools.TOOL_REGISTRY), every tool accepts discharge tokens, and
there is a `who_authorized` tool for provenance questions. Importing this module
without `mcp` installed still works -- only create_server() raises.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

from ..audit import AuditLog
from ..issuer import Issuer
from ..ledger import RevocationLedger
from ..verifier import Verifier
from .mcp_tools import TOOL_REGISTRY, call_tool, tool_catalogue

try:  # optional dependency: the library and tests work without it
    from mcp.server.fastmcp import FastMCP  # type: ignore

    MCP_AVAILABLE = True
    _MCP_IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # pragma: no cover - exercised only when mcp is missing/incompatible
    FastMCP = None  # type: ignore
    MCP_AVAILABLE = False
    # Distinguish "not installed at all" from "installed but incompatible" (e.g. the
    # mcp 2.x rename of FastMCP -> MCPServer): the two need different fixes, and
    # telling someone to `pip install mcp` when it's already installed just wastes
    # their time debugging the wrong problem.
    _MCP_IMPORT_ERROR = str(exc)


def service_verifier() -> Verifier:
    """Verifier wired the way the HTTP service wires it (env-configurable paths)."""
    issuer = Issuer()
    ledger = RevocationLedger(os.environ.get("AGENTAUTH_LEDGER_DB", "agentauth-ledger.db"))
    audit = AuditLog(os.environ.get("AGENTAUTH_AUDIT_DB", "agentauth-audit.db"))
    return Verifier(issuer, ledger, audit)


def create_server(verifier: Optional[Verifier] = None) -> Any:
    """Build the FastMCP server. Raises RuntimeError if the mcp package is absent."""
    if not MCP_AVAILABLE:
        try:
            import importlib.metadata as _metadata

            installed_version = _metadata.version("mcp")
        except Exception:
            installed_version = None

        if installed_version is not None:
            raise RuntimeError(
                f"the 'mcp' package is installed (version {installed_version}) but could not be "
                f"imported as expected: {_MCP_IMPORT_ERROR}. agentauth targets the mcp 1.x API "
                f"(FastMCP); if this is mcp 2.x, run `pip install \"mcp>=1.2,<2\"` to install a "
                f"compatible version."
            )
        raise RuntimeError(
            "the 'mcp' package is not installed; run `pip install \"mcp>=1.2,<2\"` to serve tools over MCP"
        )

    verifier = verifier or service_verifier()
    mcp = FastMCP("agentauth-mcp")

    def _run(name: str, token: str, arguments: dict, discharges: Optional[list] = None,
             workflow_id: Optional[str] = None) -> dict:
        return call_tool(
            verifier, name, token, arguments, discharges=discharges, workflow_id=workflow_id
        )

    def _discharges(raw: Optional[str]) -> Optional[list]:
        if not raw:
            return None
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else [parsed]

    @mcp.tool()
    def get_order(token: str, order_id: str, discharges: Optional[str] = None) -> dict:
        """Read one order. Requires a token allowing 'read' on orders/{order_id}."""
        return _run("get_order", token, {"order_id": order_id}, _discharges(discharges))

    @mcp.tool()
    def update_order(
        token: str,
        order_id: str,
        status: str,
        approval_id: Optional[str] = None,
        discharges: Optional[str] = None,
    ) -> dict:
        """Update an order's status. Requires 'write' plus the tool's own policy."""
        arguments: dict[str, Any] = {"order_id": order_id, "status": status}
        if approval_id:
            arguments["approval_id"] = approval_id
        return _run("update_order", token, arguments, _discharges(discharges))

    @mcp.tool()
    def get_customer_insights(
        token: str,
        customer_id: str,
        workflow_id: Optional[str] = None,
        discharges: Optional[str] = None,
    ) -> dict:
        """Aggregate one customer's history. Counts toward the token's aggregation budget."""
        return _run(
            "get_customer_insights",
            token,
            {"customer_id": customer_id},
            _discharges(discharges),
            workflow_id=workflow_id,
        )

    @mcp.tool()
    def search_orders(
        token: str,
        status: Optional[str] = None,
        limit: int = 10,
        discharges: Optional[str] = None,
    ) -> dict:
        """Search orders. Requires 'read' on orders/* and limit between 1 and 100."""
        arguments: dict[str, Any] = {"limit": limit}
        if status:
            arguments["status"] = status
        return _run("search_orders", token, arguments, _discharges(discharges))

    @mcp.tool()
    def who_authorized(token_id: str) -> dict:
        """Provenance: which principal authorized which agent, hop by hop (from the audit log)."""
        return {
            "token_id": token_id,
            "path": verifier.audit_log.who_authorized(token_id),
            "decisions": [
                {"event": r.event, "allowed": r.allowed, "layer": r.layer, "reason": r.reason}
                for r in verifier.audit_log.trace(token_id)[-10:]
            ],
        }

    @mcp.tool()
    def list_tools_catalogue() -> list[dict]:
        """The tools this server exposes, with their required action/resource and policy."""
        return tool_catalogue()

    return mcp


def main() -> None:  # pragma: no cover - entry point
    mcp = create_server()
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()


def tool_names() -> list[str]:
    """Registered tools, importable without the mcp package."""
    return list(TOOL_REGISTRY)
