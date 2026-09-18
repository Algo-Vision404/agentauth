"""The same flow driven over real HTTP: a uvicorn server on an ephemeral port in
a background thread, then the httpx-based AgentAuthClient talking to it.

    python examples/demo_http_service.py

Equivalent manual run:

    AGENTAUTH_ADMIN_KEY=demo-admin-key \
        uvicorn agentauth.service.api:create_app --factory --port 8811
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn

from agentauth import ActionCaveat, AggregationBudgetCaveat, AuditLog, Issuer, MaxUsesCaveat, ResourceCaveat
from agentauth.ledger import RevocationLedger
from agentauth.service.api import create_app
from agentauth.service.client import AgentAuthClient, AgentAuthError

ADMIN_KEY = "demo-admin-key"


def line(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'ALLOW' if ok else 'DENY '}] {label}{f' -- {detail}' if detail else ''}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_server(app) -> tuple[uvicorn.Server, int, threading.Thread]:
    port = free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("uvicorn did not start")
    return server, port, thread


def main() -> None:
    issuer = Issuer()
    issuer.register_principal("alice")
    app = create_app(
        issuer=issuer,
        ledger=RevocationLedger(":memory:"),
        audit_log=AuditLog(":memory:"),
        admin_key=ADMIN_KEY,
    )
    server, port, _thread = start_server(app)
    base_url = f"http://127.0.0.1:{port}"
    print(f"verification service listening on {base_url}")

    client = AgentAuthClient(base_url, admin_key=ADMIN_KEY)
    try:
        health = client.health()
        print(f"  health: version {health['version']}, admin key required for mutations: "
              f"{health['admin_key_required_for_mutations']}")

        print("\n1. mutating endpoints require the admin key")
        # (a) the SDK refuses to even send the request without a key...
        try:
            AgentAuthClient(base_url).mint("alice", "planner_agent", [ActionCaveat(("read",))])
            print("  [BUG  ] mint without an admin key should have failed")
        except AgentAuthError as exc:
            print(f"  [DENY ] client refused to send an unauthenticated mutation: {exc}")

        # (b) ...and the service rejects a wrong key server-side
        try:
            AgentAuthClient(base_url, admin_key="not-the-key").mint(
                "alice", "planner_agent", [ActionCaveat(("read",))]
            )
            print("  [BUG  ] mint with a wrong admin key should have failed")
        except AgentAuthError as exc:
            print(f"  [DENY ] wrong admin key -- HTTP {exc.status_code}: {exc.payload['detail']}")

        print("\n2. mint over HTTP (the only operation that needs a root key)")
        minted = client.mint(
            "alice",
            "planner_agent",
            [
                ActionCaveat(("read", "write")),
                ResourceCaveat(("orders/*",)),
                MaxUsesCaveat(10),
                AggregationBudgetCaveat("customers_touched", 2, "customer_id"),
            ],
            purpose="demo over HTTP",
        )
        token_id, token = minted["token_id"], minted["serialized"]
        print(f"  token {token_id[:8]}... signed with {minted['key_id']}")

        print("\n3. every decision reports the layer that decided it")
        for context in (
            {"action": "read", "resource": "orders/42", "workflow_id": "wf-demo"},
            {"action": "delete", "resource": "orders/42", "workflow_id": "wf-demo"},
        ):
            decision = client.verify_detailed(token, context)
            line(f"{context['action']} orders/42", decision["allowed"],
                 f"layer={decision['layer']} {decision['reason']}")

        print("\n4. a widening delegation is refused, with the violations attached")
        try:
            # parent is read/write on orders/*: asking for every resource and 'delete' would widen
            client.delegate(
                token_id,
                "planner_agent",
                "sub_agent",
                [ResourceCaveat(("*",)), ActionCaveat(("read", "write", "delete"))],
            )
        except AgentAuthError as exc:
            violations = exc.payload["detail"]["narrowing"]["violations"]
            print(f"  [DENY ] HTTP {exc.status_code}")
            for violation in violations:
                print(f"         {violation['caveat']}: {violation['detail']}")

        child = client.delegate(
            token_id,
            "planner_agent",
            "sub_agent",
            [ActionCaveat(("read",)), ResourceCaveat(("orders/42",))],
        )
        line("narrow delegation accepted", True,
             f"depth {child['depth']}, holder {child['holder']}, caveats {len(child['token']['chain'])}")
        line("delegated token reads orders/42",
             *client.verify(child["serialized"], {"action": "read", "resource": "orders/42"}))  # type: ignore[arg-type]

        print("\n5. enforcement through the service for a registered tool")
        outcome = client.call_tool("get_order", child["serialized"], {"order_id": "42"})
        line("tools/get_order with the delegated token", outcome["allowed"], f"layer={outcome['layer']}")
        blocked = client.call_tool("update_order", child["serialized"], {"order_id": "42", "status": "shipped"})
        line("tools/update_order with a read-only token", blocked["allowed"], f"layer={blocked['layer']}")

        print("\n6. revocation is immediate; provenance is a query")
        client.revoke(token_id, reason="demo revocation", revoked_by="alice")
        decision = client.verify_detailed(token, {"action": "read", "resource": "orders/42"})
        line("revoked token replays a read", decision["allowed"], decision["reason"])
        print("  authorisation path:", client.who_authorized(token_id)["path"])

        print("\n7. shared ledger and audit state")
        usage = client.ledger_usage()
        print(f"  uses recorded: {usage['stats']['total_uses']}, revoked: {usage['stats']['revoked_tokens']}")
        print(f"  audit events: {client.audit_recent()['stats']['by_event']}")
        print(f"  denials by layer: {client.audit_recent()['denials_by_layer']}")
    finally:
        client.close()
        server.should_exit = True


if __name__ == "__main__":
    main()
