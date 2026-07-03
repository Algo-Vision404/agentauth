"""
Runs the FastAPI verification service on a background thread and drives
it through the same mint -> delegate -> verify -> revoke flow as the
in-process demo, but over real HTTP -- proving the library works as an
actual network service, not just an in-process library.

Run:
    python examples/demo_http_service.py
"""

import sys, os, threading, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uvicorn

from agentauth.service import create_app, AgentAuthClient


def run_server(app, port):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    server.run()


def main():
    app = create_app()
    port = 8811
    thread = threading.Thread(target=run_server, args=(app, port), daemon=True)
    thread.start()
    time.sleep(1.0)  # let uvicorn bind

    client = AgentAuthClient(f"http://127.0.0.1:{port}")

    print("-- registering principal 'alice' over HTTP --")
    root_key = client.register_principal("alice")
    print(f"root key issued (would normally never be transmitted like this): {root_key[:12]}...")

    from agentauth import ActionCaveat, ResourceCaveat

    print("\n-- minting a token for planner_agent over HTTP --")
    token = client.mint("alice", "planner_agent", [ActionCaveat(("read",)), ResourceCaveat(("orders/*",))])
    print(f"token_id={token.token_id[:8]}...  holder={token.holder()}")

    ok, reason = client.verify(token, {"action": "read", "resource": "orders/42"})
    print(f"verify read orders/42:  allowed={ok}  ({reason})")

    ok, reason = client.verify(token, {"action": "write", "resource": "orders/42"})
    print(f"verify write orders/42: allowed={ok}  ({reason})")

    print("\n-- delegating a narrower token to sub_agent over HTTP --")
    sub_token = client.delegate(token, "planner_agent", "sub_agent", [ResourceCaveat(("orders/customer_1/*",))])
    ok, reason = client.verify(sub_token, {"action": "read", "resource": "orders/customer_1/5"})
    print(f"sub_agent reads in scope:     allowed={ok}  ({reason})")
    ok, reason = client.verify(sub_token, {"action": "read", "resource": "orders/customer_2/5"})
    print(f"sub_agent reads out of scope: allowed={ok}  ({reason})")

    print("\n-- revoking sub_agent's token over HTTP --")
    client.revoke(sub_token.token_id)
    ok, reason = client.verify(sub_token, {"action": "read", "resource": "orders/customer_1/5"})
    print(f"sub_agent retries after revoke: allowed={ok}  ({reason})")

    print("\n-- audit trail over HTTP --")
    print(" -> ".join(client.who_authorized(sub_token.token_id)))

    client.close()


if __name__ == "__main__":
    main()
