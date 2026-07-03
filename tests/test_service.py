import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from agentauth.service import create_app


def make_client():
    app = create_app()
    return TestClient(app)


def test_register_mint_verify_flow():
    c = make_client()
    r = c.post("/principals/alice/register")
    assert r.status_code == 200
    assert "root_key_hex" in r.json()

    r = c.post("/tokens/mint", json={
        "root_principal": "alice",
        "to_principal": "agent1",
        "caveats": [{"kind": "action", "allowed_actions": ["read"]}],
    })
    assert r.status_code == 200
    token = r.json()["token"]

    r = c.post("/verify", json={"token": token, "context": {"action": "read", "resource": "x"}})
    assert r.status_code == 200
    assert r.json()["allowed"] is True

    r = c.post("/verify", json={"token": token, "context": {"action": "write", "resource": "x"}})
    assert r.status_code == 200
    assert r.json()["allowed"] is False


def test_mint_unknown_principal_fails():
    c = make_client()
    r = c.post("/tokens/mint", json={"root_principal": "nobody", "to_principal": "agent1", "caveats": []})
    assert r.status_code == 400


def test_delegate_endpoint_narrows_scope():
    c = make_client()
    c.post("/principals/alice/register")
    r = c.post("/tokens/mint", json={
        "root_principal": "alice", "to_principal": "agent1",
        "caveats": [{"kind": "action", "allowed_actions": ["read", "write"]}],
    })
    token = r.json()["token"]

    r = c.post("/tokens/delegate", json={
        "token": token, "from_principal": "agent1", "to_principal": "agent2",
        "caveats": [{"kind": "action", "allowed_actions": ["read"]}],
    })
    narrowed = r.json()["token"]

    r = c.post("/verify", json={"token": narrowed, "context": {"action": "write", "resource": "x"}})
    assert r.json()["allowed"] is False


def test_revoke_endpoint_blocks_future_verifies():
    c = make_client()
    c.post("/principals/alice/register")
    r = c.post("/tokens/mint", json={"root_principal": "alice", "to_principal": "agent1", "caveats": []})
    token = r.json()["token"]
    token_id = token["token_id"]

    r = c.post("/verify", json={"token": token, "context": {"action": "read", "resource": "x"}})
    assert r.json()["allowed"] is True

    c.post("/revoke", json={"token_id": token_id})

    r = c.post("/verify", json={"token": token, "context": {"action": "read", "resource": "x"}})
    assert r.json()["allowed"] is False


def test_audit_who_authorized_endpoint():
    c = make_client()
    c.post("/principals/alice/register")
    r = c.post("/tokens/mint", json={"root_principal": "alice", "to_principal": "agent1", "caveats": []})
    token = r.json()["token"]
    r = c.post("/tokens/delegate", json={"token": token, "from_principal": "agent1", "to_principal": "agent2", "caveats": []})
    delegated = r.json()["token"]
    token_id = delegated["token_id"]

    c.post("/verify", json={"token": delegated, "context": {"action": "read", "resource": "x"}})

    r = c.get(f"/audit/who_authorized/{token_id}")
    assert r.json()["chain"] == ["alice", "agent1", "agent2"]


if __name__ == "__main__":
    import subprocess
    subprocess.run(["python", "-m", "pytest", __file__, "-v"])
