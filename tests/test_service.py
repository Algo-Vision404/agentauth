"""HTTP verification service: admin auth, mint/delegate/verify/revoke, rotation,
discharges, policy, tool invocation, audit and ledger reads. Fully offline
(FastAPI TestClient -- no live server needed)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentauth import ActionCaveat, AggregationBudgetCaveat, AuditLog, Issuer, ResourceCaveat, RevocationLedger
from agentauth.service.api import ADMIN_KEY_HEADER, create_app

ADMIN = {ADMIN_KEY_HEADER: "test-admin"}
WINDOW = {"not_before": 1_700_000_000.0, "not_after": 4_000_000_000.0}


@pytest.fixture()
def client() -> TestClient:
    issuer = Issuer()
    issuer.register_principal("alice")
    issuer.register_principal("bob")
    app = create_app(
        issuer=issuer,
        ledger=RevocationLedger(":memory:"),
        audit_log=AuditLog(":memory:"),
        admin_key="test-admin",
    )
    with TestClient(app) as test_client:
        yield test_client


def _mint(client, caveats, root="alice", to="planner_agent") -> dict:
    response = client.post(
        "/tokens/mint",
        headers=ADMIN,
        json={"root_principal": root, "to_principal": to, "caveats": caveats},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _verify(client, token, context, discharges=None) -> dict:
    body = {"token": token, "context": context}
    if discharges:
        body["discharges"] = discharges
    response = client.post("/verify", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_health_reports_state_and_auth_posture(client):
    payload = client.get("/health").json()
    assert payload["ok"] is True
    assert payload["admin_key_required_for_mutations"] is True
    assert payload["admin_key_is_dev_default"] is False
    assert "ledger" in payload and "audit" in payload


def test_mutating_endpoints_require_the_admin_key(client):
    response = client.post(
        "/tokens/mint",
        json={"root_principal": "alice", "to_principal": "planner_agent", "caveats": []},
    )
    assert response.status_code == 401
    assert "admin key" in response.json()["detail"]

    assert client.post(
        "/tokens/revoke", json={"token_id": "x"}
    ).status_code == 401
    assert client.post(
        "/principals", json={"principal_id": "mallory", "kind": "agent"}
    ).status_code == 401


def test_registration_never_returns_key_material(client, monkeypatch):
    monkeypatch.delenv("AGENTAUTH_ALLOW_KEY_EXPORT", raising=False)
    created = client.post(
        "/principals", headers=ADMIN, json={"principal_id": "planner_agent", "kind": "agent", "provision_key": True}
    )
    assert created.status_code == 201
    body = created.json()
    assert body["key_exported"] is False
    assert "root_key" not in body
    assert body["key_id"] == "planner_agent#gen1"

    legacy = client.post("/principals/carol/register", headers=ADMIN)
    assert legacy.status_code == 200
    assert "root_key" not in legacy.json()
    assert legacy.json()["deprecated"] is True


def test_mint_and_verify_round_trip(client):
    minted = _mint(
        client,
        [
            {"kind": "action", "allowed_actions": ["read"]},
            {"kind": "resource", "allowed_patterns": ["orders/*"]},
            {"kind": "time_window", **WINDOW},
        ],
    )
    assert minted["key_id"] == "alice#gen1"
    assert minted["token_id"] and minted["serialized"] and minted["compact"].startswith("agentauth1_")

    allowed = _verify(client, minted["serialized"], {"action": "read", "resource": "orders/42"})
    assert allowed["allowed"] is True
    assert allowed["layer"] == "ok"

    denied = _verify(client, minted["serialized"], {"action": "delete", "resource": "orders/42"})
    assert denied["allowed"] is False
    assert denied["layer"] == "caveat"


def test_unknown_caveat_kind_is_a_400(client):
    response = client.post(
        "/tokens/mint",
        headers=ADMIN,
        json={
            "root_principal": "alice",
            "to_principal": "planner_agent",
            "caveats": [{"kind": "grant_everything"}],
        },
    )
    assert response.status_code == 400
    assert "unknown caveat kind" in response.json()["detail"]


def test_widening_delegation_is_refused_with_a_report(client):
    parent = _mint(
        client,
        [
            {"kind": "action", "allowed_actions": ["read"]},
            {"kind": "resource", "allowed_patterns": ["orders/customer_42/*"]},
        ],
    )
    refused = client.post(
        "/tokens/delegate",
        headers=ADMIN,
        json={
            "parent_token_id": parent["token_id"],
            "from_principal": "planner_agent",
            "to_principal": "sub_agent",
            "caveats": [{"kind": "resource", "allowed_patterns": ["orders/*"]}],
        },
    )
    assert refused.status_code == 409
    detail = refused.json()["detail"]
    assert detail["narrowing"]["ok"] is False
    assert detail["narrowing"]["violations"][0]["caveat"] == "resource"

    # the refusal is auditable, not silent
    recent = client.get("/audit/recent", params={"only_denied": True}).json()
    assert any(record["event"] == "widening_rejected" for record in recent["records"])


def test_only_the_current_holder_may_delegate(client):
    parent = _mint(client, [{"kind": "action", "allowed_actions": ["read"]}])
    response = client.post(
        "/tokens/delegate",
        headers=ADMIN,
        json={
            "parent_token_id": parent["token_id"],
            "from_principal": "bob",  # not the holder
            "to_principal": "sub_agent",
            "caveats": [],
        },
    )
    assert response.status_code == 409
    assert "not the current holder" in response.json()["detail"]


def test_narrow_delegation_then_verify(client):
    parent = _mint(
        client,
        [
            {"kind": "action", "allowed_actions": ["read", "write"]},
            {"kind": "resource", "allowed_patterns": ["orders/*"]},
        ],
    )
    child = client.post(
        "/tokens/delegate",
        headers=ADMIN,
        json={
            "parent_token_id": parent["token_id"],
            "from_principal": "planner_agent",
            "to_principal": "sub_agent",
            "caveats": [
                {"kind": "action", "allowed_actions": ["read"]},
                {"kind": "resource", "allowed_patterns": ["orders/42"]},
            ],
        },
    )
    assert child.status_code == 201
    payload = child.json()
    assert payload["narrowing"]["ok"] is True
    assert payload["depth"] == 2

    assert _verify(client, payload["serialized"], {"action": "read", "resource": "orders/42"})["allowed"]
    assert not _verify(client, payload["serialized"], {"action": "write", "resource": "orders/42"})["allowed"]
    assert not _verify(client, payload["serialized"], {"action": "read", "resource": "orders/43"})["allowed"]


def test_revocation_is_checked_at_verify_time(client):
    minted = _mint(client, [{"kind": "action", "allowed_actions": ["read"]}])
    assert _verify(client, minted["serialized"], {"action": "read", "resource": "orders/42"})["allowed"]

    revoked = client.post(
        "/tokens/revoke",
        headers=ADMIN,
        json={"token_id": minted["token_id"], "reason": "agent compromised", "revoked_by": "alice"},
    )
    assert revoked.status_code == 200

    decision = _verify(client, minted["serialized"], {"action": "read", "resource": "orders/42"})
    assert decision["allowed"] is False
    assert decision["layer"] == "ledger"


def test_third_party_caveat_through_the_service(client):
    client.post(
        "/principals",
        headers=ADMIN,
        json={"principal_id": "hr-directory", "kind": "discharge_service", "provision_key": True},
    )
    minted = _mint(
        client,
        [
            {"kind": "action", "allowed_actions": ["read"]},
            {"kind": "resource", "allowed_patterns": ["customers/*"]},
            {
                "kind": "third_party",
                "location": "hr-directory",
                "predicate": "the caller acts on behalf of employee alice",
                "nonce": "svc-nonce-1",
            },
        ],
        to="research_agent",
    )

    blocked = _verify(client, minted["serialized"], {"action": "read", "resource": "customers/C-42/x"})
    assert blocked["allowed"] is False
    assert blocked["layer"] == "discharge"

    issued = client.post(
        "/discharges",
        headers=ADMIN,
        json={
            "location": "hr-directory",
            "parent_token_id": minted["token_id"],
            "claims": {"on_behalf_of": "alice"},
        },
    )
    assert issued.status_code == 201, issued.text
    discharge = issued.json()["discharge"]

    allowed = _verify(
        client,
        minted["serialized"],
        {"action": "read", "resource": "customers/C-42/x", "on_behalf_of": "alice"},
        discharges=[discharge],
    )
    assert allowed["allowed"] is True
    assert allowed["discharges_used"]

    assert not _verify(
        client,
        minted["serialized"],
        {"action": "read", "resource": "customers/C-42/x", "on_behalf_of": "bob"},
        discharges=[discharge],
    )["allowed"]


def test_key_rotation_and_compromise_endpoints(client):
    first = _mint(client, [{"kind": "action", "allowed_actions": ["read"]}])
    assert first["key_id"] == "alice#gen1"

    rotated = client.post("/keys/rotate", headers=ADMIN, json={"principal_id": "alice"})
    assert rotated.status_code == 200
    assert rotated.json()["key_id"] == "alice#gen2"

    second = _mint(client, [{"kind": "action", "allowed_actions": ["read"]}])
    assert second["key_id"] == "alice#gen2"
    # tokens from the retired generation keep working
    assert _verify(client, first["serialized"], {"action": "read", "resource": "orders/42"})["allowed"]

    compromised = client.post(
        "/keys/compromise",
        headers=ADMIN,
        json={"principal_id": "alice", "key_id": "alice#gen1", "note": "leaked"},
    )
    assert compromised.status_code == 200
    decision = _verify(client, first["serialized"], {"action": "read", "resource": "orders/42"})
    assert decision["allowed"] is False
    assert decision["layer"] == "cryptographic"
    assert _verify(client, second["serialized"], {"action": "read", "resource": "orders/42"})["allowed"]

    # key listing never leaks material
    keys = client.get("/keys").json()["keys"]
    assert all("fingerprint" in entry and "key" not in entry for entry in keys)


def test_verifier_policy_endpoint_changes_decisions(client):
    minted = _mint(client, [{"kind": "action", "allowed_actions": ["read"]}])
    assert _verify(client, minted["serialized"], {"action": "read", "resource": "orders/42"})["allowed"]

    updated = client.put(
        "/policy",
        headers=ADMIN,
        json={"ast": {"op": "eq", "field": "region", "value": "apac"}, "name": "region-lock"},
    )
    assert updated.status_code == 200
    decision = _verify(
        client, minted["serialized"], {"action": "read", "resource": "orders/42", "region": "eu-west"}
    )
    assert decision["allowed"] is False
    assert decision["layer"] == "policy"

    bad = client.put("/policy", headers=ADMIN, json={"ast": {"op": "eval", "field": "x"}})
    assert bad.status_code == 400


def test_tool_policy_override_and_tool_invocation(client):
    minted = _mint(
        client,
        [
            {"kind": "action", "allowed_actions": ["read"]},
            {"kind": "resource", "allowed_patterns": ["orders/*"]},
        ],
    )
    ok = client.post(
        "/tools/get_order", json={"token": minted["serialized"], "arguments": {"order_id": "42"}}
    ).json()
    assert ok["allowed"] is True
    assert ok["result"]["order_id"] == "42"

    no_token = client.post("/tools/get_order", json={"token": "", "arguments": {"order_id": "42"}}).json()
    assert no_token["allowed"] is False
    assert no_token["layer"] == "cryptographic"

    assert client.post("/tools/nope", json={"token": minted["serialized"]}).status_code == 404

    # tighten the search tool's page size at runtime, no redeploy
    client.put(
        "/policy/tools/search_orders",
        headers=ADMIN,
        json={"ast": {"op": "lte", "field": "limit", "value": 5}},
    )
    too_big = client.post(
        "/tools/search_orders", json={"token": minted["serialized"], "arguments": {"limit": 50}}
    ).json()
    assert too_big["allowed"] is False
    assert too_big["layer"] == "policy"

    small = client.post(
        "/tools/search_orders", json={"token": minted["serialized"], "arguments": {"limit": 5}}
    ).json()
    assert small["allowed"] is True


def test_audit_and_ledger_read_endpoints(client):
    minted = _mint(
        client,
        [
            {"kind": "action", "allowed_actions": ["read"]},
            {"kind": "max_uses", "max_uses": 5},
            {"kind": "agg_budget", "budget_name": "touched", "max_units": 1, "unit_field": "customer_id"},
        ],
    )
    _verify(
        client,
        minted["serialized"],
        {"action": "read", "resource": "orders/42", "customer_id": "C-42", "workflow_id": "wf-1"},
    )
    _verify(client, minted["serialized"], {"action": "delete", "resource": "orders/42", "workflow_id": "wf-1"})

    usage = client.get("/ledger/usage", params={"workflow_id": "wf-1"}).json()
    assert usage["use_counts"][0]["count"] == 1
    assert usage["budgets"][0]["distinct_units"] == 1
    assert usage["stats"]["total_uses"] == 1

    trace = client.get(f"/audit/trace/{minted['token_id']}").json()
    assert trace["authorisation_path"] == ["alice", "planner_agent"]
    events = [d["event"] for d in trace["decisions"]]
    assert events.count("verify") == 2
    assert "mint" in events  # issuance is audited too, not just decisions

    who = client.get(f"/audit/who_authorized/{minted['token_id']}").json()
    assert who["authorized_by"] == "alice"
    assert who["hops"] == 1

    recent = client.get("/audit/recent").json()
    verifications = [r for r in recent["records"] if r["event"] == "verify"]
    assert sum(1 for r in verifications if r["allowed"]) == 1
    assert sum(1 for r in verifications if not r["allowed"]) == 1
    assert recent["stats"]["denied"] == 1
    assert recent["denials_by_layer"][0]["layer"] == "caveat"
    assert recent["denials_by_reason"][0]["count"] == 1


def test_in_process_aggregation_budget_over_http(client):
    minted = _mint(
        client,
        [
            {"kind": "action", "allowed_actions": ["read"]},
            {"kind": "agg_budget", "budget_name": "customers", "max_units": 2, "unit_field": "customer_id"},
        ],
    )
    for customer in ("C-42", "C-43"):
        assert _verify(
            client,
            minted["serialized"],
            {"action": "read", "resource": "orders/42", "customer_id": customer, "workflow_id": "wf-x"},
        )["allowed"]
    blocked = _verify(
        client,
        minted["serialized"],
        {"action": "read", "resource": "orders/42", "customer_id": "C-44", "workflow_id": "wf-x"},
    )
    assert blocked["allowed"] is False
    assert "aggregation budget" in blocked["reason"]
