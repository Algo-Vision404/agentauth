"""MCP tool enforcement: the token is checked before the tool body runs, and the
server-side policy is checked after. Fully offline."""

from __future__ import annotations

import pytest

from agentauth import ActionCaveat, AggregationBudgetCaveat, Issuer, MaxUsesCaveat, ResourceCaveat
from agentauth.service.mcp_tools import (
    ToolAuthError,
    call_tool,
    get_customer_insights_impl,
    get_order_impl,
    orders_snapshot,
    reset_orders,
    search_orders_impl,
    tool_catalogue,
    update_order_impl,
)


@pytest.fixture(autouse=True)
def clean_orders():
    reset_orders()
    yield
    reset_orders()


@pytest.fixture()
def read_token(issuer):
    return issuer.mint(
        "alice",
        "research_agent",
        [
            ActionCaveat(("read",)),
            ResourceCaveat(("orders/*", "customers/*")),
            MaxUsesCaveat(20),
            AggregationBudgetCaveat("customers_touched", 2, "customer_id"),
        ],
        ts=1_700_000_000.0,
    )


@pytest.fixture()
def write_token(issuer):
    return issuer.mint(
        "alice",
        "planner_agent",
        [ActionCaveat(("read", "write")), ResourceCaveat(("orders/*",)), MaxUsesCaveat(20)],
        ts=1_700_000_000.0,
    )


def test_authorized_read_runs_the_tool_body(verifier, read_token):
    order = get_order_impl(verifier, read_token.serialize(), "42")
    assert order["order_id"] == "42"
    assert order["customer_id"] == "C-42"


def test_no_token_is_refused_before_the_body(verifier):
    with pytest.raises(ToolAuthError) as excinfo:
        get_order_impl(verifier, "", "42")
    assert excinfo.value.layer == "cryptographic"
    assert "malformed token" in excinfo.value.reason


def test_read_token_cannot_write(verifier, read_token):
    with pytest.raises(ToolAuthError) as excinfo:
        update_order_impl(verifier, read_token.serialize(), "42", "shipped")
    assert "not in allowed set" in excinfo.value.reason
    assert next(o for o in orders_snapshot() if o["order_id"] == "42")["status"] == "pending"


def test_out_of_scope_resource_is_refused(verifier, issuer):
    scoped = issuer.mint(
        "alice",
        "sub_agent",
        [ActionCaveat(("read",)), ResourceCaveat(("orders/42",))],
        ts=1_700_000_000.0,
    )
    assert get_order_impl(verifier, scoped.serialize(), "42")["order_id"] == "42"
    with pytest.raises(ToolAuthError) as excinfo:
        get_order_impl(verifier, scoped.serialize(), "43")
    assert excinfo.value.layer == "caveat"


def test_forged_token_is_caught_before_the_body(verifier, read_token):
    forged = read_token.to_dict()
    forged["chain"].append({"type": "caveat", "kind": "action", "allowed_actions": ["read", "write", "delete"]})
    with pytest.raises(ToolAuthError) as excinfo:
        update_order_impl(verifier, forged, "42", "shipped")
    assert excinfo.value.layer == "cryptographic"
    assert next(o for o in orders_snapshot() if o["order_id"] == "42")["status"] == "pending"


def test_missing_required_argument_is_a_transport_denial(verifier, read_token):
    outcome = call_tool(verifier, "get_order", read_token.serialize(), {})
    assert outcome["allowed"] is False
    assert outcome["layer"] == "transport"
    assert "missing required argument" in outcome["reason"]


def test_policy_requires_approval_for_refunds(verifier, write_token):
    denied = call_tool(verifier, "update_order", write_token.serialize(), {"order_id": "42", "status": "refunded"})
    assert denied["allowed"] is False
    assert denied["layer"] == "policy"

    allowed = call_tool(
        verifier,
        "update_order",
        write_token.serialize(),
        {"order_id": "42", "status": "refunded", "approval_id": "APR-991"},
    )
    assert allowed["allowed"] is True
    assert allowed["result"]["status"] == "refunded"
    assert allowed["result"]["approval_id"] == "APR-991"


def test_policy_money_ceiling_is_beyond_any_token(verifier, issuer):
    big_spender = issuer.mint(
        "alice",
        "planner_agent",
        [ActionCaveat(("read", "write")), ResourceCaveat(("orders/*",))],
        ts=1_700_000_000.0,
    )
    small = call_tool(verifier, "update_order", big_spender.serialize(), {"order_id": "45", "status": "shipped"})
    assert small["allowed"] is True  # 1899 is under the ceiling

    large = call_tool(verifier, "update_order", big_spender.serialize(), {"order_id": "46", "status": "shipped"})
    assert large["allowed"] is False
    assert large["layer"] == "policy"
    assert "order.total" in large["reason"]
    assert next(o for o in orders_snapshot() if o["order_id"] == "46")["status"] == "shipped"  # untouched by the denial


def test_policy_caps_the_search_page_size(verifier, read_token):
    assert call_tool(verifier, "search_orders", read_token.serialize(), {"limit": 10})["allowed"] is True
    wide = call_tool(verifier, "search_orders", read_token.serialize(), {"limit": 500})
    assert wide["allowed"] is False
    assert wide["layer"] == "policy"
    assert "limit LTE 100" in wide["reason"]


def test_aggregation_budget_through_a_tool(verifier, read_token):
    def insights(customer_id):
        return call_tool(
            verifier,
            "get_customer_insights",
            read_token.serialize(),
            {"customer_id": customer_id},
            workflow_id="wf-mcp",
        )

    assert insights("C-42")["allowed"] is True
    assert insights("C-42")["allowed"] is True  # free re-read
    assert insights("C-43")["allowed"] is True  # 2 distinct customers: at the cap
    blocked = insights("C-44")
    assert blocked["allowed"] is False
    assert blocked["layer"] == "caveat"
    assert "aggregation budget" in blocked["reason"]


def test_legacy_impl_helpers_still_raise_tool_auth_error(verifier, read_token):
    assert get_customer_insights_impl(verifier, read_token.serialize(), "C-42")["customer_id"] == "C-42"
    results = search_orders_impl(verifier, read_token.serialize(), status="shipped", limit=5)
    assert results["count"] >= 1
    with pytest.raises(ToolAuthError):
        search_orders_impl(verifier, read_token.serialize(), status="shipped", limit=1000)


def test_outcome_reports_holder_and_caveat_count(verifier, read_token):
    outcome = call_tool(verifier, "get_order", read_token.serialize(), {"order_id": "42"})
    assert outcome["token_id"] == read_token.token_id
    assert outcome["holder"] == "research_agent"
    assert outcome["caveats_checked"] == 4
    assert outcome["resource"] == "orders/42"
    assert outcome["action"] == "read"


def test_unknown_tool_is_reported_not_crashed(verifier, read_token):
    outcome = call_tool(verifier, "delete_everything", read_token.serialize(), {})
    assert outcome["allowed"] is False
    assert outcome["layer"] == "transport"


def test_catalogue_advertises_the_auth_requirement():
    catalogue = {entry["name"]: entry for entry in tool_catalogue()}
    assert set(catalogue) == {"get_order", "update_order", "get_customer_insights", "search_orders"}
    for entry in catalogue.values():
        assert "token" in entry["inputSchema"]["required"]
        assert entry["annotations"]["x-agentauth-auth-required"] is True
    assert catalogue["update_order"]["annotations"]["x-agentauth-policy"]
    assert "5000" in catalogue["update_order"]["annotations"]["x-agentauth-policy"]


def test_a_verifier_without_alice_keys_refuses_everything(issuer, ledger, audit_log, read_token):
    from agentauth import Verifier

    stranger_issuer = Issuer()
    stranger_issuer.register_principal("mallory")
    stranger = Verifier(stranger_issuer, ledger, audit_log)
    outcome = call_tool(stranger, "get_order", read_token.serialize(), {"order_id": "42"})
    assert outcome["allowed"] is False
    assert outcome["layer"] == "cryptographic"
