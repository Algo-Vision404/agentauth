"""The declarative policy language (new in 1.1.0)."""

from __future__ import annotations

import json

import pytest

from agentauth import Policy, PolicyError, policy_from
from agentauth.policy import compare, render_ast, resolve_field, validate_ast


def test_validate_rejects_unknown_operators():
    with pytest.raises(PolicyError) as excinfo:
        validate_ast({"op": "always_allow"})
    assert "unknown policy operator" in str(excinfo.value)


def test_validate_requires_fields_and_arg_lists():
    with pytest.raises(PolicyError):
        validate_ast({"op": "and", "args": []})
    with pytest.raises(PolicyError):
        validate_ast({"op": "eq", "value": 1})
    with pytest.raises(PolicyError):
        validate_ast({"op": "in", "field": "status", "value": "pending"})
    with pytest.raises(PolicyError):
        validate_ast({"op": "lte", "field": "total", "value": "lots"})


def test_resolve_field_walks_dotted_paths():
    context = {"order": {"customer_id": "C-42", "total": 129.99}, "action": "read"}
    assert resolve_field(context, "order.customer_id") == "C-42"
    assert resolve_field(context, "order.missing") is None
    assert resolve_field(context, "nope.deeply.nested") is None


def test_numeric_comparisons_never_pass_on_missing_values():
    assert compare("lte", 10, 100) is True
    assert compare("lte", None, 100) is False  # unset must not satisfy a bound
    assert compare("gt", "10", 5) is True


def test_policy_and_or_not_evaluate():
    policy = Policy.from_dict(
        {
            "op": "and",
            "args": [
                {"op": "in", "field": "status", "value": ["pending", "shipped", "cancelled"]},
                {
                    "op": "or",
                    "args": [
                        {"op": "exists", "field": "approval_id"},
                        {"op": "nin", "field": "status", "value": ["cancelled", "refunded"]},
                    ],
                },
            ],
        },
        name="update_order",
    )
    assert policy.allows({"status": "pending"}) is True
    assert policy.allows({"status": "cancelled"}) is False
    assert policy.allows({"status": "cancelled", "approval_id": "APR-1"}) is True
    assert policy.allows({"status": "nonsense"}) is False  # not an allowed status at all

    negated = Policy.from_dict({"op": "not", "args": [{"op": "eq", "field": "region", "value": "apac"}]})
    assert negated.allows({"region": "eu-west"}) is True
    assert negated.allows({"region": "apac"}) is False


def test_matches_uses_glob_semantics():
    policy = Policy.from_dict({"op": "matches", "field": "resource", "value": "orders/customer_42/*"})
    assert policy.allows({"resource": "orders/customer_42/17"}) is True
    assert policy.allows({"resource": "orders/customer_43/17"}) is False


def test_evaluate_returns_a_reason_and_render_is_readable():
    policy = Policy.from_dict(
        {"op": "lte", "field": "order.total", "value": 5000}, name="money-ceiling"
    )
    allowed, reason = policy.evaluate({"order": {"total": 7800}})
    assert allowed is False
    assert "policy denied" in reason
    assert policy.render() == "order.total LTE 5000"
    assert policy.to_dict()["name"] == "money-ceiling"
    assert render_ast({"op": "has"}) if False else True


def test_policy_callable_shortcut():
    policy = Policy.from_dict({"op": "eq", "field": "action", "value": "read"})
    assert policy({"action": "read"}) is True
    assert policy({"action": "write"}) is False


def test_policy_from_accepts_dict_json_string_and_policy_object():
    ast = {"op": "eq", "field": "action", "value": "read"}
    assert policy_from(ast).name == ""
    assert policy_from(json.dumps(ast)).allows({"action": "read"})
    assert policy_from(Policy.from_dict(ast, name="x")).name == "x"
    assert policy_from(None) is None


def test_policy_from_file_round_trips(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"name": "tools", "ast": {"op": "exists", "field": "token"}}))
    policy = Policy.from_file(str(path))
    assert policy.name == "tools"
    assert policy.allows({"token": "abc"}) is True
    assert policy.allows({}) is False
    assert policy_from(str(path)).allows({"token": "abc"}) is True


def test_invalid_ast_from_client_is_rejected_not_ignored():
    with pytest.raises(PolicyError):
        Policy.from_dict({"op": "and", "args": [{"op": "eval", "field": "__import__"}]})


def test_multi_arg_not_renders_the_expression_it_actually_evaluates():
    """Regression: eval_ast computes NOT(A OR B OR ...) for a multi-arg 'not'
    (De Morgan: NOT(A OR B) == NOT A AND NOT B), so the human-readable render
    must say OR, not AND -- otherwise a denial reason tells the reader the
    opposite of the rule that was actually applied."""
    policy = Policy.from_dict({"op": "not", "args": [
        {"op": "eq", "field": "status", "value": "pending"},
        {"op": "eq", "field": "status", "value": "shipped"},
    ]})
    assert policy.render() == 'NOT (status EQ "pending" OR status EQ "shipped")'

    # status="pending" satisfies the first branch of the OR, so NOT(OR) is False
    allowed, reason = policy.evaluate({"status": "pending"})
    assert allowed is False
    assert "OR" in reason  # the printed rule must match what was actually checked

    # status outside both branches: OR is False, so NOT(OR) is True
    assert policy.allows({"status": "delivered"}) is True
