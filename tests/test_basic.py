"""Core library: chain integrity, caveat semantics, ledger counters, audit trail.

Fully offline. These are the invariants everything else depends on.
"""

from __future__ import annotations

import pytest

from agentauth import (
    ActionCaveat,
    AggregationBudgetCaveat,
    Capability,
    ClaimCaveat,
    DEFAULT_KEY_ID,
    Issuer,
    MaxUsesCaveat,
    ResourceCaveat,
    TimeWindowCaveat,
    Verifier,
)


def test_minted_token_verifies(verifier, planner_token, in_window):
    ok, reason = verifier.verify(
        planner_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    assert ok is True
    assert reason == "all caveats satisfied"


def test_token_from_another_root_key_is_rejected(issuer, ledger, audit_log, planner_token, in_window):
    other = Issuer()
    other.register_principal("alice")  # different random root key, same principal id
    rogue = Verifier(other, ledger, audit_log)
    ok, reason = rogue.verify(
        planner_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    assert ok is False
    assert "signature mismatch" in reason


def test_editing_a_caveat_is_detected(verifier, planner_token, in_window):
    planner_token.chain = [
        {**entry, "allowed_actions": ["read", "write", "delete"]}
        if entry.get("kind") == "action"
        else entry
        for entry in planner_token.chain
    ]
    decision = verifier.verify_detailed(
        planner_token, {"action": "delete", "resource": "orders/42", "_now": in_window}
    )
    assert decision.allowed is False
    assert decision.layer == "cryptographic"


def test_removing_a_caveat_is_detected(verifier, planner_token, in_window):
    planner_token.chain = [e for e in planner_token.chain if e.get("kind") != "max_uses"]
    ok, reason = verifier.verify(
        planner_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    assert ok is False
    assert "signature mismatch" in reason


def test_reordering_the_chain_is_detected(verifier, planner_token, in_window):
    delegation = planner_token.chain[0]
    rest = planner_token.chain[1:]
    planner_token.chain = [delegation, rest[1], rest[0], *rest[2:]]
    ok, _ = verifier.verify(
        planner_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    assert ok is False


def test_delegation_needs_no_root_key_and_still_verifies(verifier, planner_token, sub_token, in_window):
    ok, _ = verifier.verify(sub_token, {"action": "read", "resource": "orders/42", "_now": in_window})
    assert ok is True
    assert sub_token.signature != planner_token.signature


def test_holder_depth_and_path(planner_token, sub_token):
    assert planner_token.holder() == "planner_agent"
    assert planner_token.depth() == 1
    assert sub_token.holder() == "sub_agent"
    assert sub_token.depth() == 2
    assert sub_token.holders() == ["alice", "planner_agent", "sub_agent"]
    assert sub_token.root_principal == "alice"


def test_serialize_round_trip_preserves_chain_and_key_id(planner_token):
    restored = Capability.deserialize(planner_token.serialize())
    assert restored.signature == planner_token.signature
    assert restored.chain == planner_token.chain
    assert restored.key_id == planner_token.key_id


def test_compact_wire_form_round_trips(planner_token):
    compact = planner_token.to_compact()
    assert compact.startswith("agentauth1_")
    restored = Capability.parse(compact)
    assert restored.signature == planner_token.signature
    # and the JSON form still parses through the same entry point
    assert Capability.parse(planner_token.serialize()).signature == planner_token.signature


def test_tokens_from_1_0_0_without_key_id_still_verify(issuer, verifier, planner_token, ledger, audit_log, in_window):
    legacy = planner_token.to_dict()
    del legacy["key_id"]
    parsed = Capability.from_dict(legacy)
    assert parsed.key_id == DEFAULT_KEY_ID
    ok, _ = verifier.verify(parsed, {"action": "read", "resource": "orders/42", "_now": in_window})


def test_malformed_token_raises():
    with pytest.raises(Exception):
        Capability.parse("{not json")


def test_action_caveat_denies_other_verbs(verifier, sub_token, in_window):
    decision = verifier.verify_detailed(
        sub_token, {"action": "write", "resource": "orders/42", "_now": in_window}
    )
    assert decision.allowed is False
    assert decision.layer == "caveat"
    assert "not in allowed set" in decision.reason


def test_resource_caveat_glob_semantics(verifier, sub_token, in_window):
    assert verifier.verify(
        sub_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )[0]
    denied, reason = verifier.verify(
        sub_token, {"action": "read", "resource": "orders/43", "_now": in_window}
    )
    assert denied is False
    assert "does not match any of" in reason


def test_time_window_caveat(verifier, planner_token, in_window):
    assert verifier.verify(
        planner_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )[0]
    ok, reason = verifier.verify(
        planner_token, {"action": "read", "resource": "orders/42", "_now": in_window + 10_000}
    )
    assert ok is False
    assert "outside time window" in reason


def test_max_uses_counts_only_authorized_calls(verifier, issuer, in_window):
    token = issuer.mint(
        "alice",
        "planner_agent",
        [ActionCaveat(("read",)), ResourceCaveat(("orders/*",)), MaxUsesCaveat(2)],
        ts=in_window,
    )
    context = {"action": "read", "resource": "orders/42", "_now": in_window}
    assert verifier.verify(token, context)[0]
    assert verifier.verify(token, context)[0]
    ok, reason = verifier.verify(token, context)
    assert ok is False
    assert "max_uses exceeded (2/2)" in reason

    # a denial must not consume budget
    assert verifier.ledger.get_use_count(token.token_id) == 2


def test_aggregation_budget_caps_distinct_units(verifier, issuer, in_window):
    token = issuer.mint(
        "alice",
        "planner_agent",
        [
            ActionCaveat(("read",)),
            ResourceCaveat(("customers/*",)),
            AggregationBudgetCaveat("customers_touched", 2, "customer_id"),
        ],
        ts=in_window,
    )

    def read(customer_id):
        return verifier.verify_detailed(
            token,
            {
                "action": "read",
                "resource": f"customers/{customer_id}/orders",
                "customer_id": customer_id,
                "workflow_id": "wf-1",
                "_now": in_window,
            },
        )

    assert read("C-42").allowed is True
    assert read("C-42").allowed is True  # re-reading the same unit is free
    assert read("C-43").allowed is True  # 2 distinct units: at the cap
    blocked = read("C-44")  # 3rd distinct unit: inference by accumulation stopped
    assert blocked.allowed is False
    assert "aggregation budget" in blocked.reason
    assert verifier.ledger.distinct_count("wf-1", "customers_touched") == 2


def test_budget_is_scoped_per_workflow(verifier, issuer, in_window):
    token = issuer.mint(
        "alice",
        "planner_agent",
        [
            ActionCaveat(("read",)),
            ResourceCaveat(("customers/*",)),
            AggregationBudgetCaveat("customers_touched", 1, "customer_id"),
        ],
        ts=in_window,
    )
    base = {"action": "read", "resource": "customers/C-42/orders", "customer_id": "C-42", "_now": in_window}
    assert verifier.verify(token, {**base, "workflow_id": "wf-a"})[0]
    assert verifier.verify(token, {**base, "workflow_id": "wf-b"})[0]


def test_claim_caveat_requires_matching_context(verifier, issuer, in_window):
    token = issuer.mint(
        "alice",
        "research_agent",
        [ActionCaveat(("read",)), ResourceCaveat(("orders/*",)), ClaimCaveat("on_behalf_of", ("alice",))],
        ts=in_window,
    )
    ok, reason = verifier.verify(
        token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    assert ok is False
    assert "missing from call context" in reason
    assert verifier.verify(
        token,
        {"action": "read", "resource": "orders/42", "on_behalf_of": "alice", "_now": in_window},
    )[0]
    denied, reason = verifier.verify(
        token,
        {"action": "read", "resource": "orders/42", "on_behalf_of": "bob", "_now": in_window},
    )
    assert denied is False
    assert "not in" in reason


def test_explicit_revocation_beats_a_valid_signature(verifier, planner_token, in_window):
    verifier.ledger.revoke(planner_token.token_id, reason="agent compromised", revoked_by="alice")
    decision = verifier.verify_detailed(
        planner_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    assert decision.allowed is False
    assert decision.layer == "ledger"
    assert "explicitly revoked" in decision.reason


def test_unknown_principal_fails_cryptographically(issuer, ledger, audit_log, in_window):
    stranger = Issuer()
    stranger.register_principal("mallory")
    token = stranger.mint("mallory", "planner_agent", [ActionCaveat(("read",))], ts=in_window)
    verifier = Verifier(issuer, ledger, audit_log)
    decision = verifier.verify_detailed(token, {"action": "read", "resource": "orders/42", "_now": in_window})
    assert decision.allowed is False
    assert decision.layer == "cryptographic"


def test_audit_log_records_both_outcomes_and_provenance(verifier, sub_token, in_window):
    verifier.verify(sub_token, {"action": "read", "resource": "orders/42", "_now": in_window})
    verifier.verify(sub_token, {"action": "read", "resource": "orders/99", "_now": in_window})

    trace = verifier.audit_log.trace(sub_token.token_id)
    assert len(trace) == 2
    assert trace[0].allowed is True
    assert trace[1].allowed is False
    assert trace[1].layer == "caveat"
    assert verifier.audit_log.who_authorized(sub_token.token_id) == ["alice", "planner_agent", "sub_agent"]

    stats = verifier.audit_log.stats()
    assert stats["allowed"] == 1 and stats["denied"] == 1
    assert verifier.audit_log.denials_by_reason()[0]["count"] == 1
    assert verifier.audit_log.denials_by_layer() == [{"layer": "caveat", "count": 1}]


def test_decision_reports_layer_and_latency(verifier, planner_token, in_window):
    decision = verifier.verify_detailed(
        planner_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    payload = decision.to_dict()
    assert payload["allowed"] is True
    assert payload["layer"] == "ok"
    assert payload["caveats_checked"] == 5
    assert payload["key_id"] == planner_token.key_id
    assert payload["latency_ms"] >= 0


def test_verifier_accepts_a_resource_policy_at_call_time(verifier, planner_token, in_window):
    policy = {"op": "eq", "field": "region", "value": "apac"}
    decision = verifier.verify_detailed(
        planner_token,
        {"action": "read", "resource": "orders/42", "region": "eu-west", "_now": in_window},
        policy=policy,
    )
    assert decision.allowed is False
    assert decision.layer == "policy"
    assert "policy denied" in decision.reason
