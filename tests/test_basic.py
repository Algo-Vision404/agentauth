import copy
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentauth import (
    Issuer, Verifier, ActionCaveat, ResourceCaveat, TimeWindowCaveat,
    MaxUsesCaveat, AggregationBudgetCaveat, RevocationLedger,
)


def make_verifier():
    issuer = Issuer()
    issuer.register_principal("alice")
    return issuer, Verifier(issuer)


def test_mint_and_verify_allows_matching_call():
    issuer, verifier = make_verifier()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",)), ResourceCaveat(("orders/*",))])
    ok, _ = verifier.verify(token, {"action": "read", "resource": "orders/1"})
    assert ok


def test_verify_denies_action_outside_caveat():
    issuer, verifier = make_verifier()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",))])
    ok, reason = verifier.verify(token, {"action": "write", "resource": "orders/1"})
    assert not ok
    assert "action" in reason


def test_verify_denies_resource_outside_pattern():
    issuer, verifier = make_verifier()
    token = issuer.mint("alice", "agent1", [ResourceCaveat(("orders/*",))])
    ok, reason = verifier.verify(token, {"action": "read", "resource": "invoices/1"})
    assert not ok
    assert "resource" in reason


def test_delegation_can_only_narrow():
    issuer, verifier = make_verifier()
    root = issuer.mint("alice", "agent1", [ActionCaveat(("read", "write")), ResourceCaveat(("orders/*",))])
    narrowed = root.delegate("agent1", "agent2", [ActionCaveat(("read",))])

    ok, _ = verifier.verify(narrowed, {"action": "read", "resource": "orders/1"})
    assert ok
    ok, reason = verifier.verify(narrowed, {"action": "write", "resource": "orders/1"})
    assert not ok


def test_forged_chain_fails_signature_check():
    issuer, verifier = make_verifier()
    root = issuer.mint("alice", "agent1", [ActionCaveat(("read",))])
    narrowed = root.delegate("agent1", "agent2", [ActionCaveat(("read",))])

    forged = copy.deepcopy(narrowed)
    # attacker (holding no root key) tries to strip the extra ActionCaveat entry
    forged.chain = [e for e in forged.chain if not (e.get("kind") == "action" and len(forged.chain) > 2)][:2]
    ok, reason = verifier.verify(forged, {"action": "write", "resource": "orders/1"})
    assert not ok
    assert "signature mismatch" in reason


def test_revocation_blocks_all_future_uses():
    issuer, verifier = make_verifier()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",))])
    ok, _ = verifier.verify(token, {"action": "read", "resource": "x"})
    assert ok
    verifier.ledger.revoke(token.token_id)
    ok, reason = verifier.verify(token, {"action": "read", "resource": "x"})
    assert not ok
    assert "revoked" in reason


def test_max_uses_caveat_enforced():
    issuer, verifier = make_verifier()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",)), MaxUsesCaveat(max_uses=2)])
    ctx = {"action": "read", "resource": "x"}
    assert verifier.verify(token, ctx)[0]
    assert verifier.verify(token, ctx)[0]
    ok, reason = verifier.verify(token, ctx)
    assert not ok
    assert "max_uses" in reason


def test_time_window_caveat_enforced():
    issuer, verifier = make_verifier()
    now = time.time()
    token = issuer.mint("alice", "agent1", [TimeWindowCaveat(not_before=now - 10, not_after=now - 1)])
    ok, reason = verifier.verify(token, {"action": "read", "resource": "x"})
    assert not ok
    assert "time window" in reason


def test_aggregation_budget_blocks_after_distinct_units_exceeded():
    issuer, verifier = make_verifier()
    token = issuer.mint("alice", "agent1", [
        AggregationBudgetCaveat(budget_name="customers", max_units=3, unit_field="customer_id"),
    ])
    for i in range(3):
        ok, _ = verifier.verify(token, {"action": "read", "resource": "x", "customer_id": f"C{i}", "workflow_id": "w1"})
        assert ok
    ok, reason = verifier.verify(token, {"action": "read", "resource": "x", "customer_id": "C99", "workflow_id": "w1"})
    assert not ok
    assert "aggregation budget" in reason


def test_aggregation_budget_reaccessing_same_unit_is_free():
    issuer, verifier = make_verifier()
    token = issuer.mint("alice", "agent1", [
        AggregationBudgetCaveat(budget_name="customers", max_units=1, unit_field="customer_id"),
    ])
    ctx = {"action": "read", "resource": "x", "customer_id": "C1", "workflow_id": "w1"}
    assert verifier.verify(token, ctx)[0]
    assert verifier.verify(token, ctx)[0]  # same customer again -- should still be allowed


def test_audit_log_who_authorized_full_chain():
    issuer, verifier = make_verifier()
    root = issuer.mint("alice", "agent1", [ActionCaveat(("read",))])
    sub = root.delegate("agent1", "agent2", [])
    verifier.verify(sub, {"action": "read", "resource": "x"})
    chain = verifier.audit_log.who_authorized(sub.token_id)
    assert chain == ["alice", "agent1", "agent2"]


def test_serialization_round_trip_preserves_verification():
    issuer, verifier = make_verifier()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",))])
    restored = type(token).deserialize(token.serialize())
    ok, _ = verifier.verify(restored, {"action": "read", "resource": "x"})
    assert ok


if __name__ == "__main__":
    import subprocess
    subprocess.run(["python", "-m", "pytest", __file__, "-v"])
