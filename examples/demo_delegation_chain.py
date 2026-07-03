"""
Worked example: human -> planner_agent -> sub_agent, a three-hop
delegation chain -- exactly the depth Tallam 2026 says deployed protocols
currently can't cryptographically account for.

Run:
    python examples/demo_delegation_chain.py
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentauth import (
    Issuer, Verifier, ActionCaveat, ResourceCaveat, MaxUsesCaveat, AggregationBudgetCaveat,
)


def section(title):
    print(f"\n{'-'*60}\n{title}\n{'-'*60}")


def main():
    issuer = Issuer()
    issuer.register_principal("alice")  # a human
    verifier = Verifier(issuer)

    # --- Hop 1: alice mints a token for planner_agent ---------------------
    section("Hop 1: alice -> planner_agent (root token)")
    root_token = issuer.mint(
        root_principal="alice",
        to_principal="planner_agent",
        caveats=[
            ActionCaveat(("read", "write")),
            ResourceCaveat(("orders/*",)),
            MaxUsesCaveat(max_uses=100),
            AggregationBudgetCaveat(budget_name="customers_touched", max_units=5, unit_field="customer_id"),
        ],
    )
    print(f"minted token {root_token.token_id[:8]}... holder={root_token.holder()}")

    ok, reason = verifier.verify(root_token, {"action": "read", "resource": "orders/42", "customer_id": "C-42"})
    print(f"planner_agent reads orders/42:  allowed={ok}  ({reason})")

    # --- Hop 2: planner_agent delegates a NARROWER token to sub_agent -----
    section("Hop 2: planner_agent -> sub_agent (attenuated: read-only, one customer)")
    sub_token = root_token.delegate(
        from_principal="planner_agent",
        to_principal="sub_agent",
        additional_caveats=[
            ActionCaveat(("read",)),                    # narrows write out
            ResourceCaveat(("orders/customer_42/*",)),   # narrows to one customer
        ],
    )
    print(f"sub_agent holds token {sub_token.token_id[:8]}...  (same token_id, extended chain)")

    ok, reason = verifier.verify(sub_token, {"action": "read", "resource": "orders/customer_42/17"})
    print(f"sub_agent reads own scope:        allowed={ok}  ({reason})")

    ok, reason = verifier.verify(sub_token, {"action": "write", "resource": "orders/customer_42/17"})
    print(f"sub_agent attempts WRITE:         allowed={ok}  ({reason})")

    ok, reason = verifier.verify(sub_token, {"action": "read", "resource": "orders/customer_99/1"})
    print(f"sub_agent reads OTHER customer:   allowed={ok}  ({reason})")

    # --- Forgery attempt: tamper the chain without the root key ------------
    section("Forgery attempt: sub_agent edits its own chain to remove the ActionCaveat narrowing")
    import copy
    forged = copy.deepcopy(sub_token)
    forged.chain = [e for e in forged.chain if not (e.get("kind") == "action" and e.get("allowed_actions") == ["read"])]
    # signature is unchanged -> won't match the recomputed chain
    ok, reason = verifier.verify(forged, {"action": "write", "resource": "orders/customer_42/17"})
    print(f"forged token attempts WRITE:      allowed={ok}  ({reason})")

    # --- Aggregation inference guard ---------------------------------------
    section("Aggregation guard: planner_agent reading across many distinct customers")
    for i in range(1, 8):
        ok, reason = verifier.verify(
            root_token,
            {"action": "read", "resource": f"orders/{i}", "customer_id": f"C-{i}", "workflow_id": "wf-1"},
        )
        print(f"  read distinct customer C-{i}:  allowed={ok}  {'' if ok else '<- ' + reason}")

    # --- Revocation ----------------------------------------------------------
    section("Revocation: alice revokes sub_agent's token mid-workflow")
    verifier.ledger.revoke(sub_token.token_id)
    ok, reason = verifier.verify(sub_token, {"action": "read", "resource": "orders/customer_42/17"})
    print(f"sub_agent retries after revoke:   allowed={ok}  ({reason})")
    # note: revoking by token_id revokes the WHOLE delegation chain sharing that id,
    # including the root token planner_agent holds -- delegation narrows scope, not identity
    ok, reason = verifier.verify(root_token, {"action": "read", "resource": "orders/1"})
    print(f"planner_agent (same token_id):    allowed={ok}  ({reason})")

    # --- Audit trail -----------------------------------------------------------
    section("Audit trail: who authorized sub_agent's token, end to end")
    print(" -> ".join(verifier.audit_log.who_authorized(sub_token.token_id)))
    print(f"total denials logged: {len(verifier.audit_log.denials())}")


if __name__ == "__main__":
    main()
