"""3-hop in-process delegation: narrowing, the attenuation guard, forgery
detection, revocation and the aggregation-inference ceiling.

    python examples/demo_delegation_chain.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentauth import (
    ActionCaveat,
    AggregationBudgetCaveat,
    AuditLog,
    Issuer,
    MaxUsesCaveat,
    ResourceCaveat,
    RevocationLedger,
    Verifier,
    check_narrowing,
)
from agentauth.audit import WIDENING_REJECTED

NOW = 1_700_000_000.0


def line(label: str, ok: bool, detail: str = "") -> None:
    mark = "ALLOW" if ok else "DENY "
    print(f"  [{mark}] {label}{f' -- {detail}' if detail else ''}")


def main() -> None:
    issuer = Issuer()
    issuer.register_principal("alice")  # the only principal that can seed a chain
    ledger = RevocationLedger(":memory:")
    audit = AuditLog(":memory:")
    verifier = Verifier(issuer, ledger, audit)

    print("1. alice authorizes planner_agent (read+write, 25 uses, 2-customer budget)")
    root = issuer.mint(
        "alice",
        "planner_agent",
        [
            ActionCaveat(("read", "write")),
            ResourceCaveat(("orders/*", "customers/*")),
            MaxUsesCaveat(25),
            AggregationBudgetCaveat("customers_touched", 2, "customer_id"),
        ],
        ts=NOW,
    )
    line("planner_agent reads orders/42", *verifier.verify(root, {"action": "read", "resource": "orders/42", "_now": NOW}))  # type: ignore[arg-type]

    print("\n2. the attenuation guard refuses a widening delegation")
    report = check_narrowing(root.caveats(), [ResourceCaveat(("orders/*",)), ActionCaveat(("read", "write", "delete"))])
    for violation in report.violations:
        print(f"       violation [{violation.caveat}] {violation.detail}")
    audit.record(
        token_id=root.token_id, root_principal="alice", holder="planner_agent",
        delegation_chain=root.delegation_chain(), context={"violations": [v.to_dict() for v in report.violations]},
        allowed=False, reason="delegation refused: would widen permissions", event=WIDENING_REJECTED, layer="caveat",
    )
    print(f"       recorded as auditable event '{WIDENING_REJECTED}'")

    print("\n3. planner_agent delegates a narrower token -- no root key involved")
    sub = root.delegate(
        "planner_agent",
        "sub_agent",
        [ActionCaveat(("read",)), ResourceCaveat(("orders/42", "customers/*")), MaxUsesCaveat(6)],
        ts=NOW + 10,
    )
    line("sub_agent reads orders/42", *verifier.verify(sub, {"action": "read", "resource": "orders/42", "_now": NOW}))  # type: ignore[arg-type]
    line("sub_agent writes orders/42", *verifier.verify(sub, {"action": "write", "resource": "orders/42", "_now": NOW}))  # type: ignore[arg-type]
    line("sub_agent reads orders/43", *verifier.verify(sub, {"action": "read", "resource": "orders/43", "_now": NOW}))  # type: ignore[arg-type]

    print("\n4. aggregation inference is bounded by distinct-unit budget")
    for customer in ("C-42", "C-42", "C-43", "C-44"):
        ctx = {"action": "read", "resource": f"customers/{customer}/orders", "customer_id": customer,
               "workflow_id": "wf-1", "_now": NOW}
        ok, reason = verifier.verify(sub, ctx)
        line(f"read customer {customer}", ok, "" if ok else reason)

    print("\n5. a token edited after the fact fails signature recomputation")
    forged = root.to_dict()
    forged["chain"] = [e for e in forged["chain"] if e.get("kind") != "max_uses"]
    forged["chain"].append({"type": "caveat", "kind": "action", "allowed_actions": ["read", "write", "delete"]})
    from agentauth import Capability

    line("forged token asks to delete orders/42",
         *verifier.verify(Capability.from_dict(forged), {"action": "delete", "resource": "orders/42", "_now": NOW}))  # type: ignore[arg-type]

    print("\n6. revocation is checked at verify time, not by wall clock")
    ledger.revoke(root.token_id, reason="agent behaviour looked compromised", revoked_by="alice")
    line("revoked token replays a read", *verifier.verify(root, {"action": "read", "resource": "orders/42", "_now": NOW}))  # type: ignore[arg-type]

    print("\n7. provenance: who authorized whom, hop by hop")
    for token, label in ((root, "root token"), (sub, "delegated token")):
        path = audit.who_authorized(token.token_id)
        print(f"  {label}: {' -> '.join(path) if path else '(no decisions recorded)'}")

    print("\naudit stats:", audit.stats()["by_event"])


if __name__ == "__main__":
    main()
