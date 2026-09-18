"""Key rotation and compromise recovery: rotate without invalidating live
tokens, then revoke a leaked generation without taking the principal down.

    python examples/demo_key_rotation.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentauth import ActionCaveat, AuditLog, Issuer, ResourceCaveat, RevocationLedger, Verifier

NOW = 1_700_000_000.0
CONTEXT = {"action": "read", "resource": "orders/42", "_now": NOW}


def line(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'ALLOW' if ok else 'DENY '}] {label}{f' -- {detail}' if detail else ''}")


def mint(issuer: Issuer):
    return issuer.mint("alice", "planner_agent", [ActionCaveat(("read",)), ResourceCaveat(("orders/*",))], ts=NOW)


def main() -> None:
    issuer = Issuer()
    issuer.register_principal("alice")
    verifier = Verifier(issuer, RevocationLedger(":memory:"), AuditLog(":memory:"))

    print("1. key generations are namespaced per principal")
    before = mint(issuer)
    print(f"   first token signed with {before.key_id}")

    print("\n2. rotating retires the old generation; live tokens keep verifying")
    record = issuer.rotate_key("alice", note="scheduled rotation")
    after = mint(issuer)
    print(f"   new generation {record.key_id}")
    line(f"token minted with {before.key_id} (retired generation)", *verifier.verify(before, CONTEXT))  # type: ignore[arg-type]
    line(f"token minted with {after.key_id} (active generation)", *verifier.verify(after, CONTEXT))  # type: ignore[arg-type]

    print("\n3. compromise recovery: mark the leaked generation, keep operating")
    issuer.compromise_key("alice", before.key_id, note="key appeared in a public repository")
    decision = verifier.verify_detailed(before, CONTEXT)
    line(f"token from compromised generation {before.key_id}", decision.allowed, decision.reason)
    line(f"token from active generation {after.key_id}", *verifier.verify(after, CONTEXT))  # type: ignore[arg-type]

    print("\n4. minting with a compromised generation is refused outright")
    issuer.compromise_key("alice")  # the newly active one
    try:
        mint(issuer)
        print("   [BUG ] minting with a compromised key should be refused")
    except Exception as exc:  # KeyCompromised
        print(f"   [REFUSED] {type(exc).__name__}: {exc}")

    print("\n5. rotate again and resume")
    recovery = issuer.rotate_key("alice", note="post-compromise recovery key")
    resumed = mint(issuer)
    line(f"token minted with {recovery.key_id}", *verifier.verify(resumed, CONTEXT))  # type: ignore[arg-type]

    print("\nkey inventory (fingerprints only -- no key material):")
    for key in issuer.list_keys():
        print("   ", key)


if __name__ == "__main__":
    main()
