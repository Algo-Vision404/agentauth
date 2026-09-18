"""Third-party caveats: a token that nobody can satisfy locally, discharged by an
external service (here: an HR directory attesting who the agent is acting for).

    python examples/demo_third_party.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentauth import (
    ActionCaveat,
    AuditLog,
    Issuer,
    MaxUsesCaveat,
    ResourceCaveat,
    RevocationLedger,
    ThirdPartyCaveat,
    Verifier,
    mint_discharge,
)
from agentauth.discharge import discharge_summary

NOW = 1_700_000_000.0


def line(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'ALLOW' if ok else 'DENY '}] {label}{f' -- {detail}' if detail else ''}")


def main() -> None:
    issuer = Issuer()
    issuer.register_principal("alice")
    issuer.register_principal("hr-directory", note="external discharge service")
    hr_key = issuer.root_key_for("hr-directory")

    verifier = Verifier(issuer, RevocationLedger(":memory:"), AuditLog(":memory:"))

    token = issuer.mint(
        "alice",
        "research_agent",
        [
            ActionCaveat(("read",)),
            ResourceCaveat(("customers/*",)),
            MaxUsesCaveat(5),
            ThirdPartyCaveat(
                location="hr-directory",
                predicate="the caller acts on behalf of employee alice",
                nonce="caveat-nonce-1",
            ),
        ],
        ts=NOW,
    )
    print("token chain (note the third-party caveat nobody can satisfy locally):")
    for entry in token.chain:
        print("   ", entry)

    context = {"action": "read", "resource": "customers/C-42/orders", "on_behalf_of": "alice", "_now": NOW}
    line("verify without a discharge", *verifier.verify(token, context))  # type: ignore[arg-type]

    print("\nhr-directory issues a discharge for this exact token + caveat instance")
    discharge = mint_discharge(
        service_root_key=hr_key,
        location="hr-directory",
        parent_token_id=token.token_id,
        nonce="caveat-nonce-1",
        predicate="the caller acts on behalf of employee alice",
        claims={"on_behalf_of": "alice"},
    )
    print("   discharge:", discharge_summary(discharge))

    decision = verifier.verify_detailed(token, context, discharges=[discharge])
    line("verify with the discharge", decision.allowed, decision.reason)

    line(
        "verify with the discharge while claiming to act for bob",
        *verifier.verify(token, {**context, "on_behalf_of": "bob"}, discharges=[discharge]),  # type: ignore[arg-type]
    )

    print("\nthe discharge is bound to one token, so it cannot be replayed elsewhere")
    other = issuer.mint("alice", "research_agent", token.caveats(), ts=NOW)
    line("same discharge offered for a different token",
         *verifier.verify(other, context, discharges=[discharge]))  # type: ignore[arg-type]

    print("\nforge the discharge to claim someone else is covered:")
    discharge.chain.append({"type": "caveat", "kind": "claim", "claim_field": "on_behalf_of",
                            "allowed_values": ["mallory"]})
    line("tampered discharge", *verifier.verify(token, context, discharges=[discharge]))  # type: ignore[arg-type]


if __name__ == "__main__":
    main()
