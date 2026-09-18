"""Third-party caveats and discharge tokens (new in 1.1.0)."""

from __future__ import annotations

import pytest

from agentauth import (
    ActionCaveat,
    DischargeToken,
    ResourceCaveat,
    ThirdPartyCaveat,
    derive_discharge_key,
    mint_discharge,
    verify_discharge,
)
from agentauth.discharge import discharge_summary


@pytest.fixture()
def hr_key(issuer) -> bytes:
    """A discharge service that owns its own root key, separate from alice's."""
    issuer.register_principal("hr-directory", note="discharge service")
    return issuer.root_key_for("hr-directory")


@pytest.fixture()
def gated_token(issuer):
    return issuer.mint(
        "alice",
        "research_agent",
        [
            ActionCaveat(("read",)),
            ResourceCaveat(("customers/*",)),
            ThirdPartyCaveat("hr-directory", "the caller acts on behalf of employee alice", "nonce-1"),
        ],
        ts=1_700_000_000.0,
    )


def _context(**extra):
    return {"action": "read", "resource": "customers/C-42/orders", **extra}


def test_caveat_cannot_be_satisfied_locally(verifier, gated_token):
    decision = verifier.verify_detailed(gated_token, _context(on_behalf_of="alice"))
    assert decision.allowed is False
    assert decision.layer == "discharge"
    assert "hr-directory" in decision.reason


def test_discharge_satisfies_the_caveat(verifier, issuer, gated_token, hr_key):
    discharge = mint_discharge(
        service_root_key=hr_key,
        location="hr-directory",
        parent_token_id=gated_token.token_id,
        nonce="nonce-1",
        predicate="the caller acts on behalf of employee alice",
        claims={"on_behalf_of": "alice"},
    )
    decision = verifier.verify_detailed(
        gated_token, _context(on_behalf_of="alice"), discharges=[discharge]
    )
    assert decision.allowed is True
    assert decision.discharges_used == [discharge.discharge_id]
    assert "third-party caveats discharged" in decision.reason or decision.layer == "ok"


def test_discharge_is_bound_to_one_token(verifier, issuer, hr_key, gated_token):
    other = issuer.mint(
        "alice",
        "research_agent",
        [ActionCaveat(("read",)), ResourceCaveat(("customers/*",)),
         ThirdPartyCaveat("hr-directory", "employee alice", "nonce-1")],
        ts=1_700_000_000.0,
    )
    discharge = mint_discharge(
        service_root_key=hr_key,
        location="hr-directory",
        parent_token_id=gated_token.token_id,
        nonce="nonce-1",
        predicate="employee alice",
    )
    # same service, same nonce, different token: refused
    decision = verifier.verify_detailed(other, _context(), discharges=[discharge])
    assert decision.allowed is False
    assert decision.layer == "discharge"
    assert "different token" in decision.reason


def test_discharge_claim_must_match_the_call(verifier, hr_key, gated_token):
    discharge = mint_discharge(
        service_root_key=hr_key,
        location="hr-directory",
        parent_token_id=gated_token.token_id,
        nonce="nonce-1",
        claims={"on_behalf_of": "alice"},
    )
    allowed = verifier.verify_detailed(gated_token, _context(on_behalf_of="alice"), discharges=[discharge])
    assert allowed.allowed is True

    denied = verifier.verify_detailed(gated_token, _context(on_behalf_of="bob"), discharges=[discharge])
    assert denied.allowed is False
    assert denied.layer == "discharge"
    assert "discharge condition failed" in denied.reason


def test_forged_discharge_is_rejected(verifier, issuer, gated_token, hr_key):
    discharge = mint_discharge(
        service_root_key=hr_key,
        location="hr-directory",
        parent_token_id=gated_token.token_id,
        nonce="nonce-1",
    )
    discharge.chain.append({"type": "caveat", "kind": "claim",
                            "claim_field": "on_behalf_of", "allowed_values": ["mallory"]})
    decision = verifier.verify_detailed(gated_token, _context(on_behalf_of="alice"), discharges=[discharge])
    assert decision.allowed is False
    assert "signature invalid" in decision.reason


def test_discharge_from_an_unregistered_service_is_refused(verifier, issuer, gated_token, hr_key):
    # verifier only knows alice's keys; hr-directory's key must be provided out of band
    from agentauth import AuditLog, RevocationLedger, Verifier

    blind = Verifier(issuer_without_service(issuer), RevocationLedger(":memory:"), AuditLog(":memory:"))
    decision = blind.verify_detailed(gated_token, _context(), discharges=[])
    assert decision.allowed is False
    assert decision.layer == "discharge"


def issuer_without_service(issuer):
    """A verifier view that does not hold the discharge service's root key."""
    from agentauth import Issuer

    trimmed = Issuer()
    trimmed.register_principal("alice", root_key=issuer.root_key_for("alice", "alice#gen1"))
    return trimmed


def test_discharge_key_is_derived_per_token_and_nonce(hr_key):
    a = derive_discharge_key(hr_key, "token-1", "nonce-1")
    b = derive_discharge_key(hr_key, "token-1", "nonce-2")
    c = derive_discharge_key(hr_key, "token-2", "nonce-1")
    assert len({a, b, c}) == 3
    assert hr_key not in (a, b, c)


def test_discharge_round_trips_and_carries_no_secret(hr_key, gated_token):
    discharge = mint_discharge(
        service_root_key=hr_key,
        location="hr-directory",
        parent_token_id=gated_token.token_id,
        nonce="nonce-1",
        claims={"on_behalf_of": "alice"},
    )
    restored = DischargeToken.deserialize(discharge.serialize())
    assert restored.signature == discharge.signature
    summary = discharge_summary(restored)
    assert summary["claims"] == {"on_behalf_of": ["alice"]}
    assert "signature" not in summary


def test_verify_discharge_reports_binding_failures(hr_key, gated_token):
    discharge = mint_discharge(
        service_root_key=hr_key,
        location="hr-directory",
        parent_token_id=gated_token.token_id,
        nonce="nonce-1",
        claims={"on_behalf_of": "alice"},
    )
    ok, reason = verify_discharge(discharge, "some-other-token", hr_key)
    assert ok is False and "different token" in reason

    ok, reason = verify_discharge("not-a-discharge", gated_token.token_id, hr_key)
    assert ok is False and "malformed discharge" in reason


def test_a_discharge_cannot_itself_require_another_discharge(hr_key, gated_token):
    with pytest.raises(ValueError):
        mint_discharge(
            service_root_key=hr_key,
            location="hr-directory",
            parent_token_id=gated_token.token_id,
            nonce="nonce-1",
            caveats=[ThirdPartyCaveat("kyc-provider", "KYC verified", "n2")],
        )
