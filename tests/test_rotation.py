"""Key generations: rotation without invalidating existing tokens, and
compromise recovery that actually recovers.
"""

from __future__ import annotations

import pytest

from agentauth import ActionCaveat, Capability, Issuer, KeyCompromised, ResourceCaveat, UnknownPrincipal, Verifier


def _token(issuer: Issuer, ts: float = 1_700_000_000.0) -> Capability:
    return issuer.mint(
        "alice",
        "planner_agent",
        [ActionCaveat(("read",)), ResourceCaveat(("orders/*",))],
        ts=ts,
    )


def test_first_key_generation_is_namespaced(issuer):
    assert issuer.active_key_id("alice") == "alice#gen1"
    assert _token(issuer).key_id == "alice#gen1"


def test_rotating_retires_the_old_generation_and_new_mints_use_the_new_one(verifier, issuer, in_window):
    old_token = _token(issuer, ts=in_window)
    record = issuer.rotate_key("alice", note="scheduled rotation")
    assert record.key_id == "alice#gen2"
    assert record.status == "active"

    new_token = _token(issuer, ts=in_window)
    assert new_token.key_id == "alice#gen2"
    assert new_token.token_id != old_token.token_id

    context = {"action": "read", "resource": "orders/42", "_now": in_window}
    # the old chain still verifies against the generation stamped into it
    assert verifier.verify(old_token, context) == (True, "all caveats satisfied")
    assert verifier.verify(new_token, context)[0] is True

    statuses = {k["key_id"]: k["status"] for k in issuer.list_keys() if k["principal_id"] == "alice"}
    assert statuses == {"alice#gen1": "retired", "alice#gen2": "active"}


def test_compromising_a_generation_rejects_every_token_seeded_from_it(verifier, issuer, in_window):
    old_token = _token(issuer, ts=in_window)
    issuer.rotate_key("alice")
    new_token = _token(issuer, ts=in_window)

    issuer.compromise_key("alice", "alice#gen1", note="key appeared in a public repo")

    decision = verifier.verify_detailed(
        old_token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    assert decision.allowed is False
    assert decision.layer == "cryptographic"
    assert "compromised" in decision.reason

    # the new generation is unaffected: compromise recovery, not global outage
    assert verifier.verify(new_token, {"action": "read", "resource": "orders/42", "_now": in_window})[0]


def test_minting_with_a_compromised_generation_is_refused(issuer):
    issuer.compromise_key("alice")  # active generation
    with pytest.raises(KeyCompromised):
        _token(issuer)


def test_rotate_then_mint_recovers_after_a_compromise(issuer):
    issuer.compromise_key("alice", "alice#gen1")
    record = issuer.rotate_key("alice", note="post-compromise recovery")
    assert record.key_id == "alice#gen2"
    token = _token(issuer)
    assert token.key_id == "alice#gen2"


def test_unknown_principal_and_generation_errors(issuer):
    with pytest.raises(UnknownPrincipal):
        issuer.root_key_for("nobody")
    with pytest.raises(UnknownPrincipal):
        issuer.root_key_for("alice", "alice#gen9")
    with pytest.raises(UnknownPrincipal):
        issuer.rotate_key("nobody")


def test_list_keys_never_exposes_key_material(issuer):
    alice_key = issuer.root_key_for("alice")
    public = issuer.list_keys()
    assert public[0]["fingerprint"] == alice_key.hex()[:12]
    assert "key" not in public[0]
    assert alice_key.hex() not in str(public)


def test_registering_a_principal_twice_is_idempotent(issuer):
    first = issuer.register_principal("carol")
    second = issuer.register_principal("carol")
    assert first == second
    assert len([k for k in issuer.list_keys() if k["principal_id"] == "carol"]) == 1


def test_verifier_rejects_a_token_that_claims_the_wrong_generation(verifier, issuer, in_window):
    token = _token(issuer, ts=in_window)
    token.key_id = "alice#gen7"  # attacker pretends another generation signed it
    decision = verifier.verify_detailed(
        token, {"action": "read", "resource": "orders/42", "_now": in_window}
    )
    assert decision.allowed is False
    assert decision.layer == "cryptographic"
    assert "gen7" in decision.reason
