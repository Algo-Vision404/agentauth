import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentauth import Issuer, Verifier, RevocationLedger, AuditLog, ActionCaveat, ResourceCaveat
from agentauth.service.mcp_tools import ToolAuthError, get_order_impl, update_order_impl


def setup():
    issuer = Issuer()
    issuer.register_principal("alice")
    verifier = Verifier(issuer, ledger=RevocationLedger(), audit_log=AuditLog())
    return issuer, verifier


def test_authorized_read_succeeds():
    issuer, verifier = setup()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",)), ResourceCaveat(("orders/42",))])
    result = get_order_impl(verifier, json.dumps(token.to_dict()), "42")
    assert result["order_id"] == "42"


def test_unauthorized_resource_denied_before_business_logic():
    issuer, verifier = setup()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",)), ResourceCaveat(("orders/42",))])
    try:
        get_order_impl(verifier, json.dumps(token.to_dict()), "43")
        assert False, "expected ToolAuthError"
    except ToolAuthError as e:
        assert "does not match" in e.reason


def test_write_denied_for_read_only_token():
    issuer, verifier = setup()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",)), ResourceCaveat(("orders/42",))])
    try:
        update_order_impl(verifier, json.dumps(token.to_dict()), "42", "shipped")
        assert False, "expected ToolAuthError"
    except ToolAuthError as e:
        assert "action" in e.reason


def test_write_succeeds_with_correct_scope():
    issuer, verifier = setup()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read", "write")), ResourceCaveat(("orders/*",))])
    result = update_order_impl(verifier, json.dumps(token.to_dict()), "42", "shipped")
    assert result["status"] == "shipped"


def test_tampered_token_denied_at_tool_boundary():
    issuer, verifier = setup()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",)), ResourceCaveat(("orders/42",))])
    forged = token.to_dict()
    for entry in forged["chain"]:
        if entry.get("kind") == "action":
            entry["allowed_actions"] = ["read", "write"]
    try:
        update_order_impl(verifier, json.dumps(forged), "42", "cancelled")
        assert False, "expected ToolAuthError"
    except ToolAuthError as e:
        assert "signature mismatch" in e.reason


def test_nonexistent_order_returns_error_dict_not_exception():
    issuer, verifier = setup()
    token = issuer.mint("alice", "agent1", [ActionCaveat(("read",)), ResourceCaveat(("orders/*",))])
    result = get_order_impl(verifier, json.dumps(token.to_dict()), "999")
    assert "error" in result


if __name__ == "__main__":
    import subprocess
    subprocess.run(["python", "-m", "pytest", __file__, "-v"])
