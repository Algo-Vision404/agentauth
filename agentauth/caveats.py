"""
Caveats: structured, independently-checkable restrictions attached to a
Capability token. Delegation can only ADD caveats (narrow), never remove
them -- that invariant is what makes attenuation safe, and it's enforced
by the HMAC chain in token.py, not by these classes themselves.

Each caveat serializes to a small dict (so it can be hashed into the HMAC
chain deterministically) and implements check(context, ledger) -> (bool, str).
"""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass, field
from typing import Any, Optional


class Caveat:
    kind: str = "base"

    def to_dict(self) -> dict:
        raise NotImplementedError

    def check(self, context: dict, ledger: "RevocationLedger", token_id: str) -> tuple[bool, str]:
        raise NotImplementedError

    @staticmethod
    def from_dict(d: dict) -> "Caveat":
        kind = d["kind"]
        cls = _REGISTRY[kind]
        return cls._from_dict(d)


@dataclass
class ActionCaveat(Caveat):
    """Restricts which action verb(s) this token may authorize, e.g. 'read'."""
    allowed_actions: tuple[str, ...]
    kind: str = field(default="action", init=False)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "allowed_actions": list(self.allowed_actions)}

    def check(self, context, ledger, token_id):
        action = context.get("action")
        if action in self.allowed_actions:
            return True, ""
        return False, f"action '{action}' not in allowed set {self.allowed_actions}"

    @staticmethod
    def _from_dict(d):
        return ActionCaveat(tuple(d["allowed_actions"]))


@dataclass
class ResourceCaveat(Caveat):
    """
    Restricts which resource(s) this token may act on, via glob patterns
    (e.g. 'orders/*', 'customer/12345/*'). A delegated token's patterns
    must always be a subset of what it was given -- the token holder is
    trusted to narrow patterns responsibly when delegating; the *verifier*
    additionally re-checks the resource against every caveat in the chain,
    so a widened pattern later in the chain doesn't help an attacker
    without knowing the root secret to forge a passing HMAC.
    """
    allowed_patterns: tuple[str, ...]
    kind: str = field(default="resource", init=False)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "allowed_patterns": list(self.allowed_patterns)}

    def check(self, context, ledger, token_id):
        resource = context.get("resource", "")
        if any(fnmatch.fnmatch(resource, p) for p in self.allowed_patterns):
            return True, ""
        return False, f"resource '{resource}' does not match any of {self.allowed_patterns}"

    @staticmethod
    def _from_dict(d):
        return ResourceCaveat(tuple(d["allowed_patterns"]))


@dataclass
class TimeWindowCaveat(Caveat):
    """Restricts the token to a wall-clock window. Necessary but NOT
    sufficient for revocation -- see MaxUsesCaveat / RevocationLedger for
    why TTL alone fails at agent execution speed."""
    not_before: float
    not_after: float
    kind: str = field(default="time_window", init=False)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "not_before": self.not_before, "not_after": self.not_after}

    def check(self, context, ledger, token_id):
        now = context.get("_now", time.time())
        if self.not_before <= now <= self.not_after:
            return True, ""
        return False, f"outside time window [{self.not_before}, {self.not_after}] at {now}"

    @staticmethod
    def _from_dict(d):
        return TimeWindowCaveat(d["not_before"], d["not_after"])


@dataclass
class MaxUsesCaveat(Caveat):
    """
    Execution-count-based revocation, not wall-clock based. A compromised
    agent can burn through a TTL window arbitrarily fast; capping the
    number of verified uses (tracked in the RevocationLedger, which is
    checked synchronously at every verify() call) bounds the damage
    regardless of how fast the agent executes.
    """
    max_uses: int
    kind: str = field(default="max_uses", init=False)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "max_uses": self.max_uses}

    def check(self, context, ledger, token_id):
        used = ledger.get_use_count(token_id)
        if used < self.max_uses:
            return True, ""
        return False, f"max_uses exceeded ({used}/{self.max_uses})"

    @staticmethod
    def _from_dict(d):
        return MaxUsesCaveat(d["max_uses"])


@dataclass
class AggregationBudgetCaveat(Caveat):
    """
    Guards against aggregation inference: an agent legitimately allowed to
    see individual pieces of data inferring something it was never meant
    to know by collecting many of them across a workflow. Tracks a named
    budget (e.g. 'distinct_customers_viewed') in the shared ledger, scoped
    to a workflow_id from the context, and denies once the cap is hit --
    independent of any single call being individually permitted.
    """
    budget_name: str
    max_units: int
    unit_field: str  # which context field counts as one "unit" toward the budget
    kind: str = field(default="agg_budget", init=False)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "budget_name": self.budget_name,
            "max_units": self.max_units,
            "unit_field": self.unit_field,
        }

    def check(self, context, ledger, token_id):
        workflow_id = context.get("workflow_id", "default")
        unit_value = context.get(self.unit_field)
        if unit_value is None:
            return True, ""  # nothing to count this call
        if ledger.already_seen(workflow_id, self.budget_name, unit_value):
            return True, ""  # re-accessing a unit already counted is free
        count = ledger.distinct_count(workflow_id, self.budget_name)
        if count < self.max_units:
            return True, ""
        return False, (
            f"aggregation budget '{self.budget_name}' exceeded "
            f"({count}/{self.max_units} distinct '{self.unit_field}' values in workflow {workflow_id})"
        )

    @staticmethod
    def _from_dict(d):
        return AggregationBudgetCaveat(d["budget_name"], d["max_units"], d["unit_field"])


_REGISTRY = {
    "action": ActionCaveat,
    "resource": ResourceCaveat,
    "time_window": TimeWindowCaveat,
    "max_uses": MaxUsesCaveat,
    "agg_budget": AggregationBudgetCaveat,
}
