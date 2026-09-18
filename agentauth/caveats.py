"""
Caveats: structured, independently-checkable restrictions attached to a
Capability token. Delegation can only ADD caveats (narrow), never remove
them -- that invariant is what makes attenuation safe, and it's enforced
by the HMAC chain in token.py, not by these classes themselves.

Each caveat serializes to a small dict (so it can be hashed into the HMAC
chain deterministically) and implements check(context, ledger, token_id) ->
(bool, str).

Kinds:
  action            which verbs are allowed
  resource          which resource globs are reachable
  time_window       wall-clock validity
  max_uses          execution-count cap (ledger-backed, not wall-clock)
  agg_budget        anti-inference cap on DISTINCT units per workflow
  claim             NEW in 1.1.0: context must carry a claim value from a set
  third_party       NEW in 1.1.0: only a discharge from another service passes
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
        kind = d.get("kind")
        cls = _REGISTRY.get(kind)
        if cls is None:
            raise ValueError(f"unknown caveat kind: {kind!r}")
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

    Patterns inside one caveat are OR-ed; separate caveats are AND-ed.
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


@dataclass
class ClaimCaveat(Caveat):
    """
    NEW in 1.1.0. Requires the *call context* to carry an expected claim value,
    e.g. claim_field="on_behalf_of", allowed_values=("alice",). This is how a
    token can say "only when acting for alice", which is the piece classical
    scopes have no way to express. Also used to constrain discharges.
    """
    claim_field: str
    allowed_values: tuple[str, ...]
    kind: str = field(default="claim", init=False)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "claim_field": self.claim_field, "allowed_values": list(self.allowed_values)}

    def check(self, context, ledger, token_id):
        actual = context.get(self.claim_field)
        if actual is None:
            return False, f"claim '{self.claim_field}' missing from call context"
        if str(actual) in {str(v) for v in self.allowed_values}:
            return True, ""
        return False, (
            f"claim '{self.claim_field}' = {actual!r} not in {tuple(str(v) for v in self.allowed_values)}"
        )

    @staticmethod
    def _from_dict(d):
        return ClaimCaveat(d["claim_field"], tuple(d["allowed_values"]))


@dataclass
class ThirdPartyCaveat(Caveat):
    """
    NEW in 1.1.0 -- macaroons' actual killer feature, previously listed as a
    gap. The caveat names an external `location` (a discharge service) plus a
    predicate only that service can attest. It cannot be satisfied locally: the
    verifier accepts a discharge token minted by that service for THIS token
    (see agentauth.discharge), whose key is

        HMAC(service_root_key, f"{parent_token_id}:{nonce}")

    so a discharge is bound to one token and one caveat instance and cannot be
    replayed onto a different token or caveat.
    """
    location: str
    predicate: str
    nonce: str
    kind: str = field(default="third_party", init=False)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "location": self.location, "predicate": self.predicate, "nonce": self.nonce}

    def check(self, context, ledger, token_id):
        satisfied = context.get("_discharged_nonces") or set()
        if self.nonce in satisfied:
            return True, ""
        return False, (
            f"third-party caveat requires a discharge from '{self.location}' "
            f"(predicate: {self.predicate})"
        )

    @staticmethod
    def _from_dict(d):
        return ThirdPartyCaveat(d["location"], d.get("predicate", ""), d["nonce"])


_REGISTRY = {
    "action": ActionCaveat,
    "resource": ResourceCaveat,
    "time_window": TimeWindowCaveat,
    "max_uses": MaxUsesCaveat,
    "agg_budget": AggregationBudgetCaveat,
    "claim": ClaimCaveat,
    "third_party": ThirdPartyCaveat,
}


def from_dict(d: dict) -> Caveat:
    """Module-level alias for Caveat.from_dict (nicer import ergonomics)."""
    return Caveat.from_dict(d)


def kinds() -> list[str]:
    return sorted(_REGISTRY)
