"""
agentauth — a scoped, delegatable, revocable, auditable capability-token
system for AI agents.

Addresses "authorization propagation" (Tallam, arXiv 2605.05440): the gap
between human-oriented auth (OAuth/RBAC/ABAC) and the reality of AI agents
that delegate tasks to other agents, recursively, across tool calls.

Three problems this targets specifically:
  1. Transitive delegation  -> macaroon-style caveat attenuation: a token
     can only ever be narrowed by delegation, never widened, and the HMAC
     chain makes forged widening cryptographically detectable.
  2. Aggregation inference   -> AggregationBudget caveats + a shared ledger
     that tracks cumulative access across a workflow, not just single calls.
  3. Temporal validity       -> revocation is enforced by an execution-count
     /explicit-revocation ledger checked at verify time, not by trusting a
     TTL a compromised agent could outrun.

See README.md for what's implemented vs. still open.
"""

from .issuer import Issuer
from .token import Capability
from .caveats import ActionCaveat, ResourceCaveat, TimeWindowCaveat, MaxUsesCaveat, AggregationBudgetCaveat
from .ledger import RevocationLedger
from .verifier import Verifier
from .audit import AuditLog

__all__ = [
    "Issuer",
    "Capability",
    "ActionCaveat",
    "ResourceCaveat",
    "TimeWindowCaveat",
    "MaxUsesCaveat",
    "AggregationBudgetCaveat",
    "RevocationLedger",
    "Verifier",
    "AuditLog",
]

__version__ = "0.1.0"
