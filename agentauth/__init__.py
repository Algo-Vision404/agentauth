"""
agentauth -- scoped, delegatable, revocable, auditable capability tokens for
AI agents.

Macaroon-family capability tokens: the signature is an HMAC chain.

    sig_0 = HMAC(root_key, token_id)
    sig_i = HMAC(sig_{i-1}, entry_i)

Delegation appends an entry and re-derives the signature, so an agent can hand
a narrower token to a sub-agent without ever holding issuer credentials, and
nobody can forge a valid chain without the root key (that would require
inverting HMAC). That is what makes "delegation can only narrow, never widen"
enforceable rather than merely conventional.

Changes in 1.1.0 (see CHANGELOG.md / UPGRADE_NOTES.md):
  * key generations: tokens carry `key_id`, so root keys can be rotated or
    marked compromised without invalidating already-issued chains
  * third-party caveats + discharge tokens (`ThirdPartyCaveat`, `mint_discharge`)
  * declarative policy language (`Policy`) evaluated alongside caveats
  * attenuation guard (`check_narrowing`) that refuses widening at issue time
  * durable ledger/audit state (SQLite file-backed by default in the service)
  * admin-key authentication on every mutating HTTP endpoint
  * four token-enforced tools on the MCP server instead of two
"""

from .attenuation import NarrowingReport, Violation, WideningError, check_narrowing, glob_is_subset
from .audit import AuditLog, AuditRecord
from .caveats import (
    ActionCaveat,
    AggregationBudgetCaveat,
    Caveat,
    ClaimCaveat,
    MaxUsesCaveat,
    ResourceCaveat,
    ThirdPartyCaveat,
    TimeWindowCaveat,
)
from .caveats import from_dict as caveat_from_dict
from .discharge import DischargeToken, derive_discharge_key, mint_discharge, verify_discharge
from .issuer import Issuer, KeyCompromised, KeyRecord, KeyStatus, UnknownPrincipal
from .ledger import RevocationLedger
from .policy import Policy, PolicyError, policy_from
from .token import DEFAULT_KEY_ID, Capability
from .verifier import Decision, Verifier

__version__ = "1.1.0"

__all__ = [
    # core
    "Capability",
    "Issuer",
    "Verifier",
    "Decision",
    "RevocationLedger",
    "AuditLog",
    "AuditRecord",
    "DEFAULT_KEY_ID",
    # caveats
    "Caveat",
    "ActionCaveat",
    "ResourceCaveat",
    "TimeWindowCaveat",
    "MaxUsesCaveat",
    "AggregationBudgetCaveat",
    "ClaimCaveat",
    "ThirdPartyCaveat",
    "caveat_from_dict",
    # new in 1.1.0
    "Policy",
    "PolicyError",
    "policy_from",
    "UnknownPrincipal",
    "KeyCompromised",
    "DischargeToken",
    "mint_discharge",
    "verify_discharge",
    "derive_discharge_key",
    "check_narrowing",
    "glob_is_subset",
    "NarrowingReport",
    "Violation",
    "WideningError",
    "KeyRecord",
    "KeyStatus",
    "__version__",
]
