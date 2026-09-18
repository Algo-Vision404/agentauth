"""Shared fixtures: everything runs offline, in memory, with no network."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentauth import (  # noqa: E402
    ActionCaveat,
    AggregationBudgetCaveat,
    AuditLog,
    ClaimCaveat,
    Issuer,
    MaxUsesCaveat,
    ResourceCaveat,
    RevocationLedger,
    TimeWindowCaveat,
    Verifier,
)

TTL_START = 1_700_000_000.0
TTL_END = TTL_START + 3_600


@pytest.fixture()
def issuer() -> Issuer:
    iss = Issuer()
    iss.register_principal("alice")
    iss.register_principal("bob")
    return iss


@pytest.fixture()
def ledger() -> RevocationLedger:
    return RevocationLedger(":memory:")


@pytest.fixture()
def audit_log() -> AuditLog:
    return AuditLog(":memory:")


@pytest.fixture()
def verifier(issuer: Issuer, ledger: RevocationLedger, audit_log: AuditLog) -> Verifier:
    return Verifier(issuer, ledger, audit_log)


@pytest.fixture()
def planner_token(issuer: Issuer):
    """alice -> planner_agent: read+write on orders/*, 25 uses, 2-customer budget."""
    return issuer.mint(
        "alice",
        "planner_agent",
        [
            ActionCaveat(("read", "write")),
            ResourceCaveat(("orders/*", "customers/*")),
            TimeWindowCaveat(TTL_START, TTL_END),
            MaxUsesCaveat(25),
            AggregationBudgetCaveat("customers_touched", 2, "customer_id"),
        ],
        ts=TTL_START,
    )


@pytest.fixture()
def sub_token(planner_token):
    """planner_agent -> sub_agent: read-only, one customer, 5 uses."""
    return planner_token.delegate(
        "planner_agent",
        "sub_agent",
        [
            ActionCaveat(("read",)),
            ResourceCaveat(("orders/42", "orders/44", "customers/*")),
            MaxUsesCaveat(5),
        ],
        ts=TTL_START + 10,
    )


@pytest.fixture()
def in_window() -> float:
    """A timestamp inside every time window used by the fixtures."""
    return TTL_START + 60
