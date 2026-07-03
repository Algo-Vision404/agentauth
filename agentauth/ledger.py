"""
RevocationLedger: the synchronous, checked-at-verify-time state that
MaxUsesCaveat and AggregationBudgetCaveat depend on.

Why this needs to be synchronous state and not a TTL: a 2026 result
(referenced in Tallam 2605.05440, attributed to Parakhin 2026) shows
TTL-based token revocation fails at agent execution speed -- a compromised
or malfunctioning agent can execute far more actions within a TTL window
than a human ever could, so wall-clock expiry alone bounds damage far too
loosely. Tracking actual use-counts and explicit revocation, checked on
every single verify() call, bounds damage by *action count* instead.

This in-memory implementation is a single-process stand-in for what would
be a real shared store (Redis, etc.) in a multi-process deployment --
correctness here depends on every verifier checking the same ledger.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Optional


class RevocationLedger:
    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS revoked_tokens (token_id TEXT PRIMARY KEY)"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS use_counts (token_id TEXT PRIMARY KEY, count INTEGER)"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS agg_seen ("
                "workflow_id TEXT, budget_name TEXT, unit_value TEXT, "
                "PRIMARY KEY(workflow_id, budget_name, unit_value))"
            )

    # ---- explicit revocation --------------------------------------------

    def revoke(self, token_id: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO revoked_tokens (token_id) VALUES (?)",
                (token_id,)
            )

    def is_revoked(self, token_id: str) -> bool:
        cursor = self._conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE token_id = ?",
            (token_id,)
        )
        return cursor.fetchone() is not None

    # ---- use-count tracking (called AFTER a successful verify) -----------

    def record_use(self, token_id: str) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO use_counts (token_id, count)
                VALUES (?, 1)
                ON CONFLICT(token_id) DO UPDATE SET count = count + 1
                """,
                (token_id,)
            )

    def get_use_count(self, token_id: str) -> int:
        cursor = self._conn.execute(
            "SELECT count FROM use_counts WHERE token_id = ?",
            (token_id,)
        )
        row = cursor.fetchone()
        return row[0] if row else 0

    # ---- aggregation budget tracking --------------------------------------

    def already_seen(self, workflow_id: str, budget_name: str, unit_value: Any) -> bool:
        """True if this exact unit_value has already been counted toward
        the budget (re-accessing the same unit is free -- the budget caps
        *distinct* units, e.g. distinct customers, not repeat access)."""
        cursor = self._conn.execute(
            "SELECT 1 FROM agg_seen WHERE workflow_id = ? AND budget_name = ? AND unit_value = ?",
            (workflow_id, budget_name, str(unit_value))
        )
        return cursor.fetchone() is not None

    def distinct_count(self, workflow_id: str, budget_name: str) -> int:
        cursor = self._conn.execute(
            "SELECT COUNT(*) FROM agg_seen WHERE workflow_id = ? AND budget_name = ?",
            (workflow_id, budget_name)
        )
        row = cursor.fetchone()
        return row[0] if row else 0

    def record_aggregation_use(self, workflow_id: str, budget_name: str, unit_value: Any) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO agg_seen (workflow_id, budget_name, unit_value) VALUES (?, ?, ?)",
                (workflow_id, budget_name, str(unit_value))
            )
