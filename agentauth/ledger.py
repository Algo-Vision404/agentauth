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

Backing store (changed in 1.1.0): still SQLite, but the default is now
configurable via AGENTAUTH_LEDGER_DB and the service sets it to a FILE
("agentauth-ledger.db"), so a restart no longer wipes every revocation,
use-count and aggregation budget -- the gap the previous README called out.
Correctness still depends on every verifier checking the same store; point
multiple processes at the same file (or drop in Postgres/Redis, see
UPGRADE_NOTES.md) rather than using per-process memory.
"""

from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Iterable, Optional

DEFAULT_DB_PATH = ":memory:"


def default_db_path() -> str:
    """Ledger location: AGENTAUTH_LEDGER_DB, else in-memory (library default)."""
    return os.environ.get("AGENTAUTH_LEDGER_DB", DEFAULT_DB_PATH)


class RevocationLedger:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or default_db_path()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        if self.db_path != ":memory:":
            # survive process crashes without corrupting the counters
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_db()

    # ---- lifecycle ------------------------------------------------------

    def _init_db(self):
        with self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS revoked_tokens ("
                "token_id TEXT PRIMARY KEY, reason TEXT, revoked_by TEXT, ts REAL)"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS use_counts (token_id TEXT PRIMARY KEY, count INTEGER)"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS agg_seen ("
                "workflow_id TEXT, budget_name TEXT, unit_value TEXT, "
                "PRIMARY KEY(workflow_id, budget_name, unit_value))"
            )
            # 1.1.0 columns for databases created by earlier versions
            self._add_column_if_missing("revoked_tokens", "reason", "TEXT")
            self._add_column_if_missing("revoked_tokens", "revoked_by", "TEXT")
            self._add_column_if_missing("revoked_tokens", "ts", "REAL")

    def _add_column_if_missing(self, table: str, column: str, ddl_type: str) -> None:
        existing = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            with self._conn:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "RevocationLedger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- explicit revocation --------------------------------------------

    def revoke(self, token_id: str, reason: str = "", revoked_by: str = "operator") -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO revoked_tokens (token_id, reason, revoked_by, ts) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(token_id) DO UPDATE SET reason=excluded.reason, revoked_by=excluded.revoked_by",
                (token_id, reason, revoked_by, time.time()),
            )

    def is_revoked(self, token_id: str) -> bool:
        cursor = self._conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE token_id = ?",
            (token_id,)
        )
        return cursor.fetchone() is not None

    def revocations(self, limit: int = 100) -> list[dict]:
        cursor = self._conn.execute(
            "SELECT token_id, reason, revoked_by, ts FROM revoked_tokens ORDER BY ts DESC LIMIT ?",
            (limit,)
        )
        return [
            {"token_id": row[0], "reason": row[1] or "", "revoked_by": row[2] or "", "ts": row[3]}
            for row in cursor.fetchall()
        ]

    # ---- use-count tracking (called AFTER a successful verify) -----------

    def record_use(self, token_id: str) -> int:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO use_counts (token_id, count)
                VALUES (?, 1)
                ON CONFLICT(token_id) DO UPDATE SET count = count + 1
                """,
                (token_id,)
            )
        return self.get_use_count(token_id)

    def get_use_count(self, token_id: str) -> int:
        cursor = self._conn.execute(
            "SELECT count FROM use_counts WHERE token_id = ?",
            (token_id,)
        )
        row = cursor.fetchone()
        return row[0] if row else 0

    def use_counts(self, limit: int = 100) -> list[dict]:
        cursor = self._conn.execute(
            "SELECT token_id, count FROM use_counts ORDER BY count DESC LIMIT ?",
            (limit,)
        )
        return [{"token_id": row[0], "count": row[1]} for row in cursor.fetchall()]

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
        with self._conn.execute("SELECT 1") and self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO agg_seen (workflow_id, budget_name, unit_value) VALUES (?, ?, ?)",
                (workflow_id, budget_name, str(unit_value))
            )

    def budget_usage(self, workflow_id: Optional[str] = None) -> list[dict]:
        """Distinct-unit counts per (workflow, budget) -- what audit reviewers need."""
        if workflow_id is None:
            cursor = self._conn.execute(
                "SELECT workflow_id, budget_name, COUNT(*) FROM agg_seen "
                "GROUP BY workflow_id, budget_name ORDER BY workflow_id, budget_name"
            )
        else:
            cursor = self._conn.execute(
                "SELECT workflow_id, budget_name, COUNT(*) FROM agg_seen WHERE workflow_id = ? "
                "GROUP BY workflow_id, budget_name ORDER BY budget_name",
                (workflow_id,)
            )
        return [
            {"workflow_id": row[0], "budget_name": row[1], "distinct_units": row[2]}
            for row in cursor.fetchall()
        ]

    def consumed_units(self, workflow_id: str, budget_name: str) -> list[str]:
        cursor = self._conn.execute(
            "SELECT unit_value FROM agg_seen WHERE workflow_id = ? AND budget_name = ? ORDER BY unit_value",
            (workflow_id, budget_name)
        )
        return [row[0] for row in cursor.fetchall()]

    def stats(self) -> dict:
        return {
            "revoked_tokens": self._conn.execute("SELECT COUNT(*) FROM revoked_tokens").fetchone()[0],
            "tokens_with_use_counts": self._conn.execute("SELECT COUNT(*) FROM use_counts").fetchone()[0],
            "total_uses": self._conn.execute("SELECT COALESCE(SUM(count), 0) FROM use_counts").fetchone()[0],
            "aggregation_units_tracked": self._conn.execute("SELECT COUNT(*) FROM agg_seen").fetchone()[0],
            "db_path": self.db_path,
        }
