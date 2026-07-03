"""
AuditLog: every verify() call (allowed or denied) is recorded here with
the full delegation chain attached, directly answering the question
Tallam 2026 says is currently unanswerable in deployed systems: "which
human principal authorized which specific agent to perform which specific
action at the third or fourth hop of a delegation chain."
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AuditRecord:
    ts: float
    token_id: str
    root_principal: str
    holder: str
    delegation_chain: list[dict]
    context: dict
    allowed: bool
    reason: str


class AuditLog:
    def __init__(self, db_path: str = ":memory:"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    token_id TEXT,
                    root_principal TEXT,
                    holder TEXT,
                    delegation_chain TEXT,
                    context TEXT,
                    allowed BOOLEAN,
                    reason TEXT
                )
                """
            )

    def record(self, token_id: str, root_principal: str, holder: str,
               delegation_chain: list[dict], context: dict, allowed: bool, reason: str) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO audit_records
                (ts, token_id, root_principal, holder, delegation_chain, context, allowed, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(), token_id, root_principal, holder,
                    json.dumps(delegation_chain), json.dumps(context),
                    allowed, reason
                )
            )

    def _row_to_record(self, row) -> AuditRecord:
        return AuditRecord(
            ts=row[1],
            token_id=row[2],
            root_principal=row[3],
            holder=row[4],
            delegation_chain=json.loads(row[5]),
            context=json.loads(row[6]),
            allowed=bool(row[7]),
            reason=row[8],
        )

    def trace(self, token_id: str) -> list[AuditRecord]:
        """Every recorded decision for a given token, in order -- the
        answer to 'what did this delegated token actually do'."""
        cursor = self._conn.execute(
            "SELECT * FROM audit_records WHERE token_id = ? ORDER BY id ASC",
            (token_id,)
        )
        return [self._row_to_record(row) for row in cursor.fetchall()]

    def denials(self) -> list[AuditRecord]:
        cursor = self._conn.execute(
            "SELECT * FROM audit_records WHERE allowed = 0 ORDER BY id ASC"
        )
        return [self._row_to_record(row) for row in cursor.fetchall()]

    def who_authorized(self, token_id: str) -> list[str]:
        """The chain of principals (root -> ... -> holder) for a token,
        answering 'which principal authorized which agent'. Uses the
        longest chain seen across all recorded verify() calls for this
        token_id, since later calls (after more delegation hops) see a
        longer chain than earlier ones."""
        trace = self.trace(token_id)
        if not trace:
            return []
        chain = max((r.delegation_chain for r in trace), key=len)
        return [chain[0]["from"]] + [e["to"] for e in chain]
