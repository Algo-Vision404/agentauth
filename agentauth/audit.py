"""
AuditLog: every verify() call (allowed or denied) is recorded here with
the full delegation chain attached, directly answering the question
Tallam 2026 says is currently unanswerable in deployed systems: "which
human principal authorized which specific agent to perform which specific
action at the third or fourth hop of a delegation chain."

Changed in 1.1.0:
  * the log also records mint / delegate / revoke / key_rotate /
    widening_rejected / discharge_mint events, not just verify decisions
  * records carry the decision layer, whether the signature was valid, and
    the verification latency
  * `stats()`, `denials_by_reason()` and `recent()` were added so the log can
    answer operational questions without hand-written SQL
  * the default database path comes from AGENTAUTH_AUDIT_DB (the service uses a
    file, so history survives restarts -- previously ":memory:")
  * databases created by <= 1.0.0 are migrated in place on open
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Optional

DEFAULT_AUDIT_DB = ":memory:"


def default_audit_path() -> str:
    return os.environ.get("AGENTAUTH_AUDIT_DB", DEFAULT_AUDIT_DB)


# event names used by the audit log
VERIFY = "verify"
MINT = "mint"
DELEGATE = "delegate"
REVOKE = "revoke"
KEY_ROTATE = "key_rotate"
WIDENING_REJECTED = "widening_rejected"
DISCHARGE_MINT = "discharge_mint"
TOOL_CALL = "tool_call"


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
    event: str = VERIFY
    layer: str = "ok"
    signature_valid: bool = True
    latency_ms: float = 0.0
    id: Optional[int] = None


def _jsonable(value: Any) -> Any:
    """Context may contain sets/objects (e.g. satisfied discharge nonces)."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        if isinstance(value, (set, frozenset, tuple)):
            return sorted(str(v) for v in value)
        if isinstance(value, dict):
            return {str(k): _jsonable(v) for k, v in value.items()}
        return str(value)


class AuditLog:
    _COLUMNS = [
        ("event", "TEXT"),
        ("layer", "TEXT"),
        ("signature_valid", "INTEGER"),
        ("latency_ms", "REAL"),
    ]

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or default_audit_path()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        if self.db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_db()

    # ---- lifecycle --------------------------------------------------------

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
                    reason TEXT,
                    event TEXT DEFAULT 'verify',
                    layer TEXT DEFAULT 'ok',
                    signature_valid INTEGER DEFAULT 1,
                    latency_ms REAL DEFAULT 0
                )
                """
            )
        # migrate databases written by <= 1.0.0
        existing = {row[1] for row in self._conn.execute("PRAGMA table_info(audit_records)").fetchall()}
        for column, ddl_type in self._COLUMNS:
            if column not in existing:
                with self._conn:
                    self._conn.execute(f"ALTER TABLE audit_records ADD COLUMN {column} {ddl_type}")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- writing ----------------------------------------------------------

    def record(
        self,
        token_id: str,
        root_principal: str,
        holder: str,
        delegation_chain: list[dict],
        context: dict,
        allowed: bool,
        reason: str,
        event: str = VERIFY,
        layer: str = "ok",
        signature_valid: bool = True,
        latency_ms: float = 0.0,
    ) -> int:
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO audit_records
                (ts, token_id, root_principal, holder, delegation_chain, context,
                 allowed, reason, event, layer, signature_valid, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    token_id,
                    root_principal,
                    holder,
                    json.dumps(_jsonable(delegation_chain)),
                    json.dumps(_jsonable(context)),
                    allowed,
                    reason,
                    event,
                    layer,
                    1 if signature_valid else 0,
                    latency_ms,
                ),
            )
            return int(cursor.lastrowid or 0)

    # ---- reading ----------------------------------------------------------

    def _row_to_record(self, row) -> AuditRecord:
        return AuditRecord(
            id=row[0],
            ts=row[1],
            token_id=row[2],
            root_principal=row[3],
            holder=row[4],
            delegation_chain=json.loads(row[5] or "[]"),
            context=json.loads(row[6] or "{}"),
            allowed=bool(row[7]),
            reason=row[8] or "",
            event=row[9] or VERIFY,
            layer=row[10] or "ok",
            signature_valid=bool(row[11] if row[11] is not None else 1),
            latency_ms=float(row[12] or 0.0),
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

    def recent(self, limit: int = 50, only_denied: bool = False, event: Optional[str] = None) -> list[AuditRecord]:
        clauses, params = [], []
        if only_denied:
            clauses.append("allowed = 0")
        if event:
            clauses.append("event = ?")
            params.append(event)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        cursor = self._conn.execute(
            f"SELECT * FROM audit_records {where} ORDER BY id DESC LIMIT ?", tuple(params)
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

    def stats(self) -> dict:
        def scalar(sql: str, params: tuple = ()) -> Any:
            row = self._conn.execute(sql, params).fetchone()
            return row[0] if row else 0

        return {
            "total": scalar("SELECT COUNT(*) FROM audit_records"),
            "allowed": scalar("SELECT COUNT(*) FROM audit_records WHERE allowed = 1"),
            "denied": scalar("SELECT COUNT(*) FROM audit_records WHERE allowed = 0"),
            "tamper_detected": scalar(
                "SELECT COUNT(*) FROM audit_records WHERE signature_valid = 0"
            ),
            "by_event": {
                row[0]: row[1]
                for row in self._conn.execute(
                    "SELECT event, COUNT(*) FROM audit_records GROUP BY event ORDER BY event"
                ).fetchall()
            },
            "db_path": self.db_path,
        }

    def denials_by_reason(self, limit: int = 10) -> list[dict]:
        cursor = self._conn.execute(
            "SELECT reason, COUNT(*) FROM audit_records WHERE allowed = 0 "
            "GROUP BY reason ORDER BY COUNT(*) DESC LIMIT ?",
            (limit,)
        )
        return [{"reason": row[0], "count": row[1]} for row in cursor.fetchall()]

    def denials_by_layer(self) -> list[dict]:
        cursor = self._conn.execute(
            "SELECT layer, COUNT(*) FROM audit_records WHERE allowed = 0 "
            "GROUP BY layer ORDER BY COUNT(*) DESC"
        )
        return [{"layer": row[0], "count": row[1]} for row in cursor.fetchall()]
