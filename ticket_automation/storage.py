from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import Decision


class IdempotencyConflict(RuntimeError):
    pass


class SQLiteDecisionStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS decisions (
                    event_id TEXT PRIMARY KEY,
                    ticket_id TEXT NOT NULL,
                    input_sha256 TEXT NOT NULL,
                    decision_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY REFERENCES decisions(event_id),
                    audit_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    event_id TEXT PRIMARY KEY REFERENCES decisions(event_id),
                    action TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit events are append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit events are append-only');
                END;
                """
            )
            connection.commit()

    def get_decision(self, event_id: str, input_hash: str) -> Decision | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT input_sha256, decision_json FROM decisions WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            return None
        if row["input_sha256"] != input_hash:
            raise IdempotencyConflict(f"event_id {event_id!r} was reused with a different payload")
        return _decision_from_json(row["decision_json"])

    def persist(
        self,
        *,
        decision: Decision,
        audit_event: dict[str, Any],
        input_hash: str,
    ) -> Decision:
        now = datetime.now(UTC).isoformat()
        decision_json = json.dumps(decision.to_dict(), ensure_ascii=False, sort_keys=True)
        audit_json = json.dumps(audit_event, ensure_ascii=False, sort_keys=True)
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO decisions VALUES (?, ?, ?, ?, ?)",
                    (decision.event_id, decision.ticket_id, input_hash, decision_json, now),
                )
                connection.execute(
                    "INSERT INTO audit_events VALUES (?, ?, ?)",
                    (decision.event_id, audit_json, now),
                )
                connection.execute(
                    "INSERT INTO outbox VALUES (?, ?, ?, 'pending', ?)",
                    (decision.event_id, decision.action, decision_json, now),
                )
                connection.commit()
                return decision
            except sqlite3.IntegrityError:
                connection.rollback()
        existing = self.get_decision(decision.event_id, input_hash)
        if existing is None:
            raise RuntimeError("Atomic decision persistence failed")
        return existing

    def audit_payload(self, event_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT audit_json FROM audit_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return json.loads(row["audit_json"]) if row else None

    def outbox_payload(self, event_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload_json FROM outbox WHERE event_id = ?", (event_id,)
            ).fetchone()
        return json.loads(row["payload_json"]) if row else None

    def counts(self) -> dict[str, int]:
        with closing(self._connect()) as connection:
            return {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("decisions", "audit_events", "outbox")
            }


def _decision_from_json(raw: str) -> Decision:
    payload = json.loads(raw)
    payload["risk_reasons"] = tuple(payload["risk_reasons"])
    payload["reason_codes"] = tuple(payload["reason_codes"])
    return Decision(**payload)
