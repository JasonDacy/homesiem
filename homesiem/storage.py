"""SQLite-backed storage for normalized events and generated alerts."""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Iterable, Optional

from .schema import Event


class Storage:
    def __init__(self, db_path: str = "homesiem.db") -> None:
        # check_same_thread=False because collectors run on multiple threads;
        # we guard writes with our own lock.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id   TEXT PRIMARY KEY,
                    timestamp  REAL NOT NULL,
                    source     TEXT,
                    host       TEXT,
                    src_ip     TEXT,
                    dest_ip    TEXT,
                    category   TEXT,
                    action     TEXT,
                    severity   TEXT,
                    message    TEXT,
                    raw        TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category);

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp  REAL NOT NULL,
                    rule       TEXT,
                    severity   TEXT,
                    mitre      TEXT,
                    message    TEXT,
                    event_id   TEXT
                );
                """
            )

    def store_event(self, event: Event) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT OR IGNORE INTO events
                   (event_id, timestamp, source, host, src_ip, dest_ip,
                    category, action, severity, message, raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.event_id, event.timestamp, event.source, event.host,
                    event.src_ip, event.dest_ip, event.category, event.action,
                    event.severity, event.message, json.dumps(event.raw),
                ),
            )

    def store_alert(self, *, rule: str, severity: str, mitre: str,
                    message: str, event_id: str, timestamp: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO alerts
                   (timestamp, rule, severity, mitre, message, event_id)
                   VALUES (?,?,?,?,?,?)""",
                (timestamp, rule, severity, mitre, message, event_id),
            )

    def recent_events(self, limit: int = 200,
                      category: Optional[str] = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM events"
        params: list[Any] = []
        if category:
            query += " WHERE category = ?"
            params.append(category)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def recent_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def severity_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) c FROM events GROUP BY severity"
            ).fetchall()
        return {r["severity"]: r["c"] for r in rows}
