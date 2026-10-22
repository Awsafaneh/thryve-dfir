from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    host TEXT,
    message TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source, event_type);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    event_id INTEGER,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    mitre TEXT,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    FOREIGN KEY(event_id) REFERENCES events(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, severity, created_at DESC);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    definition_json TEXT NOT NULL,
    mitre TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collector TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    item_count INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT 'medium',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    item_type TEXT NOT NULL,
    item_id INTEGER,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()
        self.initialize()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def seed_rules(self, rules: Iterable[dict[str, Any]]) -> None:
        now = utc_now()
        with self._write_lock, self.connect() as conn:
            for rule in rules:
                conn.execute(
                    """INSERT INTO rules(id,title,description,severity,source,definition_json,mitre,enabled,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET title=excluded.title, description=excluded.description,
                    severity=excluded.severity, source=excluded.source, definition_json=excluded.definition_json,
                    mitre=excluded.mitre""",
                    (
                        rule["id"], rule["title"], rule.get("description", ""), rule["severity"],
                        rule["source"], canonical_json(rule), rule.get("mitre"),
                        int(bool(rule.get("enabled", True))), now,
                    ),
                )
                conn.execute(
                    "UPDATE alerts SET title=?, severity=?, mitre=?, updated_at=? WHERE rule_id=?",
                    (rule["title"], rule["severity"], rule.get("mitre"), now, rule["id"]),
                )

    def enabled_rules(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT definition_json FROM rules WHERE enabled=1 ORDER BY severity, id").fetchall()
        return [json.loads(row["definition_json"]) for row in rows]

    def insert_events(self, events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        inserted: list[dict[str, Any]] = []
        now = utc_now()
        with self._write_lock, self.connect() as conn:
            for event in events:
                raw = canonical_json(event.get("data", {}))
                fingerprint = event.get("fingerprint") or hashlib.sha256(
                    f'{event.get("source")}|{event.get("event_type")}|{event.get("timestamp")}|{event.get("message")}|{raw}'.encode("utf-8")
                ).hexdigest()
                cursor = conn.execute(
                    """INSERT OR IGNORE INTO events
                    (fingerprint,timestamp,collected_at,source,event_type,severity,host,message,data_json)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        fingerprint, event.get("timestamp", now), now, event.get("source", "unknown"),
                        event.get("event_type", "generic"), event.get("severity", "info"),
                        event.get("host"), event.get("message", ""), raw,
                    ),
                )
                if cursor.rowcount:
                    event_copy = dict(event)
                    event_copy["id"] = cursor.lastrowid
                    event_copy["fingerprint"] = fingerprint
                    inserted.append(event_copy)
        return inserted

    def insert_alerts(self, alerts: Iterable[dict[str, Any]]) -> int:
        count = 0
        now = utc_now()
        with self._write_lock, self.connect() as conn:
            for alert in alerts:
                evidence = canonical_json(alert.get("evidence", {}))
                fingerprint = hashlib.sha256(
                    f'{alert.get("rule_id")}|{alert.get("event_id")}|{evidence}'.encode("utf-8")
                ).hexdigest()
                cur = conn.execute(
                    """INSERT OR IGNORE INTO alerts
                    (fingerprint,event_id,rule_id,title,severity,status,mitre,source,created_at,updated_at,evidence_json)
                    VALUES(?,?,?,?,?,'open',?,?,?,?,?)""",
                    (
                        fingerprint, alert.get("event_id"), alert["rule_id"], alert["title"],
                        alert["severity"], alert.get("mitre"), alert.get("source", "unknown"),
                        now, now, evidence,
                    ),
                )
                count += int(bool(cur.rowcount))
        return count

    @staticmethod
    def _decode(rows: Iterable[sqlite3.Row], json_column: str | None = None) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if json_column and json_column in item:
                item["data"] = json.loads(item.pop(json_column))
            output.append(item)
        return output

    def list_events(self, *, source: str | None = None, event_type: str | None = None,
                    severity: str | None = None, query: str | None = None,
                    limit: int = 200, offset: int = 0) -> dict[str, Any]:
        where, args = ["1=1"], []
        for column, value in (("source", source), ("event_type", event_type), ("severity", severity)):
            if value:
                where.append(f"{column}=?")
                args.append(value)
        if query:
            where.append("(message LIKE ? OR data_json LIKE ?)")
            args.extend([f"%{query}%", f"%{query}%"])
        clause = " AND ".join(where)
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM events WHERE {clause}", args).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM events WHERE {clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                [*args, min(max(limit, 1), 500), max(offset, 0)],
            ).fetchall()
        return {"items": self._decode(rows, "data_json"), "total": total, "limit": limit, "offset": offset}

    def list_alerts(self, *, status: str | None = None, severity: str | None = None,
                    query: str | None = None, limit: int = 200, offset: int = 0) -> dict[str, Any]:
        where, args = ["1=1"], []
        if status:
            where.append("status=?")
            args.append(status)
        if severity:
            where.append("severity=?")
            args.append(severity)
        if query:
            where.append("(title LIKE ? OR evidence_json LIKE ? OR rule_id LIKE ?)")
            args.extend([f"%{query}%"] * 3)
        clause = " AND ".join(where)
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM alerts WHERE {clause}", args).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM alerts WHERE {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                [*args, min(max(limit, 1), 500), max(offset, 0)],
            ).fetchall()
        return {"items": self._decode(rows, "evidence_json"), "total": total, "limit": limit, "offset": offset}

    def rules(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT id,title,description,severity,source,mitre,enabled,updated_at FROM rules ORDER BY id").fetchall()
        return [{**dict(row), "enabled": bool(row["enabled"])} for row in rows]

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        with self._write_lock, self.connect() as conn:
            cur = conn.execute("UPDATE rules SET enabled=?, updated_at=? WHERE id=?", (int(enabled), utc_now(), rule_id))
        return bool(cur.rowcount)

    def collection_start(self, collector: str) -> int:
        with self._write_lock, self.connect() as conn:
            cur = conn.execute("INSERT INTO collections(collector,started_at,status) VALUES(?,?,'running')", (collector, utc_now()))
            return int(cur.lastrowid)

    def collection_finish(self, collection_id: int, status: str, item_count: int, error: str | None = None) -> None:
        with self._write_lock, self.connect() as conn:
            conn.execute("UPDATE collections SET finished_at=?,status=?,item_count=?,error=? WHERE id=?",
                         (utc_now(), status, item_count, error, collection_id))

    def recent_collections(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM collections ORDER BY id DESC LIMIT 20").fetchall()
        return self._decode(rows)

    def overview(self) -> dict[str, Any]:
        with self.connect() as conn:
            counts = {
                "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "alerts_open": conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0],
                "alerts_critical": conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open' AND severity='critical'").fetchone()[0],
                "processes": conn.execute("SELECT COUNT(*) FROM events WHERE event_type='process'").fetchone()[0],
                "connections": conn.execute("SELECT COUNT(*) FROM events WHERE event_type='network'").fetchone()[0],
            }
            severity_rows = conn.execute("SELECT severity,COUNT(*) count FROM alerts WHERE status='open' GROUP BY severity").fetchall()
            volume_rows = conn.execute(
                """SELECT substr(timestamp,1,13) hour, COUNT(*) count FROM events
                WHERE timestamp >= datetime('now','-24 hours') GROUP BY hour ORDER BY hour"""
            ).fetchall()
            alerts = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 8").fetchall()
        return {
            "counts": counts,
            "alert_severity": {r["severity"]: r["count"] for r in severity_rows},
            "event_volume": [dict(r) for r in volume_rows],
            "recent_alerts": self._decode(alerts, "evidence_json"),
            "collections": self.recent_collections(),
        }

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        if status not in {"open", "investigating", "closed", "false_positive"}:
            return False
        with self._write_lock, self.connect() as conn:
            cur = conn.execute("UPDATE alerts SET status=?,updated_at=? WHERE id=?", (status, utc_now(), alert_id))
        return bool(cur.rowcount)

    def create_case(self, title: str, description: str, severity: str) -> dict[str, Any]:
        now = utc_now()
        with self._write_lock, self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO cases(title,description,severity,created_at,updated_at) VALUES(?,?,?,?,?)",
                (title[:200], description[:4000], severity, now, now),
            )
            case_id = int(cur.lastrowid)
        return self.get_case(case_id) or {}

    def add_case_item(self, case_id: int, item_type: str, item_id: int | None, note: str) -> bool:
        with self._write_lock, self.connect() as conn:
            exists = conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone()
            if not exists:
                return False
            conn.execute("INSERT INTO case_items(case_id,item_type,item_id,note,created_at) VALUES(?,?,?,?,?)",
                         (case_id, item_type[:30], item_id, note[:8000], utc_now()))
            conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (utc_now(), case_id))
        return True

    def list_cases(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT c.*,COUNT(i.id) item_count FROM cases c LEFT JOIN case_items i ON i.case_id=c.id
                GROUP BY c.id ORDER BY c.updated_at DESC"""
            ).fetchall()
        return self._decode(rows)

    def get_case(self, case_id: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                return None
            items = conn.execute("SELECT * FROM case_items WHERE case_id=? ORDER BY created_at", (case_id,)).fetchall()
        return {**dict(case), "items": self._decode(items)}

    def export_rows(self, case_id: int | None = None) -> dict[str, Any]:
        with self.connect() as conn:
            if case_id is not None:
                case = self.get_case(case_id)
                if not case:
                    raise KeyError("case not found")
                alert_ids = [i["item_id"] for i in case["items"] if i["item_type"] == "alert" and i["item_id"]]
                event_ids = [i["item_id"] for i in case["items"] if i["item_type"] == "event" and i["item_id"]]
                alerts = []
                events = []
                if alert_ids:
                    placeholders = ",".join("?" for _ in alert_ids)
                    alerts = self._decode(conn.execute(f"SELECT * FROM alerts WHERE id IN ({placeholders})", alert_ids).fetchall(), "evidence_json")
                if event_ids:
                    placeholders = ",".join("?" for _ in event_ids)
                    events = self._decode(conn.execute(f"SELECT * FROM events WHERE id IN ({placeholders})", event_ids).fetchall(), "data_json")
                return {"case": case, "alerts": alerts, "events": events, "exported_at": utc_now()}
            alerts = self._decode(conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 5000").fetchall(), "evidence_json")
            events = self._decode(conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT 10000").fetchall(), "data_json")
        return {"case": None, "alerts": alerts, "events": events, "exported_at": utc_now()}
