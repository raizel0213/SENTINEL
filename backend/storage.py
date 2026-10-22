"""SQLite persistence for SENTINEL scan history.

Design notes:
* local-only storage, no network sync (the app's privacy guarantee),
* one connection per operation (safe with Flask's threaded dev server),
* records capped at config.MAX_HISTORY, oldest deleted first,
* the full record JSON is stored alongside a few denormalized columns so
  listing history stays cheap.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from typing import Any, Dict, List, Optional

try:
    from . import config
except ImportError:  # pragma: no cover - direct script execution
    import config


def _connect() -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(str(config.DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error:
        pass
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id         TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            mode       TEXT NOT NULL,
            mode_label TEXT,
            target     TEXT NOT NULL,
            score      INTEGER,
            total      INTEGER,
            high       INTEGER,
            record     TEXT NOT NULL
        )
        """
    )


def save_scan(record: Dict[str, Any]) -> None:
    """Insert or replace a scan record and enforce the history cap."""
    counts = record.get("counts") or {}
    with closing(_connect()) as conn, conn:
        _ensure_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO scans "
            "(id, created_at, mode, mode_label, target, score, total, high, record) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(record.get("id")),
                str(record.get("timestamp")),
                str(record.get("mode")),
                str(record.get("mode_label") or ""),
                str(record.get("target")),
                record.get("score"),
                int(counts.get("total") or len(record.get("checks") or [])),
                int(counts.get("high") or 0),
                json.dumps(record, ensure_ascii=False),
            ),
        )
        conn.execute(
            "DELETE FROM scans WHERE id NOT IN ("
            "  SELECT id FROM scans ORDER BY created_at DESC, id LIMIT ?"
            ")",
            (config.MAX_HISTORY,),
        )


def list_scans() -> List[Dict[str, Any]]:
    """Return history summaries, newest first."""
    with closing(_connect()) as conn:
        _ensure_schema(conn)
        rows = conn.execute(
            "SELECT id, created_at, mode, mode_label, target, score, total, high "
            "FROM scans ORDER BY created_at DESC, id DESC LIMIT ?",
            (config.MAX_HISTORY,),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "timestamp": row["created_at"],
            "mode": row["mode"],
            "mode_label": row["mode_label"],
            "target": row["target"],
            "score": row["score"],
            "total": row["total"],
            "high": row["high"],
        }
        for row in rows
    ]


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Return the full stored record, or None."""
    with closing(_connect()) as conn:
        _ensure_schema(conn)
        row = conn.execute(
            "SELECT record FROM scans WHERE id = ?", (str(scan_id),)
        ).fetchone()
    return json.loads(row["record"]) if row else None


def delete_scan(scan_id: str) -> bool:
    with closing(_connect()) as conn, conn:
        _ensure_schema(conn)
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (str(scan_id),))
        return cursor.rowcount > 0


def clear_scans() -> int:
    with closing(_connect()) as conn, conn:
        _ensure_schema(conn)
        cursor = conn.execute("DELETE FROM scans")
        return cursor.rowcount


def count_scans() -> int:
    with closing(_connect()) as conn:
        _ensure_schema(conn)
        row = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()
    return int(row["n"]) if row else 0
