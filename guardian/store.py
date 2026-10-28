"""SQLite state: finding history (for dedup/new-finding alerts) and key/value cache."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    module TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS baselines (
    path TEXT PRIMARY KEY,
    digest TEXT NOT NULL,
    mode INTEGER NOT NULL,
    size INTEGER NOT NULL,
    updated TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        try:
            path.chmod(0o600)
        except OSError:
            pass

    # --- findings -----------------------------------------------------------

    def record(self, findings: list[Finding]) -> list[Finding]:
        """Store findings; return those not seen before (or resolved earlier)."""
        now = datetime.now(UTC).isoformat()
        new: list[Finding] = []
        cur = self.conn.cursor()
        seen_now = {f.fingerprint for f in findings}
        for f in findings:
            row = cur.execute(
                "SELECT resolved_at FROM findings WHERE fingerprint=?", (f.fingerprint,)
            ).fetchone()
            payload = f.model_dump_json()
            if row is None:
                cur.execute(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?,NULL,?)",
                    (f.fingerprint, f.module, f.severity, f.title, now, now, payload),
                )
                new.append(f)
            else:
                if row[0] is not None:
                    new.append(f)  # came back after being resolved
                cur.execute(
                    "UPDATE findings SET last_seen=?, resolved_at=NULL, payload=?, severity=? "
                    "WHERE fingerprint=?",
                    (now, payload, f.severity, f.fingerprint),
                )
        # Mark findings from the same modules that disappeared as resolved.
        modules = {f.module for f in findings}
        for mod in modules:
            for (fp,) in cur.execute(
                "SELECT fingerprint FROM findings WHERE module=? AND resolved_at IS NULL", (mod,)
            ).fetchall():
                if fp not in seen_now:
                    cur.execute(
                        "UPDATE findings SET resolved_at=? WHERE fingerprint=?", (now, fp)
                    )
        self.conn.commit()
        return new

    def mark_module_clean(self, module: str) -> None:
        """Called when a module ran and produced nothing: resolve its open findings."""
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "UPDATE findings SET resolved_at=? WHERE module=? AND resolved_at IS NULL",
            (now, module),
        )
        self.conn.commit()

    def open_findings(self) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT payload FROM findings WHERE resolved_at IS NULL"
        ).fetchall()
        return [Finding.model_validate_json(r[0]) for r in rows]

    # --- kv cache -----------------------------------------------------------

    def get(self, key: str, max_age_hours: float | None = None):
        row = self.conn.execute("SELECT value, updated FROM kv WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        if max_age_hours is not None:
            age = datetime.now(UTC) - datetime.fromisoformat(row[1])
            if age.total_seconds() > max_age_hours * 3600:
                return None
        return json.loads(row[0])

    def set(self, key: str, value) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO kv VALUES (?,?,?)",
            (key, json.dumps(value), datetime.now(UTC).isoformat()),
        )
        self.conn.commit()

    # --- file baselines -----------------------------------------------------

    def get_baseline(self, path: str) -> tuple[str, int, int] | None:
        row = self.conn.execute(
            "SELECT digest, mode, size FROM baselines WHERE path=?", (path,)
        ).fetchone()
        return (row[0], row[1], row[2]) if row else None

    def set_baseline(self, path: str, digest: str, mode: int, size: int) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO baselines VALUES (?,?,?,?,?)",
            (path, digest, mode, size, datetime.now(UTC).isoformat()),
        )
        self.conn.commit()

    def all_baselines(self) -> dict[str, tuple[str, int, int]]:
        rows = self.conn.execute("SELECT path, digest, mode, size FROM baselines").fetchall()
        return {r[0]: (r[1], r[2], r[3]) for r in rows}

    def delete_baseline(self, path: str) -> None:
        self.conn.execute("DELETE FROM baselines WHERE path=?", (path,))
        self.conn.commit()
