"""Lightweight fleet hub.

Hosts push their audit summary (`guardian audit --push URL --token T`); the
hub keeps the latest report per host in SQLite and serves a small HTML
overview plus JSON. It is deliberately tiny: one process, stdlib HTTP server,
no raw event streams, so it never grows into a Wazuh.

Security: the hub binds to 127.0.0.1 by default. If you bind it to a public
address, put it behind a TLS reverse proxy and keep the token long.
"""

from __future__ import annotations

import hmac
import html
import json
import socket
import sqlite3
import threading
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY, updated TEXT NOT NULL, score INTEGER NOT NULL,
    critical INTEGER NOT NULL, high INTEGER NOT NULL, medium INTEGER NOT NULL, low INTEGER NOT NULL,
    report TEXT NOT NULL
);
"""
MAX_BODY = 4 * 1024 * 1024


def summarize(report: dict) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for m in report.get("modules", []):
        for f in m.get("findings", []):
            if f.get("severity") in counts:
                counts[f["severity"]] += 1
    return counts


class HubDB:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript(SCHEMA)

    def upsert(self, report: dict) -> None:
        host = str(report.get("host") or "unknown")[:200]
        c = summarize(report)
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO hosts VALUES (?,?,?,?,?,?,?,?)",
                (host, datetime.now(UTC).isoformat(), int(report.get("score", 0)), c["critical"], c["high"], c["medium"], c["low"], json.dumps(report)),
            )
            self.conn.commit()

    def hosts(self) -> list[dict]:
        with self.lock:
            rows = self.conn.execute("SELECT host, updated, score, critical, high, medium, low FROM hosts ORDER BY score ASC, host").fetchall()
        return [dict(zip(("host", "updated", "score", "critical", "high", "medium", "low"), r)) for r in rows]

    def report(self, host: str) -> dict | None:
        with self.lock:
            row = self.conn.execute("SELECT report FROM hosts WHERE host=?", (host,)).fetchone()
        return json.loads(row[0]) if row else None


def _age(iso: str) -> str:
    try:
        delta = datetime.now(UTC) - datetime.fromisoformat(iso)
    except ValueError:
        return "?"
    s = int(delta.total_seconds())
    return f"{s // 86400}d" if s >= 86400 else f"{s // 3600}h" if s >= 3600 else f"{s // 60}m"


STYLE = """<style>body{font:14px system-ui,sans-serif;margin:2rem;color:#111;background:#fafafa}
table{border-collapse:collapse;width:100%}th,td{padding:.4rem .6rem;border-bottom:1px solid #ddd;text-align:left}
.sev-critical{color:#fff;background:#b00020;padding:0 .4rem;border-radius:3px}.sev-high{color:#b00020;font-weight:600}
.sev-medium{color:#a15c00}.sev-low{color:#0b5394}.sev-info{color:#777}.ok{color:#0a7d2c;font-weight:600}
.bad{color:#b00020;font-weight:600}.stale{color:#999}a{color:#0b5394}</style>"""


def render_index(hosts: list[dict]) -> str:
    rows = []
    for h in hosts:
        cls = "ok" if h["score"] >= 80 else "bad" if h["score"] < 50 else ""
        age = _age(h["updated"])
        stale = ' class="stale"' if age.endswith("d") else ""
        rows.append(f"<tr{stale}><td><a href='/host/{html.escape(h['host'])}'>{html.escape(h['host'])}</a></td>"
                    f"<td class='{cls}'>{h['score']}</td><td>{h['critical']}</td><td>{h['high']}</td><td>{h['medium']}</td><td>{h['low']}</td><td>{age} ago</td></tr>")
    return (f"<!doctype html><title>Guardian fleet</title>{STYLE}<h1>Guardian fleet</h1>"
            f"<p>{len(hosts)} host(s). Scores: green ≥ 80, red &lt; 50. Grey rows have not reported for a day.</p>"
            "<table><tr><th>Host</th><th>Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Last report</th></tr>"
            + "".join(rows) + "</table>")


def render_host(report: dict) -> str:
    rows = []
    for m in report.get("modules", []):
        for f in sorted(m.get("findings", []), key=lambda x: ["info", "low", "medium", "high", "critical"].index(x.get("severity", "info")), reverse=True):
            sev = f.get("severity", "info")
            rows.append(f"<tr><td><span class='sev-{sev}'>{sev.upper()}</span></td><td>{html.escape(m['module'])}</td>"
                        f"<td>{html.escape(f.get('title', ''))}</td><td>{html.escape(f.get('fix', ''))}</td></tr>")
    return (f"<!doctype html><title>{html.escape(report.get('host', ''))}</title>{STYLE}<p><a href='/'>← fleet</a></p>"
            f"<h1>{html.escape(report.get('host', ''))}</h1><p>Score {report.get('score')} · reported {html.escape(report.get('time', ''))}</p>"
            "<table><tr><th>Sev</th><th>Module</th><th>Finding</th><th>Fix</th></tr>" + "".join(rows) + "</table>")


def make_handler(db: HubDB, token: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "guardian-hub"

        def _send(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def _authed(self) -> bool:
            auth = self.headers.get("Authorization", "")
            return auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].strip(), token)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/":
                return self._send(200, render_index(db.hosts()).encode())
            if self.path == "/api/hosts":
                if not self._authed():
                    return self._send(401, b'{"error":"unauthorized"}', "application/json")
                return self._send(200, json.dumps(db.hosts()).encode(), "application/json")
            if self.path.startswith("/host/"):
                rep = db.report(self.path[6:])
                return self._send(200, render_host(rep).encode()) if rep else self._send(404, b"not found", "text/plain")
            self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/api/report":
                return self._send(404, b"not found", "text/plain")
            if not self._authed():
                return self._send(401, b'{"error":"unauthorized"}', "application/json")
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b"bad length", "text/plain")
            try:
                report = json.loads(self.rfile.read(length))
                assert isinstance(report, dict) and "modules" in report
            except (ValueError, AssertionError):
                return self._send(400, b'{"error":"bad report"}', "application/json")
            db.upsert(report)
            self._send(200, b'{"ok":true}', "application/json")

        def log_message(self, fmt, *args) -> None:  # quiet
            pass

    return Handler


def serve(bind: str, port: int, token: str, db_path: Path) -> None:
    db = HubDB(db_path)
    httpd = ThreadingHTTPServer((bind, port), make_handler(db, token))
    httpd.serve_forever()


def push(url: str, token: str, report_json: str, timeout: float = 20.0) -> bool:
    try:
        r = httpx.post(url.rstrip("/") + "/api/report", content=report_json,
                       headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": f"guardian/{socket.gethostname()}"},
                       timeout=timeout)
        return r.is_success
    except httpx.HTTPError:
        return False
