"""M12 Alerting: Telegram, Slack and generic webhook with severity filter."""

from __future__ import annotations

import json
import socket

import httpx

from .config import AlertConfig
from .models import Finding, Severity

ICON = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


def format_text(findings: list[Finding], host: str | None = None) -> str:
    host = host or socket.gethostname()
    lines = [f"Guardian on {host}: {len(findings)} new finding(s)"]
    for f in sorted(findings, key=lambda x: -x.severity.rank)[:25]:
        lines.append(f"{ICON[f.severity]} [{f.severity.upper()}] {f.title}")
        if f.fix:
            lines.append(f"   fix: {f.fix}")
    if len(findings) > 25:
        lines.append(f"... and {len(findings) - 25} more")
    return "\n".join(lines)


def filter_by_severity(findings: list[Finding], minimum: str) -> list[Finding]:
    try:
        floor = Severity(minimum).rank
    except ValueError:
        floor = Severity.MEDIUM.rank
    return [f for f in findings if f.severity.rank >= floor]


def send(cfg: AlertConfig, findings: list[Finding]) -> list[str]:
    """Send alerts for findings; returns a list of channel names that succeeded."""
    to_send = filter_by_severity(findings, cfg.min_severity)
    if not to_send:
        return []
    text = format_text(to_send)
    ok: list[str] = []
    with httpx.Client(timeout=15) as client:
        if cfg.telegram_bot_token and cfg.telegram_chat_id:
            try:
                r = client.post(
                    f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage",
                    json={"chat_id": cfg.telegram_chat_id, "text": text[:4000], "disable_web_page_preview": True},
                )
                if r.is_success:
                    ok.append("telegram")
            except httpx.HTTPError:
                pass
        if cfg.slack_webhook:
            try:
                r = client.post(cfg.slack_webhook, json={"text": text[:3900]})
                if r.is_success:
                    ok.append("slack")
            except httpx.HTTPError:
                pass
        if cfg.generic_webhook:
            try:
                payload = {"host": socket.gethostname(), "findings": [json.loads(f.model_dump_json()) for f in to_send]}
                r = client.post(cfg.generic_webhook, json=payload)
                if r.is_success:
                    ok.append("webhook")
            except httpx.HTTPError:
                pass
    return ok
