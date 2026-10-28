"""M2 SSH & auth guard.

Checks the effective sshd configuration for weak settings, looks for
brute-force bursts and successful logins from new addresses in the auth logs
(or the systemd journal), and reports whether a banning tool (fail2ban or
CrowdSec) is present and running.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path

from ..models import Finding, Severity
from ..utils import have, is_private_ip, read_text, run as sh
from . import Context

NAME = "ssh_guard"

FAIL_KEYWORDS = re.compile(
    r"Failed password|Invalid user|authentication failure|Connection closed by (?:invalid|authenticating) user|"
    r"maximum authentication attempts exceeded|Timeout before authentication|Disconnected from (?:invalid|authenticating) user",
    re.I,
)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b|\b((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4})\b", re.I)
ACCEPT_RE = re.compile(
    r"Accepted (publickey|password|keyboard-interactive/pam) for (\S+) from (\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)"
)

# Option -> (bad values, severity, fix)
SSHD_RULES: dict[str, tuple[set[str], Severity, str]] = {
    "permitrootlogin": ({"yes"}, Severity.HIGH, "Set PermitRootLogin to 'no' (or 'prohibit-password' if root keys are needed)."),
    "passwordauthentication": ({"yes"}, Severity.HIGH, "Use SSH keys only: PasswordAuthentication no. Brute-force bots target password auth."),
    "permitemptypasswords": ({"yes"}, Severity.CRITICAL, "Set PermitEmptyPasswords no."),
    "x11forwarding": ({"yes"}, Severity.LOW, "Set X11Forwarding no on servers."),
    "usepam": ({"no"}, Severity.LOW, "Keep UsePAM yes so fail2ban/pam limits apply."),
    "kbdinteractiveauthentication": ({"yes"}, Severity.MEDIUM, "Set KbdInteractiveAuthentication no unless MFA via PAM is configured."),
}


def effective_sshd_config() -> dict[str, str]:
    """Prefer `sshd -T` (effective config); fall back to parsing the file."""
    cfg: dict[str, str] = {}
    if have("sshd"):
        rc, out, _ = sh(["sshd", "-T"], timeout=10)
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    cfg[parts[0].lower()] = parts[1].strip()
            return cfg
    text = read_text("/etc/ssh/sshd_config") or ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.lower().startswith("match "):
            continue
        parts = re.split(r"\s+|=", line, maxsplit=1)
        if len(parts) == 2:
            cfg.setdefault(parts[0].lower(), parts[1].strip())
    for inc in sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")) if Path("/etc/ssh/sshd_config.d").is_dir() else []:
        for line in (read_text(inc) or "").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = re.split(r"\s+|=", line, maxsplit=1)
                if len(parts) == 2:
                    cfg.setdefault(parts[0].lower(), parts[1].strip())
    return cfg


def read_auth_lines(paths: list[str], window: timedelta) -> list[str]:
    """Return recent auth log lines from files, or from journald if no file exists."""
    lines: list[str] = []
    for p in paths:
        text = read_text(p)
        if text:
            # Keep the tail only; auth logs can be large.
            lines.extend(text.splitlines()[-20000:])
    if not lines and have("journalctl"):
        since = f"-{int(window.total_seconds() // 60)}min"
        rc, out, _ = sh(["journalctl", "-u", "ssh", "-u", "sshd", "--since", since, "--no-pager", "-o", "short-iso"], timeout=20)
        if rc == 0:
            lines = out.splitlines()
    return lines


def _line_time(line: str, now: datetime, tz: tzinfo | None = None) -> datetime | None:
    """Parse the timestamp at the start of a log line.

    ISO lines (journald short-iso, rsyslog RFC3339) carry their own offset.
    Classic "Oct 28 12:00:00" lines are written by rsyslog in the host's local
    time, so they are interpreted in `tz` (default: the local timezone).
    """
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)", line)
    if m:
        try:
            t = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
            return t if t.tzinfo else t.replace(tzinfo=UTC)
        except ValueError:
            return None
    m = re.match(r"([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})", line)
    if m:
        try:
            t = datetime.strptime(f"{now.year} {m.group(1)} {m.group(2)} {m.group(3)}:{m.group(4)}:{m.group(5)}", "%Y %b %d %H:%M:%S")
            t = t.replace(tzinfo=tz) if tz is not None else t.astimezone()  # naive -> local
            if t > now + timedelta(days=1):  # year rollover
                t = t.replace(year=now.year - 1)
            return t
        except ValueError:
            return None
    return None


def analyze_auth(lines: list[str], window: timedelta, now: datetime | None = None,
                 tz: tzinfo | None = None) -> tuple[Counter[str], dict[str, set[str]], Counter[str]]:
    """Return (failures per IP, accepted logins user->ips, invalid usernames).

    `tz` is the timezone of classic syslog timestamps (default: local time)."""
    now = now or datetime.now(UTC)
    cutoff = now - window
    failures: Counter[str] = Counter()
    accepted: dict[str, set[str]] = defaultdict(set)
    users: Counter[str] = Counter()
    for line in lines:
        t = _line_time(line, now, tz)
        if t is not None and t < cutoff:
            continue
        m = FAIL_KEYWORDS.search(line)
        if m:
            ipm = IP_RE.search(line, m.end())
            if not ipm:
                continue
            failures[ipm.group(1) or ipm.group(2)] += 1
            um = re.search(r"Invalid user (\S+)", line)
            if um:
                users[um.group(1)] += 1
            continue
        m = ACCEPT_RE.search(line)
        if m:
            accepted[m.group(2)].add(m.group(3))
    return failures, accepted, users


def service_active(name: str) -> bool | None:
    if not have("systemctl"):
        return None
    rc, out, _ = sh(["systemctl", "is-active", name], timeout=5)
    return out.strip() == "active"


def run(ctx: Context) -> list[Finding]:
    cfg = ctx.config.ssh
    findings: list[Finding] = []

    # 1. sshd configuration
    sshd = effective_sshd_config()
    if not sshd:
        findings.append(Finding(module=NAME, check="sshd-config", severity=Severity.INFO,
                                title="sshd configuration not found (sshd not installed or not readable)"))
    for key, (bad, sev, fix) in SSHD_RULES.items():
        val = sshd.get(key)
        if val is not None and val.lower() in bad:
            findings.append(Finding(
                module=NAME, check="sshd-config", severity=sev,
                title=f"sshd: {key} is '{val}'", fix=fix,
                evidence={"option": key, "value": val},
            ))
    try:
        if int(sshd.get("maxauthtries", "6")) > 4:
            findings.append(Finding(module=NAME, check="sshd-config", severity=Severity.LOW,
                                    title=f"sshd: MaxAuthTries is {sshd['maxauthtries']}",
                                    fix="Set MaxAuthTries 3."))
    except (ValueError, KeyError):
        pass
    if sshd and sshd.get("port", "22") == "22" and sshd.get("passwordauthentication", "yes").lower() == "yes":
        findings.append(Finding(module=NAME, check="sshd-config", severity=Severity.MEDIUM,
                                title="sshd: password auth on port 22 attracts constant brute force",
                                fix="Disable password auth; optionally move SSH to a non-default port and use a banning tool."))

    # 2. Auth log analysis
    window = timedelta(minutes=cfg.window_minutes)
    lines = read_auth_lines(cfg.auth_logs, window)
    failures, accepted, users = analyze_auth(lines, window)
    for ip, n in failures.most_common(10):
        if n >= cfg.brute_force_threshold:
            findings.append(Finding(
                module=NAME, check="brute-force", severity=Severity.MEDIUM,
                title=f"{n} failed SSH logins from {ip} in the last {cfg.window_minutes} min",
                detail=f"Most tried invalid users: {', '.join(u for u, _ in users.most_common(5))}",
                fix="Ban with fail2ban/CrowdSec; disable password auth; consider allow-listing admin IPs.",
                evidence={"ip": ip, "count": n},
            ))
    total_fail = sum(failures.values())
    if total_fail >= cfg.brute_force_threshold * 4:
        findings.append(Finding(
            module=NAME, check="brute-force", severity=Severity.MEDIUM,
            title=f"{total_fail} failed SSH logins from {len(failures)} addresses in the last {cfg.window_minutes} min",
            fix="Distributed brute force: use key-only auth and CrowdSec (shared blocklists) rather than per-IP bans.",
            evidence={"total": total_fail, "sources": len(failures)},
        ))

    # Successful logins from public IPs not seen before.
    known: dict[str, list[str]] = ctx.store.get("ssh_known_logins") or {}
    changed = False
    for user, ips in accepted.items():
        for ip in ips:
            if is_private_ip(ip):
                continue
            if ip not in known.get(user, []):
                known.setdefault(user, []).append(ip)
                changed = True
                if known.get("__initialized__"):
                    findings.append(Finding(
                        module=NAME, check="new-login-source", severity=Severity.MEDIUM,
                        title=f"SSH login for '{user}' from new address {ip}",
                        fix="Confirm this login was you; if not, rotate keys and check authorized_keys.",
                        evidence={"user": user, "ip": ip},
                    ))
    if not known.get("__initialized__"):
        known["__initialized__"] = ["1"]
        changed = True
    if changed:
        ctx.store.set("ssh_known_logins", known)

    # 3. Banning tool present?
    f2b, cs = service_active("fail2ban"), service_active("crowdsec")
    if f2b is not None and not (f2b or cs):
        findings.append(Finding(
            module=NAME, check="no-banning-tool", severity=Severity.MEDIUM,
            title="Neither fail2ban nor CrowdSec is running",
            fix="apt install fail2ban (or CrowdSec) and enable the sshd jail; Guardian will read its state.",
        ))
    return findings
