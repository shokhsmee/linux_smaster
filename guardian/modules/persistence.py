"""M5 Persistence watchlist (basic).

Keeps a hash baseline of the places attackers use to survive reboots (cron,
systemd units, rc.local, authorized_keys, sudoers, shell rc files, PAM,
ld.so.preload) and reports additions, removals and modifications. Also runs
content checks that need no baseline: non-empty ld.so.preload, PAM modules
that differ from the package manager's record, suspicious cron/systemd
commands, and new SUID binaries outside package ownership.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

from ..models import Finding, Severity
from ..utils import have, read_text, run as sh
from . import Context

NAME = "persistence"

WATCH_DIRS = (
    "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
    "/var/spool/cron", "/var/spool/cron/crontabs", "/etc/systemd/system", "/usr/lib/systemd/system",
    "/lib/systemd/system", "/etc/init.d", "/etc/profile.d", "/etc/sudoers.d", "/etc/pam.d",
    "/etc/ld.so.conf.d", "/etc/udev/rules.d", "/etc/apt/apt.conf.d", "/etc/ssh/sshd_config.d",
)
WATCH_FILES = (
    "/etc/crontab", "/etc/rc.local", "/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/group",
    "/etc/ld.so.preload", "/etc/profile", "/etc/bash.bashrc", "/etc/environment", "/etc/hosts",
    "/etc/ssh/sshd_config", "/etc/nsswitch.conf", "/etc/resolv.conf",
)
HOME_FILES = (
    ".ssh/authorized_keys", ".ssh/authorized_keys2", ".bashrc", ".bash_profile", ".profile", ".zshrc",
    ".config/systemd/user", ".config/autostart",
)

SUSPICIOUS_CMD = re.compile(
    r"(curl|wget)[^|\n]*\|\s*(ba)?sh|base64\s+(-d|--decode)|/dev/tcp/|nc\s+-e|python[23]?\s+-c\s+['\"]import\s+socket|"
    r"/tmp/[^\s]+|/dev/shm/[^\s]+|/var/tmp/[^\s]+|chattr\s+\+i|xmrig|stratum\+tcp|kdevtmpfsi|kinsing",
    re.I,
)


def _digest(path: Path) -> tuple[str, int, int] | None:
    try:
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            data = os.readlink(path).encode()
        elif stat.S_ISREG(st.st_mode):
            if st.st_size > 5 * 1024 * 1024:
                return None
            data = path.read_bytes()
        else:
            return None
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest(), st.st_mode, st.st_size


def watched_paths(extra: list[str]) -> list[Path]:
    paths: list[Path] = []
    for d in WATCH_DIRS + tuple(extra):
        p = Path(d)
        if p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_file() or sub.is_symlink():
                    paths.append(sub)
    for f in WATCH_FILES:
        p = Path(f)
        if p.is_file() or p.is_symlink():
            paths.append(p)
    homes = [Path("/root")] + [h for h in Path("/home").iterdir() if h.is_dir()] if Path("/home").is_dir() else [Path("/root")]
    for h in homes:
        for rel in HOME_FILES:
            p = h / rel
            if p.is_file():
                paths.append(p)
            elif p.is_dir():
                paths.extend(s for s in p.rglob("*") if s.is_file())
    return paths


def build_baseline(ctx: Context) -> int:
    n = 0
    for p in watched_paths(ctx.config.persistence.extra_paths):
        d = _digest(p)
        if d:
            ctx.store.set_baseline(str(p), *d)
            n += 1
    ctx.store.set("persistence_baseline_ready", True)
    return n


def diff_baseline(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    old = ctx.store.all_baselines()
    current: dict[str, tuple[str, int, int]] = {}
    for p in watched_paths(ctx.config.persistence.extra_paths):
        d = _digest(p)
        if d:
            current[str(p)] = d

    def sev_for(path: str) -> Severity:
        if any(k in path for k in ("authorized_keys", "sudoers", "ld.so.preload", "/etc/pam.d", "/etc/passwd", "/etc/shadow")):
            return Severity.HIGH
        if any(k in path for k in ("cron", "systemd", "rc.local", "init.d", "profile", "bashrc", "udev")):
            return Severity.MEDIUM
        return Severity.LOW

    for path, d in current.items():
        if path not in old:
            findings.append(Finding(module=NAME, check="new-file", severity=sev_for(path),
                                    title=f"New file in watched location: {path}",
                                    detail=_snippet(path), fix="Verify who created it; remove if unexpected.",
                                    evidence={"path": path, "sha256": d[0][:16]}))
            ctx.store.set_baseline(path, *d)
        elif old[path][0] != d[0] or old[path][1] != d[1]:
            what = "content" if old[path][0] != d[0] else "permissions"
            findings.append(Finding(module=NAME, check="modified-file", severity=sev_for(path),
                                    title=f"Watched file {what} changed: {path}",
                                    detail=_snippet(path), fix="Compare with a known-good copy; restore and investigate if unexpected.",
                                    evidence={"path": path, "old": old[path][0][:16], "new": d[0][:16],
                                              "old_mode": oct(old[path][1]), "new_mode": oct(d[1])}))
            ctx.store.set_baseline(path, *d)
    for path in set(old) - set(current):
        findings.append(Finding(module=NAME, check="removed-file", severity=Severity.LOW,
                                title=f"Watched file removed: {path}", evidence={"path": path}))
        ctx.store.delete_baseline(path)
    return findings


def _snippet(path: str, n: int = 300) -> str:
    text = read_text(path, limit=4096) or ""
    text = text.strip()
    return (text[:n] + "…") if len(text) > n else text


def content_checks(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []

    # ld.so.preload must normally be empty/absent.
    pre = (read_text("/etc/ld.so.preload") or "").strip()
    if pre:
        findings.append(Finding(module=NAME, check="ld-preload", severity=Severity.CRITICAL,
                                title="/etc/ld.so.preload is not empty (userland rootkit technique)",
                                detail=pre[:300], fix="Verify each library; Auto-Color, perfctl and similar malware use this. Remove and reinstall affected packages.",
                                evidence={"content": pre[:200]}))

    # Suspicious commands in cron/systemd/rc files.
    for p in watched_paths(ctx.config.persistence.extra_paths):
        s = str(p)
        if not any(k in s for k in ("cron", "systemd", "rc.local", "init.d", "profile", "bashrc", "zshrc")):
            continue
        text = read_text(p, limit=65536) or ""
        m = SUSPICIOUS_CMD.search(text)
        if m:
            findings.append(Finding(module=NAME, check="suspicious-command", severity=Severity.HIGH,
                                    title=f"Suspicious command in {s}: '{m.group(0)[:60]}'",
                                    detail=_snippet(s), fix="Inspect the file; download-and-execute or /tmp binaries in persistence files are a classic malware sign.",
                                    evidence={"path": s, "match": m.group(0)[:100]}))

    # authorized_keys: options that allow command execution without a shell, or keys without comments.
    for p in watched_paths([]):
        if p.name.startswith("authorized_keys"):
            text = read_text(p) or ""
            keys = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
            if len(keys) > 10:
                findings.append(Finding(module=NAME, check="authorized-keys", severity=Severity.LOW,
                                        title=f"{p} contains {len(keys)} keys", fix="Review and remove stale keys.",
                                        evidence={"path": str(p), "keys": len(keys)}))

    # PAM / core libs vs package manager records.
    if have("debsums"):
        rc, out, _ = sh(["debsums", "-c", "libpam-modules", "libpam-runtime", "libpam0g", "openssh-server", "sudo", "libc6"], timeout=120)
        for line in out.splitlines():
            line = line.strip()
            if line:
                findings.append(Finding(module=NAME, check="package-file-modified", severity=Severity.CRITICAL,
                                        title=f"Package-owned file modified: {line}",
                                        fix="A modified PAM/SSH/sudo/libc file is a backdoor until proven otherwise (e.g. Plague PAM). Reinstall the package and investigate.",
                                        evidence={"path": line}))
    elif have("rpm"):
        rc, out, _ = sh(["rpm", "-V", "pam", "openssh-server", "sudo", "glibc"], timeout=120)
        for line in out.splitlines():
            if line and line[0] in "S5" or ".5" in line[:9]:
                path = line.split()[-1]
                findings.append(Finding(module=NAME, check="package-file-modified", severity=Severity.CRITICAL,
                                        title=f"Package-owned file modified: {path}",
                                        fix="Reinstall the package and investigate; modified PAM/SSH/sudo files are a backdoor sign.",
                                        evidence={"path": path, "flags": line[:9]}))

    # Writable directories hiding NSS configs (preload/NSS hijack technique)
    for d in ("/tmp", "/dev/shm", "/var/tmp"):
        dp = Path(d)
        if not dp.is_dir():
            continue
        try:
            for sub in dp.rglob("libnss_*.so*"):
                findings.append(Finding(module=NAME, check="nss-in-tmp", severity=Severity.HIGH,
                                        title=f"NSS library in world-writable dir: {sub}",
                                        fix="Likely an NSS/preload hijack; remove and investigate.", evidence={"path": str(sub)}))
        except OSError:
            pass
    return findings


def run(ctx: Context) -> list[Finding]:
    findings = content_checks(ctx)
    if not ctx.store.get("persistence_baseline_ready"):
        n = build_baseline(ctx)
        findings.append(Finding(module=NAME, check="baseline", severity=Severity.INFO,
                                title=f"Persistence baseline created for {n} files; changes will be reported from the next run",
                                evidence={"files": n}))
    else:
        findings.extend(diff_baseline(ctx))
    return findings
