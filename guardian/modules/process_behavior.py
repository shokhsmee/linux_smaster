"""M7 Process behaviour monitor.

Polls /proc (via psutil) for the behaviours post-exploitation tooling has to
perform: binaries executing from /tmp, /dev/shm or memfd, deleted-on-disk
executables, system-name mimicry (a 'kswapd0' living in /tmp), web/app servers
spawning shells or downloaders, download-and-execute pipelines, and sustained
CPU burn from binaries no package owns (miners). No kernel hooks required.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from ..models import Finding, Severity
from ..utils import have, run as sh
from . import Context

NAME = "process_behavior"
CONFIG_KEY = "process"

TMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/dev/mqueue/")
SYSTEM_BIN_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/", "/lib/", "/opt/", "/snap/", "/usr/local/")
# Names malware borrows from the kernel/system to hide in `ps`.
MIMIC_NAMES = {
    "kswapd0", "kworker", "kthreadd", "crond", "cron", "systemd", "systemd-devd", "systemd-udevd", "sshd",
    "dbus-daemon", "rsyslogd", "apt-daily", "apt-daily-upgrade", "kdevtmpfsi", "kinsing", "migrations", "x86_64",
    "bash", "sh", "init", "[kworker/0:0]", "network", "dhcpd", "httpd", "nginx", "php-fpm", "java", "python3",
}
WEB_PARENTS = {"node", "nodejs", "php-fpm", "php", "php-fpm8.2", "php-fpm8.3", "java", "python", "python3", "gunicorn",
               "uwsgi", "ruby", "puma", "unicorn", "nginx", "apache2", "httpd", "dotnet", "deno", "bun", "tomcat"}
SHELLS_AND_TOOLS = {"sh", "bash", "dash", "zsh", "ash", "curl", "wget", "nc", "ncat", "netcat", "socat", "perl", "python", "python3", "base64"}
SUSPICIOUS_CMD = re.compile(
    r"(curl|wget)[^|\n]*\|\s*(ba|da)?sh|base64\s+(-d|--decode)|/dev/tcp/|\bnc\b.*\s-e\s|socat.*exec:|"
    r"python[23]?\s+-c\s+['\"]?import\s+(socket|pty)|xmrig|minerd|stratum\+tcp|stratum2?\+ssl|kdevtmpfsi|kinsing|"
    r"chattr\s+[+-]i|bash\s+-i\s*>&|/dev/shm/\S+|--donate-level|cryptonight|monero|\bxmr\b",
    re.I,
)
MINER_NAMES = re.compile(r"xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|xmr-stak|nanominer|t-rex|lolminer|cgminer", re.I)


@dataclass
class Proc:
    pid: int
    name: str
    exe: str
    cmdline: str
    user: str
    ppid: int
    pname: str
    cpu: float = 0.0
    deleted: bool = False
    memfd: bool = False
    cwd: str = ""
    extra: dict = field(default_factory=dict)


def snapshot(cpu_interval: float = 1.0) -> list[Proc]:
    procs: list[Proc] = []
    handles = []
    for p in psutil.process_iter(["pid", "name", "ppid", "username"]):
        try:
            p.cpu_percent(None)  # prime
            handles.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if cpu_interval > 0:
        psutil.cpu_percent(cpu_interval)  # sleep once for all
    for p in handles:
        try:
            with p.oneshot():
                exe = ""
                deleted = memfd = False
                try:
                    link = os.readlink(f"/proc/{p.pid}/exe")
                    exe = link
                    deleted = link.endswith(" (deleted)")
                    memfd = link.startswith("/memfd:") or link.startswith("memfd:")
                    exe = link.removesuffix(" (deleted)")
                except OSError:
                    try:
                        exe = p.exe() or ""
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        exe = ""
                try:
                    cmd = " ".join(p.cmdline())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cmd = ""
                try:
                    parent = p.parent()
                    pname = parent.name() if parent else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pname = ""
                try:
                    cwd = p.cwd() or ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cwd = ""
                procs.append(Proc(
                    pid=p.pid, name=p.info["name"] or "", exe=exe, cmdline=cmd, user=p.info["username"] or "",
                    ppid=p.info["ppid"] or 0, pname=pname, cpu=p.cpu_percent(None), deleted=deleted, memfd=memfd, cwd=cwd,
                ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return procs


def package_owns(path: str) -> bool | None:
    """True/False if the package manager knows the file; None if unknown."""
    if not path or not os.path.exists(path):
        return None
    if have("dpkg"):
        rc, _, _ = sh(["dpkg", "-S", path], timeout=15)
        return rc == 0
    if have("rpm"):
        rc, _, _ = sh(["rpm", "-qf", path], timeout=15)
        return rc == 0
    return None


def analyze(procs: list[Proc], cpu_threshold: float = 85.0, owner_check=package_owns) -> list[Finding]:
    findings: list[Finding] = []
    seen_cpu_check: dict[str, bool | None] = {}

    for p in procs:
        if p.pid <= 2 or (p.exe == "" and p.cmdline == ""):
            continue  # kernel threads / unreadable
        ev = {"pid": p.pid, "name": p.name, "exe": p.exe, "user": p.user, "parent": p.pname, "cmd": p.cmdline[:200]}

        if p.memfd:
            findings.append(Finding(module=NAME, check="memfd-exec", severity=Severity.HIGH,
                                    title=f"Fileless process {p.name} (pid {p.pid}) runs from memfd",
                                    fix="Fileless execution is a loader/malware technique; dump /proc/PID/exe for analysis, then kill.", evidence=ev))
        elif p.deleted and not p.exe.startswith(("/usr/", "/lib", "/bin", "/sbin", "/opt/", "/snap/")):
            findings.append(Finding(module=NAME, check="deleted-exe", severity=Severity.HIGH,
                                    title=f"{p.name} (pid {p.pid}) runs from a deleted binary {p.exe}",
                                    fix="Binary deleted after launch is an anti-forensics sign; copy /proc/PID/exe before killing.", evidence=ev))
        elif p.deleted:
            findings.append(Finding(module=NAME, check="deleted-exe", severity=Severity.LOW,
                                    title=f"{p.name} (pid {p.pid}) runs an updated/deleted binary {p.exe}",
                                    fix="Usually a package upgrade; restart the service (needrestart).", evidence=ev))

        if p.exe.startswith(TMP_DIRS):
            findings.append(Finding(module=NAME, check="exec-from-tmp", severity=Severity.HIGH,
                                    title=f"{p.name} (pid {p.pid}) executes from {p.exe}",
                                    fix="Mount /tmp and /dev/shm noexec; inspect and remove the binary.", evidence=ev))

        base = os.path.basename(p.exe)
        if (p.name in MIMIC_NAMES or base in MIMIC_NAMES) and p.exe and not p.exe.startswith(SYSTEM_BIN_DIRS):
            findings.append(Finding(module=NAME, check="name-mimicry", severity=Severity.HIGH,
                                    title=f"Process '{p.name}' (pid {p.pid}) mimics a system name but runs from {p.exe}",
                                    fix="Classic miner/rootkit disguise; verify the binary hash and kill.", evidence=ev))

        if p.pname in WEB_PARENTS and p.name in SHELLS_AND_TOOLS and p.user not in ("root", ""):
            findings.append(Finding(module=NAME, check="webserver-spawned-shell", severity=Severity.HIGH,
                                    title=f"{p.pname} spawned {p.name} (pid {p.pid}) as {p.user}: possible webshell/RCE",
                                    detail=p.cmdline[:300], fix="Check the web app for RCE (React2Shell, plugin exploits); review access logs around now.", evidence=ev))

        m = SUSPICIOUS_CMD.search(p.cmdline)
        if m:
            findings.append(Finding(module=NAME, check="suspicious-cmdline", severity=Severity.HIGH,
                                    title=f"Suspicious command in pid {p.pid} ({p.name}): '{m.group(0)[:50]}'",
                                    detail=p.cmdline[:300], fix="Download-and-execute, reverse-shell or miner pattern; kill and investigate the parent.", evidence=ev))

        if MINER_NAMES.search(p.name) or MINER_NAMES.search(base):
            findings.append(Finding(module=NAME, check="known-miner", severity=Severity.CRITICAL,
                                    title=f"Known cryptominer name: {p.name} (pid {p.pid})", fix="Kill, remove persistence (cron/systemd), rotate credentials.", evidence=ev))

        if p.cpu >= cpu_threshold and p.exe:
            if p.exe not in seen_cpu_check:
                seen_cpu_check[p.exe] = owner_check(p.exe)
            owned = seen_cpu_check[p.exe]
            if owned is False or p.exe.startswith(TMP_DIRS) or "/." in p.exe:
                findings.append(Finding(module=NAME, check="high-cpu-unowned", severity=Severity.MEDIUM,
                                        title=f"{p.name} (pid {p.pid}) at {p.cpu:.0f}% CPU from unpackaged binary {p.exe}",
                                        fix="Sustained CPU from an unknown binary is the miner signature; check its network connections.", evidence=ev | {"cpu": p.cpu}))

        # Hidden-dot paths in exe or cwd under /tmp, /var, home dirs: miners love "/tmp/.x/", "/var/tmp/.ICE-unix/..."
        if re.search(r"/\.[^/]+/", p.exe) and not p.exe.startswith(("/home/", "/root/", "/opt/", "/usr/")) and p.exe:
            findings.append(Finding(module=NAME, check="hidden-dir-exe", severity=Severity.MEDIUM,
                                    title=f"{p.name} (pid {p.pid}) runs from a hidden directory: {p.exe}", fix="Inspect the directory contents.", evidence=ev))
    return findings


def run(ctx: Context) -> list[Finding]:
    if not Path("/proc").is_dir():
        return [Finding(module=NAME, check="unsupported", severity=Severity.INFO, title="process_behavior needs /proc (Linux only)")]
    cfg = ctx.config.process
    procs = snapshot(cfg.cpu_sample_seconds)
    return analyze(procs, cfg.cpu_threshold)
