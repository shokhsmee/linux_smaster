"""M4 Kernel attack-surface reducer.

The 2026 local-root bugs (Copy Fail via AF_ALG, net/sched, ksmbd) all need
some reachable kernel feature. This module reports the sysctls, modules and
userspace helpers that widen that surface and gives the exact knob to close
each one. It never changes anything itself.
"""

from __future__ import annotations

import gzip
import re
from pathlib import Path

from ..models import Finding, Severity
from ..utils import have, read_text
from ..utils import run as sh
from . import Context

NAME = "kernel_hardening"
CONFIG_KEY = "kernel"

# sysctl -> (expected predicate, severity, why / fix)
SYSCTLS: dict[str, tuple[str, Severity, str]] = {
    "kernel.unprivileged_bpf_disabled": ("1|2", Severity.HIGH, "Unprivileged eBPF enables many kernel exploits and eBPF rootkits. Set kernel.unprivileged_bpf_disabled=1."),
    "kernel.kptr_restrict": ("1|2", Severity.MEDIUM, "Kernel pointers leak to unprivileged users (KASLR bypass). Set kernel.kptr_restrict=2."),
    "kernel.dmesg_restrict": ("1", Severity.LOW, "dmesg leaks addresses and hardware info. Set kernel.dmesg_restrict=1."),
    "kernel.yama.ptrace_scope": ("1|2|3", Severity.MEDIUM, "Any process can ptrace same-uid processes (credential theft from agents, browsers). Set kernel.yama.ptrace_scope=1."),
    "kernel.perf_event_paranoid": ("2|3|4", Severity.LOW, "perf is a classic exploit primitive. Set kernel.perf_event_paranoid=3."),
    "kernel.kexec_load_disabled": ("1", Severity.LOW, "kexec allows loading an attacker kernel. Set kernel.kexec_load_disabled=1."),
    "kernel.sysrq": ("0|4|176", Severity.LOW, "Full SysRq lets local users crash/reboot. Set kernel.sysrq=0 (or 176)."),
    "fs.protected_symlinks": ("1", Severity.MEDIUM, "Symlink races in /tmp become root exploits. Set fs.protected_symlinks=1."),
    "fs.protected_hardlinks": ("1", Severity.MEDIUM, "Set fs.protected_hardlinks=1."),
    "fs.protected_fifos": ("1|2", Severity.LOW, "Set fs.protected_fifos=2."),
    "fs.protected_regular": ("1|2", Severity.LOW, "Set fs.protected_regular=2."),
    "fs.suid_dumpable": ("0", Severity.MEDIUM, "Core dumps of setuid programs leak secrets. Set fs.suid_dumpable=0."),
    "net.ipv4.tcp_syncookies": ("1", Severity.LOW, "Set net.ipv4.tcp_syncookies=1 against SYN floods."),
    "net.ipv4.conf.all.rp_filter": ("1|2", Severity.LOW, "Set net.ipv4.conf.all.rp_filter=1 against spoofing."),
    "net.ipv4.conf.all.accept_redirects": ("0", Severity.LOW, "Set net.ipv4.conf.all.accept_redirects=0."),
    "net.ipv4.conf.all.send_redirects": ("0", Severity.LOW, "Set net.ipv4.conf.all.send_redirects=0."),
    "net.ipv4.ip_forward": ("0", Severity.INFO, "IP forwarding is on (fine for Docker/K8s hosts; otherwise set net.ipv4.ip_forward=0)."),
    "kernel.io_uring_disabled": ("1|2", Severity.LOW, "io_uring is a frequent LPE source and evades some EDRs. Set kernel.io_uring_disabled=2 if nothing needs it."),
}

# Modules that are rarely needed on servers but repeatedly exploited.
RISKY_MODULES: dict[str, tuple[Severity, str]] = {
    "algif_aead": (Severity.HIGH, "AF_ALG AEAD interface used by Copy Fail (CVE-2026-31431). Blacklist: echo 'install algif_aead /bin/false' > /etc/modprobe.d/guardian.conf"),
    "algif_skcipher": (Severity.MEDIUM, "AF_ALG crypto sockets are reachable by any user; blacklist unless used."),
    "algif_hash": (Severity.LOW, "AF_ALG hash sockets; blacklist unless used."),
    "ksmbd": (Severity.HIGH, "In-kernel SMB server with repeated remote bugs (CVE-2025-37899). Use Samba or blacklist ksmbd."),
    "dccp": (Severity.MEDIUM, "DCCP has a history of UAF exploits; blacklist."),
    "sctp": (Severity.LOW, "Blacklist sctp unless telecom workloads need it."),
    "rds": (Severity.MEDIUM, "RDS had multiple LPEs; blacklist."),
    "tipc": (Severity.MEDIUM, "TIPC had remote heap overflows; blacklist."),
    "n_hdlc": (Severity.LOW, "Blacklist n_hdlc."),
    "ax25": (Severity.LOW, "Blacklist ax25/netrom/rose amateur-radio stacks."),
    "cramfs": (Severity.LOW, "Blacklist legacy filesystems (cramfs, freevxfs, jffs2, hfs, hfsplus, udf, squashfs if unused)."),
    "usb_storage": (Severity.INFO, "USB storage on a server is unusual; blacklist to block BadUSB-style drops."),
    "firewire_core": (Severity.LOW, "FireWire allows DMA attacks; blacklist."),
}


def sysctl_values(keys: list[str]) -> dict[str, str]:
    vals: dict[str, str] = {}
    for k in keys:
        text = read_text(Path("/proc/sys") / k.replace(".", "/"))
        if text is not None:
            vals[k] = text.strip()
    return vals


def loaded_modules() -> set[str]:
    return {line.split()[0] for line in (read_text("/proc/modules") or "").splitlines() if line.strip()}


def blacklisted_modules() -> set[str]:
    bl: set[str] = set()
    d = Path("/etc/modprobe.d")
    if d.is_dir():
        for f in d.glob("*.conf"):
            for m in re.finditer(r"^\s*(?:blacklist\s+(\S+)|install\s+(\S+)\s+/bin/(?:false|true))", read_text(f) or "", re.M):
                bl.add(m.group(1) or m.group(2))
    return bl


def module_available(name: str) -> bool:
    """Is the module buildable/loadable on this kernel (present under /lib/modules)?"""
    _, uname, _ = sh(["uname", "-r"], timeout=5)
    base = Path("/lib/modules") / uname.strip()
    if not base.is_dir():
        return False
    dep = read_text(base / "modules.dep") or ""
    return bool(re.search(rf"/{name}\.ko(\.(xz|zst|gz))?:", dep))


def sudo_version() -> tuple[int, ...] | None:
    """Upstream sudo version, or None when the distro changelog shows the
    chroot CVE was backported (Debian/Ubuntu keep the old version number)."""
    if not have("sudo"):
        return None
    # Ask the package manager, not the setuid binary: under a hardened unit
    # (NoNewPrivileges) `sudo --version` fails before printing anything.
    out = ""
    if have("dpkg-query"):
        _, out, _ = sh(["dpkg-query", "-W", "-f", "Sudo version ${Version}", "sudo"], timeout=10)
    elif have("rpm"):
        _, out, _ = sh(["rpm", "-q", "--qf", "Sudo version %{VERSION}", "sudo"], timeout=10)
    if "Sudo version" not in out:
        _, out, _ = sh(["sudo", "--version"], timeout=5)
    m = re.search(r"Sudo version (\d+)\.(\d+)\.(\d+)(?:p(\d+))?", out)
    if not m:
        return None
    for changelog in ("/usr/share/doc/sudo/changelog.Debian.gz", "/usr/share/doc/sudo/changelog.gz"):
        p = Path(changelog)
        if p.is_file():
            try:
                with gzip.open(p, "rt", errors="replace") as fh:
                    if "CVE-2025-32463" in fh.read(400_000):
                        return None
            except OSError:
                pass
    if have("rpm"):
        _, chg, _ = sh(["rpm", "-q", "--changelog", "sudo"], timeout=15)
        if "CVE-2025-32463" in chg:
            return None
    return tuple(int(x) if x else 0 for x in m.groups())


def userns_state(vals: dict[str, str]) -> tuple[bool | None, str]:
    """Return (unprivileged user namespaces enabled?, knob to disable)."""
    if "kernel.unprivileged_userns_clone" in vals:  # Debian/Ubuntu <24.04
        return vals["kernel.unprivileged_userns_clone"] == "1", "sysctl kernel.unprivileged_userns_clone=0"
    if "kernel.apparmor_restrict_unprivileged_userns" in vals:  # Ubuntu 24.04+
        return vals["kernel.apparmor_restrict_unprivileged_userns"] != "1", "sysctl kernel.apparmor_restrict_unprivileged_userns=1"
    if "user.max_user_namespaces" in vals:
        return vals["user.max_user_namespaces"] != "0", "sysctl user.max_user_namespaces=0"
    return None, ""


def evaluate(vals: dict[str, str], loaded: set[str], blacklisted: set[str], sudo_ver: tuple[int, ...] | None,
             lockdown: str, lsm: str, available=lambda n: True) -> list[Finding]:
    findings: list[Finding] = []
    for key, (ok_re, sev, why) in SYSCTLS.items():
        v = vals.get(key)
        if v is None:
            continue
        if not re.fullmatch(ok_re, v):
            findings.append(Finding(module=NAME, check="sysctl", severity=sev, title=f"{key} = {v}", fix=why,
                                    evidence={"sysctl": key, "value": v}))

    enabled, knob = userns_state(vals)
    if enabled:
        findings.append(Finding(module=NAME, check="unprivileged-userns", severity=Severity.MEDIUM,
                                title="Unprivileged user namespaces are enabled",
                                fix=f"Most 2025-26 kernel LPEs (net/sched, nf_tables) need them. If no rootless containers run here: {knob}.",
                                evidence={"knob": knob}))

    for mod, (sev, fix) in RISKY_MODULES.items():
        if mod in loaded:
            findings.append(Finding(module=NAME, check="risky-module-loaded", severity=sev,
                                    title=f"Risky kernel module loaded: {mod}", fix=fix, evidence={"module": mod, "state": "loaded"}))
        elif mod not in blacklisted and sev.rank >= Severity.MEDIUM.rank and available(mod):
            findings.append(Finding(module=NAME, check="risky-module-autoloadable", severity=Severity.LOW,
                                    title=f"{mod} is not loaded but can be auto-loaded by an unprivileged user",
                                    fix=fix, evidence={"module": mod, "state": "available"}))

    if sudo_ver is not None and sudo_ver < (1, 9, 17, 1):
        findings.append(Finding(module=NAME, check="sudo-version", severity=Severity.HIGH,
                                title=f"sudo {'.'.join(map(str, sudo_ver[:3]))}p{sudo_ver[3]} is older than 1.9.17p1",
                                fix="CVE-2025-32463 (chroot local root, in CISA KEV) and CVE-2025-32462: upgrade sudo.",
                                evidence={"version": ".".join(map(str, sudo_ver))}))

    if lockdown and "[none]" in lockdown:
        findings.append(Finding(module=NAME, check="lockdown", severity=Severity.LOW,
                                title="Kernel lockdown mode is 'none'",
                                fix="Boot with lockdown=integrity (needs Secure Boot) to block unsigned modules and /dev/mem writes."))
    if lsm and not any(x in lsm for x in ("apparmor", "selinux")):
        findings.append(Finding(module=NAME, check="no-mac", severity=Severity.MEDIUM,
                                title="No mandatory access control (AppArmor/SELinux) active",
                                fix="Enable AppArmor (Debian/Ubuntu) or SELinux enforcing (RHEL family).", evidence={"lsm": lsm}))
    return findings


def run(ctx: Context) -> list[Finding]:
    if not Path("/proc/sys").is_dir():
        return [Finding(module=NAME, check="unsupported", severity=Severity.INFO, title="kernel checks need /proc/sys (Linux only)")]
    keys = [*SYSCTLS, "kernel.unprivileged_userns_clone", "kernel.apparmor_restrict_unprivileged_userns", "user.max_user_namespaces"]
    vals = sysctl_values(keys)
    lockdown = (read_text("/sys/kernel/security/lockdown") or "").strip()
    lsm = (read_text("/sys/kernel/security/lsm") or "").strip()
    return evaluate(vals, loaded_modules(), blacklisted_modules(), sudo_version(), lockdown, lsm, module_available)
