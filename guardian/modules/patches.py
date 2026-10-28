"""M3 Patch & KEV watcher.

Reports pending security updates, reboot-required state, kernel age and
whether installed packages match entries in CISA's Known Exploited
Vulnerabilities (KEV) catalog. KEV entries carry a short SLA (3 days by
default, following BOD 26-04 for internet-exposed hosts).
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import httpx

from ..models import Finding, Severity
from ..utils import detect_distro, have, read_text
from ..utils import run as sh
from . import Context

NAME = "patches"

# KEV "product" names (lowercased) -> package names we can match on Linux hosts.
# Kept small and conservative to avoid false positives.
KEV_PRODUCT_MAP: dict[str, tuple[str, ...]] = {
    "linux kernel": ("linux-image", "kernel", "linux"),
    "kernel": ("linux-image", "kernel"),
    "sudo": ("sudo",),
    "openssh": ("openssh-server", "openssh"),
    "openssl": ("openssl", "libssl"),
    "glibc": ("libc6", "glibc"),
    "polkit": ("polkit", "policykit-1"),
    "cups": ("cups", "cups-browsed"),
    "samba": ("samba",),
    "nginx": ("nginx",),
    "apache http server": ("apache2", "httpd"),
    "php": ("php",),
    "postgresql": ("postgresql",),
    "redis": ("redis", "redis-server"),
    "docker": ("docker-ce", "docker.io", "containerd"),
    "git": ("git",),
    "curl": ("curl", "libcurl"),
    "xz utils": ("xz-utils", "liblzma", "xz"),
    "needrestart": ("needrestart",),
    "langflow": ("langflow",),
    "ollama": ("ollama",),
    "ray": ("ray",),
    "jupyter": ("jupyter",),
}


def pending_updates() -> tuple[int, int, list[str]] | None:
    """Return (total, security, sample) of pending updates, or None if unknown."""
    if have("apt-get"):
        rc, out, _ = sh(["apt-get", "-s", "upgrade"], timeout=120)
        if rc != 0:
            return None
        pkgs = re.findall(r"^Inst (\S+) .*?\((\S+) ([^)]*)\)", out, re.M)
        sec = [p for p, _, origin in pkgs if "security" in origin.lower()]
        return len(pkgs), len(sec), [p for p, _, _ in pkgs][:10]
    if have("dnf"):
        rc, out, _ = sh(["dnf", "-q", "updateinfo", "list", "security", "--available"], timeout=120)
        sec = [l.split()[0] for l in out.splitlines() if l.strip() and not l.startswith("Last metadata")] if rc in (0, 100) else []
        rc2, out2, _ = sh(["dnf", "-q", "check-update"], timeout=120)
        total = len([l for l in out2.splitlines() if l.strip() and "." in l.split()[0]]) if rc2 in (0, 100) else len(sec)
        return total, len(sec), sec[:10]
    if have("yum"):
        rc, out, _ = sh(["yum", "-q", "check-update", "--security"], timeout=120)
        sec = [l.split()[0] for l in out.splitlines() if l.strip()] if rc in (0, 100) else []
        return len(sec), len(sec), sec[:10]
    return None


def reboot_required() -> tuple[bool, list[str]]:
    if Path("/var/run/reboot-required").exists():
        pkgs = (read_text("/var/run/reboot-required.pkgs") or "").split()
        return True, pkgs
    if have("needs-restarting"):
        rc, _, _ = sh(["needs-restarting", "-r"], timeout=30)
        return rc == 1, []
    return False, []


def installed_packages() -> dict[str, str]:
    pkgs: dict[str, str] = {}
    if have("dpkg-query"):
        rc, out, _ = sh(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"], timeout=60)
        if rc == 0:
            for line in out.splitlines():
                if "\t" in line:
                    n, v = line.split("\t", 1)
                    pkgs[n] = v
    elif have("rpm"):
        rc, out, _ = sh(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=60)
        if rc == 0:
            for line in out.splitlines():
                if "\t" in line:
                    n, v = line.split("\t", 1)
                    pkgs[n] = v
    return pkgs


def fetch_kev(ctx: Context) -> list[dict] | None:
    cfg = ctx.config.patches
    cached = ctx.store.get("kev_catalog", max_age_hours=cfg.kev_cache_hours)
    if cached:
        return cached
    try:
        r = httpx.get(cfg.kev_url, timeout=30, headers={"User-Agent": "guardian"})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
    except (httpx.HTTPError, ValueError):
        return ctx.store.get("kev_catalog")  # stale is better than nothing
    slim = [
        {
            "cve": v.get("cveID"), "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""), "added": v.get("dateAdded", ""), "due": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", ""),
        }
        for v in vulns
    ]
    ctx.store.set("kev_catalog", slim)
    return slim


def match_kev(kev: list[dict], pkgs: dict[str, str], recent_days: int = 180) -> list[tuple[dict, str, str]]:
    """Match recent KEV entries to installed package names. Version-agnostic:
    the result is 'this product is installed and has an exploited CVE added
    recently', which is a prompt to verify the version, not a confirmed vuln."""
    today = date.today()
    hits: list[tuple[dict, str, str]] = []
    names = list(pkgs)
    for v in kev:
        try:
            added = date.fromisoformat(v["added"])
        except (ValueError, KeyError):
            continue
        if (today - added).days > recent_days:
            continue
        product = v["product"].lower()
        vendor = v["vendor"].lower()
        candidates = KEV_PRODUCT_MAP.get(product) or KEV_PRODUCT_MAP.get(f"{vendor} {product}".strip())
        if not candidates and vendor == "linux" and "kernel" in product:
            candidates = KEV_PRODUCT_MAP["linux kernel"]
        if not candidates:
            continue
        for cand in candidates:
            for n in names:
                if n == cand or n.startswith(cand + "-") or (cand == "linux-image" and n.startswith("linux-image-")):
                    hits.append((v, n, pkgs[n]))
                    break
            else:
                continue
            break
    return hits


def run(ctx: Context) -> list[Finding]:
    cfg = ctx.config.patches
    findings: list[Finding] = []
    distro = detect_distro()

    pend = pending_updates()
    if pend is not None:
        total, sec, sample = pend
        if sec:
            findings.append(Finding(
                module=NAME, check="pending-security-updates", severity=Severity.HIGH if sec >= 5 else Severity.MEDIUM,
                title=f"{sec} security update(s) pending ({total} total)",
                detail="Includes: " + ", ".join(sample), fix="apt upgrade / dnf upgrade; enable unattended-upgrades or dnf-automatic.",
                evidence={"security": sec, "total": total},
            ))
        elif total:
            findings.append(Finding(module=NAME, check="pending-updates", severity=Severity.LOW,
                                    title=f"{total} update(s) pending (none flagged security)", evidence={"total": total}))

    rb, pkgs_rb = reboot_required()
    if rb:
        findings.append(Finding(
            module=NAME, check="reboot-required", severity=Severity.MEDIUM,
            title="Reboot required to apply updates" + (f" ({', '.join(pkgs_rb[:5])})" if pkgs_rb else ""),
            fix="Schedule a reboot, or use kernel live patching (livepatch/kpatch) for kernel updates.",
        ))

    # Auto-update configuration
    if distro.get("ID") in ("ubuntu", "debian") or distro.get("ID_LIKE", "").find("debian") >= 0:
        au = read_text("/etc/apt/apt.conf.d/20auto-upgrades") or ""
        if 'Unattended-Upgrade "1"' not in au:
            findings.append(Finding(module=NAME, check="auto-updates", severity=Severity.MEDIUM,
                                    title="unattended-upgrades is not enabled",
                                    fix="apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades"))
    elif have("dnf") and not Path("/etc/dnf/automatic.conf").exists():
        findings.append(Finding(module=NAME, check="auto-updates", severity=Severity.MEDIUM,
                                title="dnf-automatic is not configured",
                                fix="dnf install dnf-automatic && systemctl enable --now dnf-automatic.timer"))

    # KEV matching
    kev = fetch_kev(ctx)
    if kev is None:
        findings.append(Finding(module=NAME, check="kev-feed", severity=Severity.INFO,
                                title="Could not download the CISA KEV catalog (offline?)"))
    else:
        pkgs = installed_packages()
        hits = match_kev(kev, pkgs)
        seen_cves: set[str] = set()
        # Kernel entries are grouped into one finding against the *running*
        # kernel: distros backport fixes, so per-CVE package matching only tells
        # you the kernel is a KEV target, not that it is vulnerable.
        _, uname_out, _ = sh(["uname", "-r"], timeout=5)
        running_kernel = uname_out.strip()
        kernel_hits = [(v, p, ver) for v, p, ver in hits if p.startswith(("linux-image", "kernel", "linux"))]
        hits = [h for h in hits if h not in kernel_hits]
        recent_kernel = []
        for v, _, _ in kernel_hits:
            if v["cve"] in seen_cves:
                continue
            seen_cves.add(v["cve"])
            try:
                if int(v["cve"].split("-")[1]) >= date.today().year - 2:
                    recent_kernel.append(v)
            except (IndexError, ValueError):
                pass
        if recent_kernel:
            cves = ", ".join(v["cve"] for v in recent_kernel[:8])
            names = "; ".join(f"{v['cve']}: {v['name'][:60]}" for v in recent_kernel[:5])
            findings.append(Finding(
                module=NAME, check="kev-kernel", severity=Severity.HIGH, key=f"kernel:{running_kernel}",
                title=f"{len(recent_kernel)} actively exploited kernel CVE(s) in CISA KEV target your kernel line ({running_kernel}): {cves}",
                detail=names, fix="Check the distro advisory for each CVE (Ubuntu: `ubuntu-security-status` / USN, Debian: security-tracker, RHEL: `yum updateinfo`); apply the kernel update and reboot (or live-patch). Reduce exposure with the kernel_hardening module's module blacklists.",
                evidence={"running": running_kernel, "cves": cves},
            ))
        for v, pkg, ver in hits:
            if v["cve"] in seen_cves:
                continue
            seen_cves.add(v["cve"])
            try:
                age = (date.today() - date.fromisoformat(v["added"])).days
            except ValueError:
                age = 0
            sev = Severity.CRITICAL if (ctx.exposed and age > cfg.sla_days) or v["ransomware"] == "Known" else Severity.HIGH
            findings.append(Finding(
                module=NAME, check="kev-installed-product", severity=sev,
                title=f"{v['cve']} ({v['vendor']} {v['product']}) is actively exploited; {pkg} {ver} is installed",
                detail=f"{v['name']}. Added to KEV {v['added']} ({age} days ago), due {v['due']}. Ransomware use: {v['ransomware'] or 'unknown'}.",
                fix=f"Verify {pkg} is at a fixed version for {v['cve']} and patch within {cfg.sla_days} days (BOD 26-04 window).",
                evidence={"cve": v["cve"], "package": pkg, "version": ver, "kev_added": v["added"]},
            ))

    # Kernel: running vs newest installed (Debian/Ubuntu naming)
    _, uname, _ = sh(["uname", "-r"], timeout=5)
    running = uname.strip()
    if running and have("dpkg-query"):
        imgs = sorted(n for n in installed_packages() if n.startswith("linux-image-") and n[12:13].isdigit())
        newest = imgs[-1][12:] if imgs else ""
        if newest and newest != running and not running.startswith(newest):
            findings.append(Finding(module=NAME, check="kernel-not-running-latest", severity=Severity.MEDIUM,
                                    title=f"Running kernel {running} but {newest} is installed",
                                    fix="Reboot into the new kernel.", evidence={"running": running, "installed": newest}))
    return findings
