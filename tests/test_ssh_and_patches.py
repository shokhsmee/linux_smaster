from datetime import UTC, datetime, timedelta

from guardian.models import Severity
from guardian.modules import patches, ssh_guard

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def test_analyze_auth_counts_failures_in_window():
    lines = [
        "Oct 28 11:50:01 srv sshd[1]: Failed password for root from 45.33.32.156 port 1 ssh2",
        "Oct 28 11:51:01 srv sshd[1]: Invalid user admin from 45.33.32.156 port 2",
        "Oct 28 11:52:01 srv sshd[1]: Connection closed by invalid user oracle 45.33.32.156 port 3 [preauth]",
        "Oct 28 09:00:00 srv sshd[1]: Failed password for root from 45.33.32.157 port 1 ssh2",  # outside window
        "2026-10-28T11:55:00+00:00 srv sshd[1]: Accepted publickey for deploy from 1.1.1.1 port 5 ssh2",
    ]
    fails, accepted, users = ssh_guard.analyze_auth(lines, timedelta(minutes=60), now=NOW)
    assert fails["45.33.32.156"] == 3
    assert "45.33.32.157" not in fails
    assert accepted["deploy"] == {"1.1.1.1"}
    assert users["admin"] == 1


def test_sshd_rules_and_new_login(ctx, monkeypatch):
    monkeypatch.setattr(ssh_guard, "effective_sshd_config", lambda: {"permitrootlogin": "yes", "passwordauthentication": "yes", "port": "22"})
    monkeypatch.setattr(ssh_guard, "service_active", lambda name: False)
    lines = ["2026-10-28T11:55:00+00:00 srv sshd[1]: Accepted publickey for deploy from 1.1.1.1 port 5 ssh2"]
    monkeypatch.setattr(ssh_guard, "read_auth_lines", lambda paths, window: lines)
    monkeypatch.setattr(ssh_guard, "datetime", _FrozenDT)
    f1 = ssh_guard.run(ctx)
    checks = {f.check for f in f1}
    assert {"sshd-config", "no-banning-tool"} <= checks
    assert "new-login-source" not in checks  # first run learns, does not alert
    lines.append("2026-10-28T11:58:00+00:00 srv sshd[1]: Accepted publickey for deploy from 9.9.9.9 port 5 ssh2")
    f2 = ssh_guard.run(ctx)
    new = [f for f in f2 if f.check == "new-login-source"]
    assert len(new) == 1 and new[0].evidence["ip"] == "9.9.9.9"


class _FrozenDT(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def test_kev_matching_recent_only():
    today = datetime.now(UTC).date()
    kev = [
        {"cve": "CVE-2026-0001", "vendor": "Linux", "product": "Kernel", "name": "x", "added": (today - timedelta(days=2)).isoformat(), "due": "", "ransomware": "Unknown"},
        {"cve": "CVE-2025-32463", "vendor": "Sudo project", "product": "Sudo", "name": "chroot", "added": (today - timedelta(days=400)).isoformat(), "due": "", "ransomware": "Unknown"},
        {"cve": "CVE-2026-0002", "vendor": "Foo", "product": "Bar", "name": "x", "added": today.isoformat(), "due": "", "ransomware": "Unknown"},
    ]
    pkgs = {"linux-image-6.12.0-1-amd64": "6.12.0-1", "sudo": "1.9.15", "bar": "1"}
    hits = patches.match_kev(kev, pkgs)
    cves = {h[0]["cve"] for h in hits}
    assert cves == {"CVE-2026-0001"}


def test_kev_finding_severity(ctx, monkeypatch):
    today = datetime.now(UTC).date()
    monkeypatch.setattr(patches, "pending_updates", lambda: (3, 2, ["sudo", "curl"]))
    monkeypatch.setattr(patches, "reboot_required", lambda: (True, ["linux-image"]))
    monkeypatch.setattr(patches, "detect_distro", lambda: {"ID": "ubuntu"})
    monkeypatch.setattr(patches, "fetch_kev", lambda ctx: [
        {"cve": "CVE-2026-9", "vendor": "Sudo project", "product": "Sudo", "name": "n", "added": (today - timedelta(days=10)).isoformat(), "due": "", "ransomware": "Unknown"}])
    monkeypatch.setattr(patches, "installed_packages", lambda: {"sudo": "1.9.15"})
    monkeypatch.setattr(patches, "have", lambda c: False)
    findings = patches.run(ctx)
    kev = next(f for f in findings if f.check == "kev-installed-product")
    assert kev.severity == Severity.CRITICAL  # exposed host, past the 3-day SLA
    assert {"pending-security-updates", "reboot-required"} <= {f.check for f in findings}
