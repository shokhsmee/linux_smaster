from guardian.models import Severity
from guardian.modules import exposure


def test_public_bind_detection():
    assert exposure.is_public_bind("0.0.0.0")
    assert exposure.is_public_bind("::")
    assert exposure.is_public_bind("8.8.8.8")
    assert not exposure.is_public_bind("127.0.0.1")
    assert not exposure.is_public_bind("10.0.0.5")
    assert not exposure.is_public_bind("::1")


def test_ollama_without_auth_is_critical(ctx, monkeypatch):
    monkeypatch.setattr(exposure, "listeners", lambda: [
        exposure.Listener("tcp", "0.0.0.0", 11434, 42, "ollama"),
        exposure.Listener("tcp", "127.0.0.1", 6379, 43, "redis-server"),  # loopback: ignored
        exposure.Listener("tcp", "0.0.0.0", 22, 1, "sshd"),              # expected public port
        exposure.Listener("tcp", "0.0.0.0", 4567, 7, "mystery"),
    ])
    monkeypatch.setattr(exposure, "probe", lambda port, profile, timeout: True if port == 11434 else None)
    monkeypatch.setattr(exposure, "docker_published_ports", list)
    findings = exposure.run(ctx)
    by_port = {f.evidence["port"]: f for f in findings}
    assert by_port[11434].severity == Severity.CRITICAL
    assert "WITHOUT authentication" in by_port[11434].title
    assert 6379 not in by_port and 22 not in by_port
    assert by_port[4567].severity == Severity.INFO


def test_auth_required_downgrades(ctx, monkeypatch):
    monkeypatch.setattr(exposure, "listeners", lambda: [exposure.Listener("tcp", "::", 8888, 5, "jupyter")])
    monkeypatch.setattr(exposure, "probe", lambda *a: False)
    monkeypatch.setattr(exposure, "docker_published_ports", list)
    (f,) = exposure.run(ctx)
    assert f.severity == Severity.MEDIUM and f.evidence["auth"] == "auth-required"


def test_docker_ufw_bypass(ctx, monkeypatch):
    monkeypatch.setattr(exposure, "listeners", list)
    monkeypatch.setattr(exposure, "docker_published_ports", lambda: [("web", "0.0.0.0", 8080), ("db", "127.0.0.1", 5432)])
    monkeypatch.setattr(exposure, "ufw_active", lambda: True)
    (f,) = exposure.run(ctx)
    assert f.check == "docker-ufw-bypass" and "web:8080" in f.evidence["published"] and "db" not in f.evidence["published"]
