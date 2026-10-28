import os

from guardian.models import Severity
from guardian.modules import secrets


def test_detects_ai_keys_and_masks():
    text = (
        "OPENAI_API_KEY=sk-proj-" + "A" * 48 + "\n"
        "ANTHROPIC_API_KEY=sk-ant-api03-" + "b" * 90 + "\n"
        "HF_TOKEN=hf_" + "c" * 34 + "\n"
        "AWS_ACCESS_KEY_ID=AKIA" + "D" * 16 + "\n"
    )
    hits = secrets.scan_text(text)
    kinds = {k for k, _, _ in hits}
    assert {"OpenAI key", "Anthropic key", "Hugging Face token", "AWS access key"} <= kinds
    for _, sev, masked in hits:
        assert "…" in masked and len(masked) < 12  # never the full value
    assert all(sev.rank >= Severity.HIGH.rank for k, sev, _ in hits if k != "Generic password assignment")


def test_placeholders_ignored():
    assert secrets.scan_text("DB_PASSWORD=changeme123\nSECRET=${SECRET}\nTOKEN=your_token_here") == []
    hits = secrets.scan_text("DB_PASSWORD=Sup3rS3cretValue!!")
    assert hits and hits[0][0] == "Generic password assignment" and hits[0][1] == Severity.LOW


def test_file_scan_and_world_readable(ctx, tmp_path):
    home = tmp_path / "home" / "alice"
    home.mkdir(parents=True)
    env = home / ".env"
    env.write_text("OPENAI_API_KEY=sk-proj-" + "Z" * 48 + "\n")
    os.chmod(env, 0o644)
    (home / "node_modules").mkdir()
    (home / "node_modules" / ".env").write_text("OPENAI_API_KEY=sk-proj-" + "Q" * 48 + "\n")
    ctx.config.secrets.paths = [str(tmp_path / "home")]
    ctx.config.secrets.scan_proc_environ = False
    findings = secrets.run(ctx)
    paths = [f.evidence["path"] for f in findings]
    assert str(env) in paths
    assert not any("node_modules" in p for p in paths)
    fnd = next(f for f in findings if f.evidence["path"] == str(env))
    assert fnd.severity == Severity.CRITICAL and fnd.evidence["world_readable"] is True
    assert "Z" * 10 not in fnd.title + fnd.detail  # masked
