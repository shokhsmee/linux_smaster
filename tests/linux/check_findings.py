"""Assert that `guardian audit --json` reports every planted condition.

Usage: check_findings.py first <audit.json>   # after plant.sh
       check_findings.py second <audit.json>  # after mutate.sh
"""

from __future__ import annotations

import json
import sys


def load(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def findings(report: dict) -> list[dict]:
    return [f | {"module": m["module"]} for m in report["modules"] for f in m["findings"]]


def expect(fs: list[dict], module: str, check: str, severity: str, **evidence) -> dict:
    for f in fs:
        if f["module"] != module or f["check"] != check:
            continue
        if all(f["evidence"].get(k) == v for k, v in evidence.items()):
            if f["severity"] != severity:
                fail(f"{module}/{check} {evidence}: severity {f['severity']!r}, expected {severity!r}")
            print(f"  ok  {module}/{check} [{severity}] {f['title']}")
            return f
    fail(f"missing finding {module}/{check} [{severity}] {evidence}")


def fail(msg: str) -> None:
    print("  FAIL", msg)
    FAILURES.append(msg)


FAILURES: list[str] = []


def common_checks(fs: list[dict]) -> None:
    expect(fs, "exposure", "exposed-service", "critical", port=11434, auth="no-auth")
    expect(fs, "secrets", "secret-in-file", "critical", path="/home/test/.env", kind="OpenAI key", world_readable=True)
    expect(fs, "secrets", "secret-in-file", "critical", path="/home/test/app/docker-compose.yml", kind="Anthropic key")
    expect(fs, "secrets", "secret-in-process-env", "critical", kind="OpenAI key")
    expect(fs, "persistence", "suspicious-command", "high", path="/etc/cron.d/evil")
    expect(fs, "persistence", "ld-preload", "critical")
    expect(fs, "ssh_guard", "sshd-config", "high", option="passwordauthentication", value="yes")
    expect(fs, "ssh_guard", "brute-force", "medium", ip="45.33.32.156")


def main() -> int:
    phase, path = sys.argv[1], sys.argv[2]
    report = load(path)
    print(f"== {phase} audit: score {report['score']}")
    for m in report["modules"]:
        if m["error"]:
            fail(f"module {m['module']} crashed:\n{m['error']}")
        if m["skipped"]:
            fail(f"module {m['module']} skipped: {m['skipped']}")
    fs = findings(report)
    common_checks(fs)
    baseline = [f for f in fs if f["module"] == "persistence" and f["check"] == "baseline"]
    if phase == "first":
        if not baseline:
            fail("first run should create the persistence baseline")
        else:
            print(f"  ok  persistence/baseline: {baseline[0]['title']}")
    else:
        if baseline:
            fail("second run re-created the persistence baseline instead of diffing it")
        expect(fs, "persistence", "modified-file", "medium", path="/etc/cron.d/evil")
        expect(fs, "persistence", "new-file", "medium", path="/etc/cron.d/evil2")
        expect(fs, "persistence", "suspicious-command", "high", path="/etc/cron.d/evil2")
    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s)")
        return 1
    print("all expected findings present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
