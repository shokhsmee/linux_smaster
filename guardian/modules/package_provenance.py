"""M10 Package provenance (installed packages).

Checks what is already installed in project directories on the host:
  * artifacts of known npm worms (Shai-Hulud, s1ngularity, 0x2ai) and wiper
    lines appended to shell rc files
  * install hooks (preinstall/postinstall) in node_modules that download or
    decode-and-execute code
  * installed npm / PyPI package names one typo away from a popular package
    (typosquats and registered AI hallucinations)
  * missing lockfiles and npm configured to run lifecycle scripts

Registry checks for a package *before* installing it live in
`guardian check-package`.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..models import Finding, Severity
from ..popular import KNOWN_SLOPSQUATS
from ..registry import normalize, typosquat_candidates
from ..utils import have, read_text
from . import Context

NAME = "package_provenance"
CONFIG_KEY = "packages"

WORM_ARTIFACTS = {
    "setup_bun.js": "Shai-Hulud 2.0 loader", "bun_environment.js": "Shai-Hulud 2.0 payload",
    "shai-hulud-workflow.yml": "Shai-Hulud GitHub Actions backdoor", "shai-hulud.yaml": "Shai-Hulud workflow",
    "results.b64": "s1ngularity/Shai-Hulud secrets dump", "cloud.json": None, "truffleSecrets.json": "Shai-Hulud TruffleHog output",
    "actionsSecrets.json": "Shai-Hulud secrets dump", "environment.json": None, "contents.json": None,
    "telemetry.js": None, "processor.sh": "0x2ai / npm postinstall dropper", "CLEANER.LOG": "Amazon Q wiper prompt log",
}
WORM_ARTIFACTS = {k: v for k, v in WORM_ARTIFACTS.items() if v}
RC_WIPER = re.compile(r"sudo\s+shutdown|shutdown\s+-h\s+now|rm\s+-rf\s+(~|\$HOME|/home)|s1ngularity|shai-hulud", re.I)
HOOK_SUSPICIOUS = re.compile(
    r"(curl|wget)\b[^&;|]*\|\s*(ba|da)?sh|base64\s+(-d|--decode)|node\s+-e\s+[\"']?(require\(['\"](https?|child_process)['\"]\)|eval)|"
    r"eval\s*\(\s*(atob|Buffer\.from|unescape|String\.fromCharCode)|\bbun\s+(run\s+)?setup_bun|powershell|/dev/tcp/|\.onion|"
    r"new\s+Function\(|fromCharCode\(\s*\d+\s*,|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.I)
MAX_PACKAGES = 6000


def _homes_and_roots(extra: list[str]) -> list[Path]:
    roots = [Path("/root"), Path("/srv"), Path("/opt"), Path("/var/www")]
    if Path("/home").is_dir():
        roots += [h for h in Path("/home").iterdir() if h.is_dir()]
    roots += [Path(r) for r in extra]
    return [r for r in roots if r.is_dir()]


def find_projects(roots: list[Path], depth: int = 4) -> tuple[list[Path], list[Path]]:
    """Return (node project dirs, python site-packages dirs)."""
    node: list[Path] = []
    py: list[Path] = []
    for root in roots:
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            p = Path(dirpath)
            if len(p.parts) - base_depth >= depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", ".cache", "snap", ".local") and not d.startswith(".npm")]
            if "package.json" in filenames and (p / "node_modules").is_dir():
                node.append(p)
            if p.name == "site-packages":
                py.append(p)
            if p.name in (".venv", "venv", "env"):
                for sp in p.glob("lib/python*/site-packages"):
                    py.append(sp)
                dirnames[:] = []
    return node, py


def scan_worm_artifacts(roots: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    targets = [Path("/tmp/CLEANER.LOG")]
    for root in roots:
        for fn, label in WORM_ARTIFACTS.items():
            try:
                for p in list(root.rglob(fn))[:20]:
                    if "node_modules" in p.parts and fn in ("cloud.json", "environment.json"):
                        continue
                    targets.append(p)
                    findings.append(Finding(module=NAME, check="worm-artifact", severity=Severity.CRITICAL,
                                            title=f"{label} artifact found: {p}",
                                            fix="Assume every token on this host is stolen: rotate npm/GitHub/cloud/AI keys, remove the package, check GitHub for repos named 'Shai-Hulud' or 's1ngularity-repository'.",
                                            evidence={"path": str(p), "family": label}))
            except OSError:
                continue
    for home in [r for r in roots if r.parent.name == "home" or r.name == "root"]:
        for rc in (".bashrc", ".zshrc", ".profile", ".bash_profile"):
            text = read_text(home / rc, limit=65536) or ""
            m = RC_WIPER.search(text)
            if m:
                findings.append(Finding(module=NAME, check="rc-wiper-line", severity=Severity.CRITICAL,
                                        title=f"Destructive line in {home / rc}: '{m.group(0)}'",
                                        fix="Shai-Hulud appends shutdown/wipe commands to shell rc files when it cannot steal credentials. Remove the line and treat the host as compromised.",
                                        evidence={"path": str(home / rc), "match": m.group(0)}))
    return findings


def scan_node_modules(project: Path, budget: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    nm = project / "node_modules"
    pkg_jsons: list[Path] = []
    try:
        for entry in nm.iterdir():
            if entry.name.startswith("@") and entry.is_dir():
                pkg_jsons += [e / "package.json" for e in entry.iterdir() if (e / "package.json").is_file()]
            elif (entry / "package.json").is_file():
                pkg_jsons.append(entry / "package.json")
    except OSError:
        return findings
    for pj in pkg_jsons:
        if budget[0] <= 0:
            break
        budget[0] -= 1
        try:
            data = json.loads(pj.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        name = str(data.get("name", pj.parent.name))
        scripts = data.get("scripts") or {}
        for hook in ("preinstall", "install", "postinstall"):
            cmd = str(scripts.get(hook, ""))
            if cmd and HOOK_SUSPICIOUS.search(cmd):
                findings.append(Finding(module=NAME, check="suspicious-install-hook", severity=Severity.HIGH,
                                        title=f"npm package {name} has a suspicious {hook} hook: '{cmd[:60]}'",
                                        fix="Install hooks run as you on every `npm install`. Remove the package; set `npm config set ignore-scripts true`.",
                                        evidence={"package": name, "hook": hook, "cmd": cmd[:200], "path": str(pj)}))
        for fn in ("setup_bun.js", "bun_environment.js"):
            if (pj.parent / fn).exists():
                findings.append(Finding(module=NAME, check="worm-artifact", severity=Severity.CRITICAL,
                                        title=f"Shai-Hulud 2.0 file {fn} inside npm package {name}",
                                        fix="Remove the package and rotate all credentials on the host.", evidence={"package": name, "path": str(pj.parent / fn)}))
        squats = typosquat_candidates(name, "npm")
        if squats and name not in data.get("dependencies", {}) :
            findings.append(Finding(module=NAME, check="possible-typosquat", severity=Severity.MEDIUM,
                                    title=f"Installed npm package '{name}' is one typo from {', '.join(squats[:2])}",
                                    fix="Confirm you meant this package (AI-suggested names are often hallucinated). `guardian check-package npm NAME` for registry details.",
                                    evidence={"package": name, "similar": ", ".join(squats[:3]), "path": str(pj)}))
    return findings


def scan_site_packages(sp: Path, budget: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        dists = [d for d in sp.iterdir() if d.name.endswith(".dist-info")]
    except OSError:
        return findings
    for d in dists:
        if budget[0] <= 0:
            break
        budget[0] -= 1
        name = d.name[: -len(".dist-info")].rsplit("-", 1)[0]
        if normalize(name) in {normalize(x) for x in KNOWN_SLOPSQUATS["pypi"]}:
            findings.append(Finding(module=NAME, check="known-slopsquat", severity=Severity.CRITICAL,
                                    title=f"Installed PyPI package '{name}' is a documented AI-hallucinated name that was later registered",
                                    fix="Uninstall it and inspect what it did; it was never the package you wanted.", evidence={"package": name, "path": str(d)}))
            continue
        squats = typosquat_candidates(name, "pypi")
        if squats:
            findings.append(Finding(module=NAME, check="possible-typosquat", severity=Severity.MEDIUM,
                                    title=f"Installed PyPI package '{name}' is one typo from {', '.join(squats[:2])}",
                                    fix="Confirm this is the intended package; run `guardian check-package pypi NAME`.",
                                    evidence={"package": name, "similar": ", ".join(squats[:3]), "path": str(d)}))
    return findings


def hygiene(projects: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    if have("npm"):
        npmrc_ok = False
        for p in (Path.home() / ".npmrc", Path("/etc/npmrc"), Path("/root/.npmrc")):
            if re.search(r"^\s*ignore-scripts\s*=\s*true", read_text(p) or "", re.M | re.I):
                npmrc_ok = True
        if not npmrc_ok:
            findings.append(Finding(module=NAME, check="npm-scripts-enabled", severity=Severity.LOW,
                                    title="npm runs lifecycle scripts on install (ignore-scripts not set)",
                                    fix="`npm config set ignore-scripts true` on servers/CI; run needed builds explicitly. Blocks the Shai-Hulud/0x2ai postinstall vector."))
    for p in projects:
        if not any((p / lf).exists() for lf in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")):
            findings.append(Finding(module=NAME, check="no-lockfile", severity=Severity.LOW,
                                    title=f"Node project without a lockfile: {p}",
                                    fix="Commit a lockfile and install with `npm ci` so a hijacked release cannot slip in silently.", evidence={"path": str(p)}))
    return findings


def run(ctx: Context) -> list[Finding]:
    cfg = ctx.config.packages
    roots = _homes_and_roots(cfg.extra_roots)
    findings = scan_worm_artifacts(roots)
    node, py = find_projects(roots, cfg.project_depth)
    budget = [MAX_PACKAGES]
    for p in node:
        findings += scan_node_modules(p, budget)
    for sp in py:
        findings += scan_site_packages(sp, budget)
    findings += hygiene(node)
    return findings
