"""M8 Secrets-on-host scanner.

Looks for leaked AI and cloud API keys where they end up on real servers:
.env files, compose/Dockerfiles, shell history, CI configs, AI agent config
directories (~/.claude, .mcp.json, ~/.config), and process environments.
Also flags secret-bearing files that other users can read.

Values are never printed in full; findings carry a masked prefix only.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from ..models import Finding, Severity
from . import Context

NAME = "secrets"

# name -> (regex, severity). Patterns favour precision over recall.
PATTERNS: dict[str, tuple[re.Pattern[str], Severity]] = {
    "OpenAI key": (re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-(?:proj-)?[A-Za-z0-9]{48}\b"), Severity.CRITICAL),
    "Anthropic key": (re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b"), Severity.CRITICAL),
    "Google API key": (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH),
    "Hugging Face token": (re.compile(r"\bhf_[A-Za-z0-9]{34}\b"), Severity.HIGH),
    "Groq key": (re.compile(r"\bgsk_[A-Za-z0-9]{52}\b"), Severity.HIGH),
    "Mistral/Together style key": (re.compile(r"(?i)\b(?:MISTRAL|TOGETHER|OPENROUTER)_API_KEY\s*[=:]\s*['\"]?([A-Za-z0-9_-]{32,})"), Severity.HIGH),
    "OpenRouter key": (re.compile(r"\bsk-or-v1-[a-f0-9]{64}\b"), Severity.HIGH),
    "Replicate token": (re.compile(r"\br8_[A-Za-z0-9]{37}\b"), Severity.HIGH),
    "AWS access key": (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    "AWS secret key": (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), Severity.CRITICAL),
    "GitHub token": (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{80,}\b"), Severity.HIGH),
    "GitLab token": (re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b"), Severity.HIGH),
    "Slack token": (re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    "Stripe live key": (re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"), Severity.CRITICAL),
    "Telegram bot token": (re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), Severity.MEDIUM),
    "Private key block": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), Severity.HIGH),
    "Generic password assignment": (re.compile(r"(?im)^\s*(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN)[A-Z0-9_]*)\s*=\s*['\"]?([^\s'\"#]{8,})"), Severity.LOW),
}

# Files and directories we always look at, relative to each home directory.
HOME_TARGETS = (
    ".env", ".bash_history", ".zsh_history", ".python_history", ".npmrc", ".pypirc",
    ".netrc", ".git-credentials", ".docker/config.json", ".aws/credentials", ".config/gcloud",
    ".azure", ".claude", ".claude.json", ".mcp.json", ".cursor/mcp.json", ".codex", ".gemini",
    ".config/github-copilot", ".continue", ".openai", ".anthropic", ".ollama", ".config/gh/hosts.yml",
)

NAME_HINTS = re.compile(
    r"(^|/)(\.env(\..+)?|.*\.env|docker-compose.*\.ya?ml|compose\.ya?ml|Dockerfile.*|\.mcp\.json|mcp\.json|"
    r"settings(\.local)?\.json|credentials(\.json)?|config\.(json|ya?ml|toml)|.*\.pem|.*\.key|id_(rsa|ed25519|ecdsa)|"
    r"\.npmrc|\.pypirc|\.netrc|\.git-credentials|.*_history|secrets?\.(ya?ml|json|txt)|\.github/workflows/.*\.ya?ml)$"
)

SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".so", ".o",
            ".pyc", ".whl", ".jar", ".class", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".db", ".sqlite"}


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:6] + "…" + value[-2:]


def scan_text(text: str) -> list[tuple[str, Severity, str]]:
    hits: list[tuple[str, Severity, str]] = []
    for name, (rx, sev) in PATTERNS.items():
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() and m.group(1) else m.group(0)
            if name == "Generic password assignment" and _looks_like_placeholder(val):
                continue
            hits.append((name, sev, mask(val)))
            if len(hits) > 50:
                return hits
    return hits


def _looks_like_placeholder(val: str) -> bool:
    v = val.lower()
    return any(w in v for w in ("changeme", "example", "your_", "xxxx", "placeholder", "<", "${", "dummy", "test")) or v in ("password", "secret")


def _should_scan(path: Path, max_bytes: int) -> bool:
    if path.suffix.lower() in SKIP_EXT:
        return False
    try:
        st = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes or st.st_size == 0:
        return False
    return bool(NAME_HINTS.search(str(path)))


def candidate_files(roots: list[str], max_bytes: int, exclude: list[str], limit: int = 20000) -> list[Path]:
    out: list[Path] = []
    seen_homes: set[Path] = set()
    for root in roots:
        r = Path(root)
        if not r.exists():
            continue
        # Home-directory targets (explicit, even if the name hints miss them)
        homes = [r] if r.name in ("root",) else [p for p in r.iterdir() if p.is_dir()] if r.name == "home" else []
        for h in homes:
            if h in seen_homes:
                continue
            seen_homes.add(h)
            for t in HOME_TARGETS:
                p = h / t
                if p.is_file():
                    out.append(p)
                elif p.is_dir():
                    for sub in p.rglob("*"):
                        if sub.is_file() and sub.suffix.lower() not in SKIP_EXT:
                            try:
                                if sub.stat().st_size <= max_bytes:
                                    out.append(sub)
                            except OSError:
                                pass
        for dirpath, dirnames, filenames in os.walk(r, followlinks=False):
            here = Path(dirpath)
            # Never prune the home directories themselves: a user called
            # "test", "build" or "sample" still gets their files scanned.
            if not (r.name == "home" and here == r):
                dirnames[:] = [d for d in dirnames if d not in exclude]
            for fn in filenames:
                p = here / fn
                if _should_scan(p, max_bytes):
                    out.append(p)
            if len(out) >= limit:
                return list(dict.fromkeys(out))
    return list(dict.fromkeys(out))


def file_world_readable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & stat.S_IROTH)
    except OSError:
        return False


def scan_proc_environ() -> list[tuple[int, str, str, Severity, str]]:
    hits = []
    proc = Path("/proc")
    if not proc.is_dir():
        return hits
    for p in proc.iterdir():
        if not p.name.isdigit():
            continue
        try:
            env = (p / "environ").read_bytes().decode(errors="replace").replace("\0", "\n")
            comm = (p / "comm").read_text().strip()
        except OSError:
            continue
        for name, sev, masked in scan_text(env):
            if name == "Generic password assignment":
                continue
            hits.append((int(p.name), comm, name, sev, masked))
    return hits


def run(ctx: Context) -> list[Finding]:
    cfg = ctx.config.secrets
    findings: list[Finding] = []
    files = candidate_files(cfg.paths, cfg.max_file_kb * 1024, cfg.exclude_dirs)

    for f in files:
        try:
            text = f.read_bytes().decode(errors="replace")
        except OSError:
            continue
        hits = scan_text(text)
        if not hits:
            continue
        world = file_world_readable(f)
        for name, sev, masked in hits[:5]:
            if world and Severity.LOW.rank < sev.rank < Severity.HIGH.rank:
                sev = Severity.HIGH  # a real key readable by every local user
            findings.append(Finding(
                module=NAME, check="secret-in-file", severity=sev,
                title=f"{name} in {f}" + (" (world-readable)" if world else ""),
                detail=f"Value starts with {masked}. Keys found on disk are the first thing credential-stealing worms (PCPJack, Shai-Hulud) grab.",
                fix="Rotate the key (deleting the file is not enough), move it to a secrets manager or root-only file, chmod 600.",
                evidence={"path": str(f), "kind": name, "masked": masked, "world_readable": world},
            ))

    if cfg.scan_proc_environ:
        for pid, comm, name, sev, masked in scan_proc_environ():
            findings.append(Finding(
                module=NAME, check="secret-in-process-env", severity=Severity.MEDIUM if sev.rank < Severity.HIGH.rank else sev,
                title=f"{name} in environment of {comm} (pid {pid})",
                detail=f"Value starts with {masked}. Any code execution in this process (or /proc read by the same user) exposes it.",
                fix="Prefer file-based secrets with 0600 perms or a secrets manager; avoid passing keys via environment to long-running services.",
                evidence={"pid": pid, "process": comm, "kind": name, "masked": masked},
            ))
    return findings
