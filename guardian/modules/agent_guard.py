"""M9 AI agent guard.

AI coding agents (Claude Code, Codex, Gemini CLI, Cursor, aider, OpenCode)
and MCP servers are a new class of process: they execute shell commands on
behalf of whatever text they read. This module inventories them, flags
permission-bypass flags (especially when launched by a package install
script, as the s1ngularity and 0x2ai attacks did), checks whether they run as
root or unsandboxed, watches their config files for injected MCP servers or
hooks, and notices when an agent process has credential files open.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import psutil

from ..models import Finding, Severity
from ..utils import read_text
from . import Context

NAME = "agent_guard"
CONFIG_KEY = "agents"

AGENT_NAMES = {
    "claude": "Claude Code", "codex": "OpenAI Codex", "gemini": "Gemini CLI", "aider": "aider", "opencode": "OpenCode",
    "cursor": "Cursor", "cursor-agent": "Cursor agent", "copilot": "GitHub Copilot CLI", "goose": "Goose",
    "amazon-q": "Amazon Q", "q": "Amazon Q", "cline": "Cline", "continue": "Continue", "openhands": "OpenHands",
    "crush": "Crush", "amp": "Amp", "kiro": "Kiro", "openclaw": "OpenClaw",
}
AGENT_CMD_HINTS = re.compile(r"(?:^|/)(claude|codex|gemini|aider|opencode|cursor-agent|copilot|goose|cline|openhands|amp|kiro|openclaw)(?:\s|$)|@anthropic-ai/claude-code|@openai/codex|@google/gemini-cli")
MCP_HINT = re.compile(r"mcp[-_]?server|mcp-remote|modelcontextprotocol|--mcp|mcp\.json|mcp_server", re.I)
BYPASS_FLAGS = re.compile(
    r"--dangerously-skip-permissions|--yolo|--trust-all-tools|--full-auto|--dangerously-bypass-approvals-and-sandbox|"
    r"--approval-mode\s*=?\s*(yolo|auto_edit)|--no-sandbox|--sandbox\s+danger-full-access|--auto-approve|-y\b.*--yolo|--allow-all|"
    r"--permission-mode\s+bypassPermissions|--skip-permissions|--auto-run|--no-confirm", re.I)
INSTALLER_PARENTS = {"npm", "npx", "bun", "pnpm", "yarn", "node", "pip", "pip3", "uv", "python", "python3", "sh", "dash", "bash"}
INSTALLER_CHAIN = {"npm", "npx", "bun", "pnpm", "yarn", "pip", "pip3", "uv"}
CRED_PATHS = (".ssh/", ".aws/", ".gnupg/", ".config/gcloud/", ".azure/", ".kube/config", ".docker/config.json", ".netrc", ".git-credentials", "/etc/shadow")

CONFIG_FILES = (
    ".claude/settings.json", ".claude/settings.local.json", ".claude.json", ".mcp.json", ".cursor/mcp.json",
    ".codex/config.toml", ".gemini/settings.json", ".config/claude/settings.json", ".continue/config.json",
    ".config/goose/config.yaml", ".kiro/settings/mcp.json", ".vscode/mcp.json", ".config/opencode/opencode.json",
    ".openclaw/config.json",
)
INSTRUCTION_FILES = ("CLAUDE.md", "GEMINI.md", "AGENTS.md", ".cursorrules", ".cursor/rules", ".github/copilot-instructions.md", ".windsurfrules", ".clinerules")

SUSPICIOUS_IN_CONFIG = re.compile(
    r"(curl|wget)[^\"\n]*\|\s*(ba)?sh|base64\s+(-d|--decode)|/dev/tcp/|\bnc\s+-e|python[23]?\s+-c\s+['\"]import\s+socket|"
    r"eval\s*\(|\$\(\s*curl|/tmp/[^\s\"]+\.(sh|py|js)|\.onion\b|pastebin\.com|transfer\.sh|ngrok|\bchmod\s+\+x\s+/tmp", re.I)
SUSPICIOUS_IN_INSTRUCTIONS = re.compile(
    r"ignore (all )?(previous|prior|above) instructions|do not (tell|inform|mention)( this)? to the user|without (asking|telling) the user|"
    r"(curl|wget)[^\n]*\|\s*(ba)?sh|base64\s+-d|--dangerously-skip-permissions|cat\s+~/\.ssh|~/\.aws/credentials|/etc/shadow|"
    r"\bexfil|send (the )?(keys|secrets|credentials|tokens) to|upload .* to (http|pastebin)|hidden instruction|<!--[^>]*(run|execute|curl)", re.I)


def _cmdline(p: psutil.Process) -> str:
    try:
        return " ".join(p.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ""


def _ancestors(p: psutil.Process, depth: int = 6) -> list[str]:
    names: list[str] = []
    cur = p
    for _ in range(depth):
        try:
            cur = cur.parent()
            if cur is None:
                break
            names.append(cur.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
    return names


def _sandboxed(pid: int, ancestors: list[str]) -> bool:
    if any(a in ("bwrap", "srt", "sandbox-runtime", "firejail", "nsjail", "landrun", "nono") for a in ancestors):
        return True
    status = read_text(f"/proc/{pid}/status") or ""
    seccomp = re.search(r"^Seccomp:\s*(\d)", status, re.M)
    nnp = re.search(r"^NoNewPrivs:\s*(\d)", status, re.M)
    return bool(seccomp and seccomp.group(1) == "2" and nnp and nnp.group(1) == "1")


def _open_cred_files(pid: int) -> list[str]:
    hits: list[str] = []
    fd_dir = Path(f"/proc/{pid}/fd")
    try:
        for fd in fd_dir.iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if any(c in target for c in CRED_PATHS):
                hits.append(target)
    except OSError:
        pass
    return hits


def agent_processes() -> list[dict]:
    out: list[dict] = []
    for p in psutil.process_iter(["pid", "name", "username"]):
        try:
            name = p.info["name"] or ""
            cmd = _cmdline(p)
            is_agent = name in AGENT_NAMES or bool(AGENT_CMD_HINTS.search(cmd))
            is_mcp = bool(MCP_HINT.search(cmd)) and not is_agent
            if not (is_agent or is_mcp):
                continue
            anc = _ancestors(p)
            out.append({
                "pid": p.pid, "name": name, "label": AGENT_NAMES.get(name) or ("MCP server" if is_mcp else name),
                "cmd": cmd, "user": p.info["username"] or "", "ancestors": anc, "kind": "mcp" if is_mcp else "agent",
                "bypass": bool(BYPASS_FLAGS.search(cmd)), "sandboxed": _sandboxed(p.pid, anc),
                "cred_files": _open_cred_files(p.pid),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return out


def analyze_processes(procs: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for a in procs:
        ev = {"pid": a["pid"], "name": a["name"], "user": a["user"], "cmd": a["cmd"][:200], "ancestors": " < ".join(a["ancestors"][:4])}
        label = f"{a['label']} (pid {a['pid']})"
        from_installer = any(x in INSTALLER_CHAIN for x in a["ancestors"])
        if a["bypass"] and from_installer:
            findings.append(Finding(module=NAME, check="agent-launched-by-installer", severity=Severity.CRITICAL,
                                    title=f"{label} started by a package installer with permission bypass flags",
                                    detail=a["cmd"][:300], fix="This is the s1ngularity/0x2ai supply-chain pattern (postinstall runs an AI CLI with --dangerously-skip-permissions). Kill it, find the package, rotate every key on the host.", evidence=ev))
        elif a["bypass"]:
            findings.append(Finding(module=NAME, check="agent-bypass-flags", severity=Severity.HIGH if a["user"] == "root" else Severity.MEDIUM,
                                    title=f"{label} runs with permission bypass flags as {a['user'] or '?'}",
                                    detail=a["cmd"][:300], fix="Any prompt injection in files/web pages it reads becomes command execution. Run it under a sandbox (srt/bwrap) as an unprivileged user without cloud credentials.", evidence=ev))
        elif from_installer and a["kind"] == "agent":
            findings.append(Finding(module=NAME, check="agent-launched-by-installer", severity=Severity.HIGH,
                                    title=f"{label} was started from a package install chain ({ev['ancestors']})",
                                    fix="Package install scripts should never run AI agents. Investigate the package.", evidence=ev))
        if a["user"] == "root" and a["kind"] == "agent":
            findings.append(Finding(module=NAME, check="agent-as-root", severity=Severity.HIGH,
                                    title=f"{label} is running as root", fix="Run agents as a dedicated unprivileged user; never give them root.", evidence=ev))
        if a["cred_files"]:
            findings.append(Finding(module=NAME, check="agent-reads-credentials", severity=Severity.HIGH,
                                    title=f"{label} has credential files open: {', '.join(a['cred_files'][:3])}",
                                    fix="Agents should not touch ~/.ssh, ~/.aws, etc. Revoke those credentials if this was not you.", evidence=ev | {"files": ", ".join(a["cred_files"][:5])}))
        if not a["sandboxed"] and a["kind"] == "agent" and not a["bypass"]:
            findings.append(Finding(module=NAME, check="agent-unsandboxed", severity=Severity.LOW,
                                    title=f"{label} runs without a sandbox (no bwrap/srt/seccomp detected)",
                                    fix="Use Anthropic sandbox-runtime (srt), bubblewrap or Landlock-based wrappers to limit filesystem and network.", evidence=ev))
    return findings


# --- config files ------------------------------------------------------------

def _homes() -> list[Path]:
    homes = [Path("/root")]
    if Path("/home").is_dir():
        homes += [h for h in Path("/home").iterdir() if h.is_dir()]
    return homes


def config_targets(extra_roots: list[str], project_depth: int = 3) -> list[Path]:
    targets: list[Path] = []
    roots = _homes() + [Path(r) for r in extra_roots]
    for root in roots:
        for rel in CONFIG_FILES + INSTRUCTION_FILES:
            p = root / rel
            if p.is_file():
                targets.append(p)
            elif p.is_dir():
                targets += [s for s in p.rglob("*") if s.is_file()]
        # project-level files a few levels down (repos under the home dir)
        for rel in (".mcp.json", ".cursor/mcp.json", ".claude/settings.json", ".claude/settings.local.json", ".vscode/mcp.json") + INSTRUCTION_FILES:
            name = Path(rel).name
            try:
                for p in root.rglob(name):
                    if len(p.relative_to(root).parts) <= project_depth + len(Path(rel).parts) and p.is_file() and "node_modules" not in p.parts:
                        targets.append(p)
            except OSError:
                continue
    return list(dict.fromkeys(targets))


def inspect_config(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    ev = {"path": str(path)}
    name = path.name
    if name in INSTRUCTION_FILES or path.suffix == ".md" or name in (".cursorrules", ".windsurfrules", ".clinerules") or "rules" in path.parts:
        m = SUSPICIOUS_IN_INSTRUCTIONS.search(text)
        if m:
            findings.append(Finding(module=NAME, check="instruction-injection", severity=Severity.HIGH,
                                    title=f"Prompt-injection pattern in {path}: '{m.group(0)[:50]}'",
                                    fix="Agent instruction files are executed as intent. Remove the text; check git blame / package postinstall for who wrote it.", evidence=ev | {"match": m.group(0)[:100]}))
        return findings

    m = SUSPICIOUS_IN_CONFIG.search(text)
    if m:
        findings.append(Finding(module=NAME, check="config-suspicious-command", severity=Severity.CRITICAL,
                                title=f"Download-and-execute pattern in agent config {path}: '{m.group(0)[:50]}'",
                                fix="MCP server/hook commands run with the agent's privileges on every start. Remove and investigate.", evidence=ev | {"match": m.group(0)[:100]}))

    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except ValueError:
            return findings
        if isinstance(data, dict):
            servers = data.get("mcpServers") or data.get("servers") or {}
            if isinstance(servers, dict):
                for sname, s in servers.items():
                    if not isinstance(s, dict):
                        continue
                    cmd = " ".join([str(s.get("command", ""))] + [str(a) for a in s.get("args", [])])
                    url = str(s.get("url", ""))
                    if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                        findings.append(Finding(module=NAME, check="mcp-plaintext-remote", severity=Severity.MEDIUM,
                                                title=f"MCP server '{sname}' in {path} uses plaintext http to {url[:60]}",
                                                fix="Use https; tool definitions over http can be tampered with in transit (tool poisoning).", evidence=ev | {"server": sname, "url": url[:120]}))
                    if re.search(r"\bnpx\b.*\s-y\b|\buvx\b|\bbunx\b", cmd) and "@latest" in cmd:
                        findings.append(Finding(module=NAME, check="mcp-unpinned-package", severity=Severity.LOW,
                                                title=f"MCP server '{sname}' runs an unpinned package: {cmd[:60]}",
                                                fix="Pin MCP server package versions; a hijacked release becomes code execution on every agent start.", evidence=ev | {"server": sname, "cmd": cmd[:120]}))
                    env = s.get("env") or {}
                    if isinstance(env, dict):
                        for k, v in env.items():
                            if re.search(r"KEY|TOKEN|SECRET|PASSWORD", k, re.I) and isinstance(v, str) and len(v) > 16 and not v.startswith("$"):
                                findings.append(Finding(module=NAME, check="mcp-config-secret", severity=Severity.MEDIUM,
                                                        title=f"MCP server '{sname}' config embeds a secret in {k}",
                                                        fix="Reference secrets via environment variables instead of inline values; this file is often committed or world-readable.", evidence=ev | {"server": sname, "key": k}))
            perms = data.get("permissions") or {}
            allow = perms.get("allow") if isinstance(perms, dict) else None
            if isinstance(allow, list) and any(re.fullmatch(r"Bash(\(\*?\))?|Bash\(\*:\*\)|\*", str(a)) for a in allow):
                findings.append(Finding(module=NAME, check="agent-permissions-wide-open", severity=Severity.MEDIUM,
                                        title=f"{path} allows unrestricted Bash for the agent",
                                        fix="Allow specific commands (Bash(git *), Bash(npm test)) rather than Bash(*).", evidence=ev))
            if str(data.get("defaultMode", "")).lower() in ("bypasspermissions", "dontask") or data.get("skipDangerousPermissionCheck"):
                findings.append(Finding(module=NAME, check="agent-permissions-wide-open", severity=Severity.MEDIUM,
                                        title=f"{path} sets a permission-bypass default mode", fix="Remove defaultMode bypass; use per-command allow lists.", evidence=ev))
            hooks = data.get("hooks") or {}
            if hooks and SUSPICIOUS_IN_CONFIG.search(json.dumps(hooks)):
                findings.append(Finding(module=NAME, check="agent-hook-suspicious", severity=Severity.HIGH,
                                        title=f"Agent hook in {path} contains a download/execute pattern", fix="Hooks run on every tool call; inspect and remove.", evidence=ev))
    return findings


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode(errors="replace")).hexdigest()[:16]


def run(ctx: Context) -> list[Finding]:
    cfg = ctx.config.agents
    findings: list[Finding] = []
    if Path("/proc").is_dir():
        findings += analyze_processes(agent_processes())

    baseline: dict[str, str] = ctx.store.get("agent_config_baseline") or {}
    current: dict[str, str] = {}
    first_run = not baseline
    for p in config_targets(cfg.extra_roots):
        text = read_text(p, limit=256 * 1024)
        if text is None:
            continue
        current[str(p)] = _digest(text)
        findings += inspect_config(p, text)
        try:
            if p.stat().st_mode & 0o004 and (p.suffix == ".json" or p.name == ".claude.json"):
                findings.append(Finding(module=NAME, check="agent-config-world-readable", severity=Severity.LOW,
                                        title=f"Agent config {p} is world-readable", fix="chmod 600; these files often hold API keys and OAuth tokens.", evidence={"path": str(p)}))
        except OSError:
            pass
        if not first_run:
            old = baseline.get(str(p))
            if old is None:
                findings.append(Finding(module=NAME, check="agent-config-new", severity=Severity.MEDIUM,
                                        title=f"New agent config/instruction file: {p}",
                                        fix="Attackers plant .mcp.json / CLAUDE.md to hijack the next agent run (0x2ai npm packages). Verify who created it.", evidence={"path": str(p)}))
            elif old != current[str(p)]:
                findings.append(Finding(module=NAME, check="agent-config-changed", severity=Severity.MEDIUM,
                                        title=f"Agent config/instruction file changed: {p}", fix="Diff against git/backup; look for added MCP servers, hooks or instructions.", evidence={"path": str(p)}))
    if first_run and current:
        findings.append(Finding(module=NAME, check="baseline", severity=Severity.INFO,
                                title=f"Agent config baseline recorded for {len(current)} files", evidence={"files": len(current)}))
    if current != baseline:
        ctx.store.set("agent_config_baseline", current)
    return findings
