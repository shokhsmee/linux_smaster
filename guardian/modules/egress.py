"""M11 Egress monitor.

Looks at outbound connections per process for the destinations malware and
hijacked agents talk to: mining pools (stratum ports), IRC command-and-control,
Telegram/Discord/pastebin-style exfil channels from daemons, LLM API hosts used
by processes that are not known AI tools (LLM-enabled malware, LLMjacking),
and worm-style scanning (one process touching many hosts on admin ports).
"""

from __future__ import annotations

import socket
from collections import defaultdict
from dataclasses import dataclass

import psutil

from ..models import Finding, Severity
from ..utils import is_private_ip
from . import Context

NAME = "egress"
CONFIG_KEY = "egress"

STRATUM_PORTS = {3333, 3334, 3335, 3336, 4444, 5555, 5556, 7777, 8888, 9999, 14444, 14433, 45560, 45700, 10001, 10002, 2222, 20535}
IRC_PORTS = {6667, 6668, 6669, 6697, 7000}
SCAN_PORTS = {22, 23, 2375, 2376, 6379, 27017, 8265, 10250, 11434, 5432, 3306, 9200, 445, 3389}
EXFIL_HOST_HINTS = ("api.telegram.org", "discord.com", "discordapp.com", "pastebin.com", "transfer.sh", "ngrok", "file.io",
                    "anonfiles", "gofile.io", "oast.", "interact.sh", "burpcollaborator", "requestbin", "webhook.site", "pipedream")
LLM_HOST_HINTS = ("api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
                  "huggingface.co", "api.groq.com", "openrouter.ai", "api.mistral.ai", "api.together.xyz", "api.deepseek.com",
                  "bedrock-runtime", "api.cohere.ai", "api.x.ai", "api.perplexity.ai", "api.replicate.com", "api.fireworks.ai")
KNOWN_AI_PROCS = {"claude", "codex", "gemini", "aider", "opencode", "cursor", "cursor-agent", "copilot", "goose", "ollama", "python", "python3",
                  "node", "uvicorn", "gunicorn", "litellm", "open-webui", "langflow", "n8n", "openclaw", "bun", "deno"}
INTERACTIVE_OR_BROWSER = {"firefox", "chrome", "chromium", "curl", "wget", "ssh", "git", "apt", "apt-get", "dnf", "yum", "snapd", "telegram-desktop", "discord"}


PROXY_PORTS = {1080, 3128, 8118, 9050, 8888, 8080}


@dataclass
class Conn:
    pid: int | None
    name: str
    user: str
    raddr: str
    rport: int
    status: str
    lport: int = 0


def connections() -> list[Conn]:
    out: list[Conn] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return out
    cache: dict[int, tuple[str, str]] = {}
    for c in conns:
        if not c.raddr or c.status not in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT):
            continue
        ip, port = c.raddr.ip, c.raddr.port
        if is_private_ip(ip):
            continue
        name = user = ""
        if c.pid:
            if c.pid not in cache:
                try:
                    p = psutil.Process(c.pid)
                    cache[c.pid] = (p.name(), p.username())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cache[c.pid] = ("", "")
            name, user = cache[c.pid]
        out.append(Conn(c.pid, name, user, ip, port, c.status, c.laddr.port if c.laddr else 0))
    return out


def reverse_dns(ips: set[str], timeout: float = 1.0, limit: int = 60) -> dict[str, str]:
    names: dict[str, str] = {}
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for ip in list(ips)[:limit]:
            try:
                names[ip] = socket.gethostbyaddr(ip)[0].lower()
            except (socket.herror, socket.gaierror, OSError):
                names[ip] = ""
    finally:
        socket.setdefaulttimeout(old)
    return names


def analyze(conns: list[Conn], names: dict[str, str], scan_threshold: int = 15) -> list[Finding]:
    findings: list[Finding] = []
    per_proc: dict[tuple[int | None, str], list[Conn]] = defaultdict(list)
    for c in conns:
        per_proc[(c.pid, c.name)].append(c)

    # Inbound clients of a proxy port: sockets accepted by a proxy (or with no
    # owning process at all) that come from many public addresses mean the
    # host is being used as an open relay.
    inbound: dict[int, set[str]] = defaultdict(set)
    for c in conns:
        if c.lport in PROXY_PORTS and c.rport > 1024:
            inbound[c.lport].add(c.raddr)
    for lport, clients in inbound.items():
        if len(clients) >= 2 or len([c for c in conns if c.lport == lport]) >= scan_threshold:
            findings.append(Finding(module=NAME, check="open-relay-clients", severity=Severity.CRITICAL, key=f"lport:{lport}",
                                    title=f"{len([c for c in conns if c.lport == lport])} connections from {len(clients)} public address(es) are relaying through local port {lport}",
                                    fix="This looks like an open proxy being abused. Stop the proxy service (or add auth and bind it to localhost) and firewall the port.",
                                    evidence={"lport": lport, "clients": ", ".join(sorted(clients)[:5])}))
    # Sockets accepted on a proxy port are the relay's inbound side, not this
    # host's own egress: skip them so the relay is reported once, above.
    conns = [c for c in conns if c.lport not in inbound]
    per_proc = defaultdict(list)
    for c in conns:
        per_proc[(c.pid, c.name)].append(c)

    for (pid, pname), cs in per_proc.items():
        label = f"{pname or 'unknown'} (pid {pid})" if pid else "socket with no owning process (kernel/proxied)"
        base_ev = {"pid": pid, "process": pname}
        for c in cs:
            host = names.get(c.raddr, "")
            ev = base_ev | {"remote": f"{c.raddr}:{c.rport}", "host": host, "user": c.user}
            if c.rport in STRATUM_PORTS and pname not in INTERACTIVE_OR_BROWSER:
                findings.append(Finding(module=NAME, check="mining-pool-port", severity=Severity.HIGH,
                                        title=f"{label} connected to {c.raddr}:{c.rport} (common mining-pool port)",
                                        fix="Verify the process; if it is a miner, kill it, remove its persistence and check how it got in.", evidence=ev))
            elif c.rport in IRC_PORTS:
                findings.append(Finding(module=NAME, check="irc-c2", severity=Severity.HIGH,
                                        title=f"{label} connected to IRC port {c.rport} at {c.raddr}",
                                        fix="IRC is the C2 of Outlaw/Gafgyt-style botnets. Investigate the process.", evidence=ev))
            if host and any(h in host for h in EXFIL_HOST_HINTS) and pname not in INTERACTIVE_OR_BROWSER:
                findings.append(Finding(module=NAME, check="exfil-channel", severity=Severity.MEDIUM,
                                        title=f"{label} talks to {host} (common exfil/C2 channel)",
                                        fix="Confirm it is an intended integration (e.g. your own Telegram alerts). Otherwise treat as data theft.", evidence=ev))
            if host and any(h in host for h in LLM_HOST_HINTS) and pname not in KNOWN_AI_PROCS and pname not in INTERACTIVE_OR_BROWSER:
                findings.append(Finding(module=NAME, check="llm-api-unexpected-process", severity=Severity.MEDIUM,
                                        title=f"{label} is calling an LLM API ({host})",
                                        fix="LLM-enabled malware (PROMPTSTEAL/PromptLock) and LLMjacking proxies call model APIs from unexpected binaries. Verify the process and which key it uses.", evidence=ev))
        # worm-style scanning: many distinct hosts on admin ports
        targets = {c.raddr for c in cs if c.rport in SCAN_PORTS}
        if len(targets) >= scan_threshold:
            findings.append(Finding(module=NAME, check="outbound-scanning", severity=Severity.CRITICAL,
                                    title=f"{label} has connections to {len(targets)} hosts on admin ports (SSH/Docker/Redis/K8s...)",
                                    fix="This host is scanning others: PCPJack/P2PInfect-style worm behaviour. Isolate it now.", evidence=base_ev | {"targets": len(targets)}))
    return findings


def run(ctx: Context) -> list[Finding]:
    cfg = ctx.config.egress
    conns = connections()
    if not conns:
        return []
    names = reverse_dns({c.raddr for c in conns}, cfg.dns_timeout) if cfg.reverse_dns else {}
    return analyze(conns, names, cfg.scan_threshold)
