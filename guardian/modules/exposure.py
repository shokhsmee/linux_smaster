"""M1 Exposure scanner.

Finds services listening on public interfaces, with a profile of AI/dev tools
that are commonly deployed without authentication (Ollama, Ray, Jupyter, MCP
servers, vector databases, ...). Where it can, it probes the service locally to
confirm that it answers without credentials. It also checks whether Docker is
publishing ports that bypass a host firewall (UFW).
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

import httpx
import psutil

from ..models import Finding, Severity
from ..utils import have, is_private_ip
from ..utils import run as sh
from . import Context

NAME = "exposure"


@dataclass(frozen=True)
class ServiceProfile:
    name: str
    severity: Severity
    fix: str
    # HTTP probe: path and a regex that must match the body of a 200 response
    # for the service to count as "open without auth".
    probe_path: str | None = None
    probe_match: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)


# Port -> profile. Severity is for the service being reachable on a public
# interface; a confirmed no-auth probe bumps it to CRITICAL.
PROFILES: dict[int, ServiceProfile] = {
    # --- AI / ML tooling ----------------------------------------------------
    11434: ServiceProfile("Ollama API", Severity.HIGH,
        "Bind Ollama to 127.0.0.1 (OLLAMA_HOST=127.0.0.1) or put it behind a reverse proxy with auth; upgrade to >=0.17.1.",
        "/api/tags", r'"models"', ("ai",)),
    8265: ServiceProfile("Ray dashboard (ShadowRay)", Severity.CRITICAL,
        "Ray has no auth by design (CVE-2023-48022). Firewall port 8265/10001 and run Ray only on a private network.",
        "/api/version", r'"ray_version"', ("ai",)),
    10001: ServiceProfile("Ray client server", Severity.CRITICAL,
        "Ray has no auth by design. Restrict to private network / VPN.", None, None, ("ai",)),
    8888: ServiceProfile("Jupyter", Severity.HIGH,
        "Require a token/password (c.ServerApp.token) and bind to localhost or use HTTPS + auth proxy.",
        "/api", r'"version"', ("ai",)),
    7860: ServiceProfile("Gradio / Langflow / Stable Diffusion WebUI", Severity.HIGH,
        "Enable auth (Gradio auth=, Langflow LANGFLOW_AUTO_LOGIN=false) and bind to localhost; Langflow <1.3.0 is in CISA KEV (CVE-2025-3248).",
        "/api/v1/version", r'"version"', ("ai",)),
    8188: ServiceProfile("ComfyUI", Severity.HIGH,
        "ComfyUI has no auth; bind to 127.0.0.1 and front it with an authenticating proxy.",
        "/system_stats", r'"system"', ("ai",)),
    3000: ServiceProfile("Open WebUI / Grafana / dev server", Severity.MEDIUM,
        "Confirm the service requires login; bind dev servers to localhost.",
        "/api/config", r'"name"', ("ai", "dev")),
    6333: ServiceProfile("Qdrant", Severity.HIGH,
        "Set an API key (QDRANT__SERVICE__API_KEY) and bind to a private interface.",
        "/collections", r'"result"', ("ai", "db")),
    19530: ServiceProfile("Milvus", Severity.HIGH,
        "Enable Milvus authentication and restrict network access.", None, None, ("ai", "db")),
    8000: ServiceProfile("Chroma / FastAPI app", Severity.MEDIUM,
        "Chroma has no auth by default (CHROMA_SERVER_AUTHN_PROVIDER); bind to localhost.",
        "/api/v1/heartbeat", r'heartbeat', ("ai", "db")),
    5000: ServiceProfile("MLflow / Flask app", Severity.MEDIUM,
        "MLflow has no auth by default; use the basic-auth app or a proxy.",
        "/api/2.0/mlflow/experiments/search", r'"experiments"', ("ai",)),
    6274: ServiceProfile("MCP Inspector UI", Severity.CRITICAL,
        "MCP Inspector <0.14.1 allows RCE (CVE-2025-49596). Never expose it; upgrade.",
        "/", r'MCP Inspector', ("ai", "mcp")),
    6277: ServiceProfile("MCP Inspector proxy", Severity.CRITICAL,
        "Never expose the Inspector proxy (CVE-2025-49596).", None, None, ("ai", "mcp")),
    18789: ServiceProfile("OpenClaw gateway", Severity.CRITICAL,
        "OpenClaw <2026.1.29 is remotely hijackable (CVE-2026-25253); bind to localhost and upgrade.",
        "/", r'OpenClaw|openclaw', ("ai",)),
    3001: ServiceProfile("Flowise", Severity.HIGH,
        "Set FLOWISE_USERNAME/PASSWORD; many exposed instances leak credentials.",
        "/api/v1/chatflows", r'\[', ("ai",)),
    5678: ServiceProfile("n8n", Severity.MEDIUM,
        "Ensure owner account/auth is set up and bind behind a proxy.",
        "/rest/settings", r'"data"', ("ai", "dev")),
    8080: ServiceProfile("HTTP app (Open WebUI / proxies / dev)", Severity.LOW,
        "Confirm the app requires authentication.", "/api/config", r'"name"', ("dev",)),
    # --- classic high-risk admin services ------------------------------------
    2375: ServiceProfile("Docker API (unencrypted)", Severity.CRITICAL,
        "Never expose the Docker socket over TCP without TLS; remove -H tcp://0.0.0.0:2375.",
        "/version", r'"ApiVersion"', ("infra",)),
    2376: ServiceProfile("Docker API (TLS)", Severity.HIGH,
        "Verify client certificate verification (tlsverify) is on.", None, None, ("infra",)),
    6443: ServiceProfile("Kubernetes API", Severity.HIGH,
        "Restrict API server access; check anonymous-auth is disabled.", None, None, ("infra",)),
    10250: ServiceProfile("Kubelet", Severity.CRITICAL,
        "Kubelet must not be public; set --anonymous-auth=false and firewall it.",
        "/pods", r'"items"', ("infra",)),
    2379: ServiceProfile("etcd", Severity.CRITICAL,
        "etcd holds cluster secrets; require client certs and firewall it.", None, None, ("infra",)),
    6379: ServiceProfile("Redis", Severity.CRITICAL,
        "Set requirepass / ACLs, bind 127.0.0.1, enable protected-mode.", None, None, ("db",)),
    27017: ServiceProfile("MongoDB", Severity.CRITICAL,
        "Enable authorization and bindIp 127.0.0.1.", None, None, ("db",)),
    5432: ServiceProfile("PostgreSQL", Severity.HIGH,
        "Bind to localhost / private network; review pg_hba.conf.", None, None, ("db",)),
    3306: ServiceProfile("MySQL/MariaDB", Severity.HIGH,
        "Bind to localhost; disable remote root.", None, None, ("db",)),
    9200: ServiceProfile("Elasticsearch/OpenSearch", Severity.CRITICAL,
        "Enable security plugin / auth; never expose unauthenticated.",
        "/", r'"cluster_name"', ("db",)),
    11211: ServiceProfile("Memcached", Severity.HIGH,
        "Bind to localhost; memcached has no auth and is a DDoS amplifier.", None, None, ("db",)),
    631: ServiceProfile("CUPS", Severity.HIGH,
        "CUPS browsing/IPP exposure enabled RCE in 2024; disable cups-browsed and bind to localhost.", None, None, ("infra",)),
    5900: ServiceProfile("VNC", Severity.HIGH,
        "Tunnel VNC over SSH/VPN; never expose directly.", None, None, ("infra",)),
    8086: ServiceProfile("InfluxDB", Severity.MEDIUM, "Enable auth.", None, None, ("db",)),
    15672: ServiceProfile("RabbitMQ management", Severity.MEDIUM,
        "Change default guest credentials; firewall.", None, None, ("infra",)),
    9000: ServiceProfile("Portainer / MinIO / PHP-FPM", Severity.MEDIUM,
        "Confirm auth and bind to localhost.", None, None, ("infra",)),
    # --- proxies: an open relay gets your IP used for IRC/mining/abuse traffic ---
    1080: ServiceProfile("SOCKS proxy (microsocks/dante/ssh -D)", Severity.HIGH,
        "Require auth (microsocks -u USER -P PASS), bind to 127.0.0.1 or a VPN interface, and firewall port 1080. Open SOCKS proxies are found and abused within hours.",
        "socks5", None, ("proxy",)),
    3128: ServiceProfile("HTTP proxy (squid/tinyproxy)", Severity.HIGH,
        "Restrict with ACLs/auth and firewall; open HTTP proxies are abused for spam and attacks.", None, None, ("proxy",)),
    8118: ServiceProfile("Privoxy", Severity.HIGH, "Bind to 127.0.0.1 (listen-address).", None, None, ("proxy",)),
    9050: ServiceProfile("Tor SOCKS", Severity.HIGH, "Bind Tor SocksPort to 127.0.0.1.", "socks5", None, ("proxy",)),
    # --- common app servers that should sit behind a reverse proxy ------------
    8069: ServiceProfile("Odoo", Severity.MEDIUM,
        "Put Odoo behind nginx/TLS (proxy_mode = True) and bind to 127.0.0.1 (http_interface).", "/web/login", r"odoo", ("app",)),
}
UDP_INFO_PROFILES: dict[int, tuple[str, Severity, str]] = {
    5353: ("mDNS/Avahi", Severity.LOW, "Avahi is for LAN discovery and has no place on an internet server: apt remove avahi-daemon (or firewall udp/5353)."),
    111: ("rpcbind", Severity.MEDIUM, "rpcbind is a DDoS amplifier and NFS attack surface; remove or firewall it."),
    161: ("SNMP", Severity.MEDIUM, "Change community strings, use SNMPv3, firewall udp/161."),
    1900: ("SSDP/UPnP", Severity.MEDIUM, "SSDP is a DDoS amplifier; disable it on servers."),
}

SAFE_PUBLIC_PORTS = {22, 80, 443, 25, 465, 587, 993, 995, 53}


@dataclass
class Listener:
    proto: str
    ip: str
    port: int
    pid: int | None
    process: str
    user: str = ""


def listeners() -> list[Listener]:
    out: list[Listener] = []
    seen: set[tuple[str, str, int]] = set()
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        conns = []
    for c in conns:
        if not c.laddr:
            continue
        is_tcp = c.type == 1  # SOCK_STREAM
        if is_tcp and c.status != psutil.CONN_LISTEN:
            continue
        if not is_tcp and c.status != psutil.CONN_NONE:
            continue
        ip, port = c.laddr.ip, c.laddr.port
        key = ("tcp" if is_tcp else "udp", ip, port)
        if key in seen:
            continue
        seen.add(key)
        pname = user = ""
        if c.pid:
            try:
                proc = psutil.Process(c.pid)
                pname, user = proc.name(), proc.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = user = ""
        out.append(Listener(key[0], ip, port, c.pid, pname, user))
    return out


def probe_socks5(port: int, timeout: float) -> bool | None:
    """SOCKS5 handshake offering only 'no authentication'. A server that
    accepts it (reply 05 00) is an open proxy."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            reply = s.recv(2)
    except OSError:
        return None
    if reply == b"\x05\x00":
        return True
    if reply[:1] == b"\x05":
        return False  # 05 ff: no acceptable method -> auth required
    return None


def is_public_bind(ip: str) -> bool:
    # Detection string compared against a socket table; nothing is bound here.
    if ip in ("0.0.0.0", "::", ""):  # nosec B104
        return True
    return not is_private_ip(ip)


def probe(port: int, profile: ServiceProfile, timeout: float) -> bool | None:
    """Return True if the service answered without auth, False if it demanded
    auth, None if it could not be probed."""
    if not profile.probe_path:
        return None
    if profile.probe_path == "socks5":
        return probe_socks5(port, timeout)
    url = f"http://127.0.0.1:{port}{profile.probe_path}"
    try:
        r = httpx.get(url, timeout=timeout, follow_redirects=False,
                      headers={"User-Agent": "guardian-probe"})
    except httpx.HTTPError:
        return None
    if r.status_code in (401, 403) or (300 <= r.status_code < 400 and "login" in r.headers.get("location", "")):
        return False
    if r.status_code == 200 and profile.probe_match and re.search(profile.probe_match, r.text[:4000]):
        return True
    return None


def docker_published_ports() -> list[tuple[str, str, int]]:
    """Return (container, host_ip, host_port) for published ports."""
    if not have("docker"):
        return []
    rc, out, _ = sh(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"], timeout=10)
    if rc != 0:
        return []
    result = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, ports = line.split("\t", 1)
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+|\[?::\]?):(\d+)->", ports):
            result.append((name, m.group(1).strip("[]"), int(m.group(2))))
    return result


def ufw_active() -> bool:
    if not have("ufw"):
        return False
    rc, out, _ = sh(["ufw", "status"], timeout=10)
    return rc == 0 and "Status: active" in out


def run(ctx: Context) -> list[Finding]:
    cfg = ctx.config.exposure
    findings: list[Finding] = []
    public = [l for l in listeners() if is_public_bind(l.ip)]

    for l in public:
        profile = PROFILES.get(l.port)
        if profile is None:
            if l.port in SAFE_PUBLIC_PORTS:
                continue
            if l.proto == "udp" and l.port in UDP_INFO_PROFILES:
                name, usev, ufix = UDP_INFO_PROFILES[l.port]
                findings.append(Finding(module=NAME, check="exposed-service", severity=usev,
                                        title=f"{name} on udp/{l.port} is bound to {l.ip}", fix=ufix,
                                        evidence={"port": l.port, "proto": l.proto, "pid": l.pid, "process": l.process, "service": name}))
                continue
            if l.proto == "udp" and l.port >= 32768:
                continue  # ephemeral client sockets (avahi, DNS resolvers) are not services
            as_root = l.user == "root" and l.port > 1024
            findings.append(Finding(
                module=NAME, check="public-listener", severity=Severity.LOW if as_root else Severity.INFO,
                title=f"{l.proto}/{l.port} ({l.process or 'unknown'}) listens on {l.ip}" + (" as root" if as_root else ""),
                detail="Unknown service on a public interface. Confirm it is meant to be reachable from the internet."
                       + (" It runs as root: any bug in it is a root compromise." if as_root else ""),
                fix="Bind to 127.0.0.1 behind a reverse proxy, or restrict with the firewall." + (" Run it as a dedicated user." if as_root else ""),
                evidence={"port": l.port, "proto": l.proto, "pid": l.pid, "process": l.process, "user": l.user},
            ))
            continue

        sev = profile.severity
        auth_state = "unknown"
        if cfg.probe_http and l.proto == "tcp":
            res = probe(l.port, profile, cfg.probe_timeout)
            if res is True:
                sev = Severity.CRITICAL
                auth_state = "no-auth"
            elif res is False:
                auth_state = "auth-required"
                sev = Severity.MEDIUM if sev.rank > Severity.MEDIUM.rank else sev

        title = f"{profile.name} on {l.proto}/{l.port} is bound to {l.ip}"
        if auth_state == "no-auth":
            title += " and answers WITHOUT authentication"
        if "proxy" in profile.tags and auth_state != "auth-required":
            sev = Severity.CRITICAL  # an open relay is actively abused, not merely exposed
        findings.append(Finding(
            module=NAME, check="exposed-service", severity=sev, title=title,
            detail=f"Process: {l.process or 'unknown'} (pid {l.pid}, user {l.user or '?'}). Tags: {', '.join(profile.tags)}. Auth probe: {auth_state}.",
            fix=profile.fix,
            evidence={"port": l.port, "proto": l.proto, "pid": l.pid, "process": l.process,
                      "auth": auth_state, "service": profile.name},
        ))

    # Docker publishing ports on all interfaces silently bypasses UFW rules.
    published = [(n, ip, p) for n, ip, p in docker_published_ports() if is_public_bind(ip)]
    if published and ufw_active():
        ports = ", ".join(f"{n}:{p}" for n, _, p in published)
        findings.append(Finding(
            module=NAME, check="docker-ufw-bypass", severity=Severity.HIGH,
            title="Docker publishes ports on 0.0.0.0 while UFW is active (UFW does not filter them)",
            detail=f"Published: {ports}. Docker inserts its own iptables rules ahead of UFW, so these ports are reachable regardless of UFW.",
            fix="Publish to 127.0.0.1 (-p 127.0.0.1:PORT:PORT) or add rules in the DOCKER-USER chain / use ufw-docker.",
            evidence={"published": ports},
        ))
    return findings

