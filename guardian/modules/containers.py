"""Container configuration & image secrets (Phase 3 extension of M8).

Uses the Docker/Podman CLI to inspect running containers and local images for
secrets baked into ENV or build history, dangerous host access (privileged,
docker.sock, host PID/network, sensitive bind mounts, added capabilities),
containers running as root, and unpinned `latest` images.
"""

from __future__ import annotations

import json

from ..models import Finding, Severity
from ..utils import have, run as sh
from . import Context
from .secrets import scan_text

NAME = "containers"
CONFIG_KEY = "containers"

SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/home", "/var/run/docker.sock", "/run/docker.sock", "/proc", "/sys", "/boot", "/dev", "/var/lib/docker")
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH", "SYS_RAWIO", "BPF"}


def _cli() -> str | None:
    for c in ("docker", "podman"):
        if have(c):
            return c
    return None


def _inspect(cli: str, ids: list[str]) -> list[dict]:
    if not ids:
        return []
    rc, out, _ = sh([cli, "inspect"] + ids, timeout=60)
    if rc != 0:
        return []
    try:
        data = json.loads(out)
        return data if isinstance(data, list) else [data]
    except ValueError:
        return []


def running_containers(cli: str) -> list[dict]:
    rc, out, _ = sh([cli, "ps", "-q"], timeout=30)
    return _inspect(cli, out.split()) if rc == 0 else []


def local_images(cli: str) -> list[dict]:
    rc, out, _ = sh([cli, "images", "-q", "--no-trunc"], timeout=30)
    ids = list(dict.fromkeys(out.split()))[:200]
    return _inspect(cli, ids) if rc == 0 else []


def image_history(cli: str, image_id: str) -> str:
    rc, out, _ = sh([cli, "history", "--no-trunc", "--format", "{{.CreatedBy}}", image_id], timeout=30)
    return out if rc == 0 else ""


def analyze_container(c: dict) -> list[Finding]:
    findings: list[Finding] = []
    name = (c.get("Name") or "").lstrip("/") or c.get("Id", "")[:12]
    cfg = c.get("Config") or {}
    hc = c.get("HostConfig") or {}
    image = cfg.get("Image", "")
    ev = {"container": name, "image": image}

    for kind, sev, masked in scan_text("\n".join(cfg.get("Env") or [])):
        if kind == "Generic password assignment":
            sev = Severity.LOW
        findings.append(Finding(module=NAME, check="secret-in-container-env", severity=sev,
                                title=f"{kind} in environment of container {name}",
                                detail=f"Value starts with {masked}. `docker inspect` exposes it to anyone in the docker group.",
                                fix="Use Docker secrets / mounted 0600 files or a secrets manager; rotate the key.", evidence=ev | {"kind": kind, "masked": masked}))

    if hc.get("Privileged"):
        findings.append(Finding(module=NAME, check="privileged-container", severity=Severity.HIGH,
                                title=f"Container {name} runs --privileged (full host access)",
                                fix="Drop --privileged; add only the capabilities the workload needs.", evidence=ev))
    for b in hc.get("Binds") or []:
        src = b.split(":", 1)[0]
        if src in SENSITIVE_MOUNTS or src.startswith(("/etc/", "/root/", "/var/lib/docker")):
            sev = Severity.CRITICAL if "docker.sock" in src or src == "/" else Severity.HIGH
            findings.append(Finding(module=NAME, check="sensitive-host-mount", severity=sev,
                                    title=f"Container {name} mounts host path {src}",
                                    fix="docker.sock or / inside a container equals root on the host (and is what PCPJack looks for). Use a socket proxy or remove the mount.",
                                    evidence=ev | {"bind": b}))
    for m in c.get("Mounts") or []:
        if m.get("Type") == "bind" and m.get("Source") in ("/var/run/docker.sock", "/run/docker.sock") and not any("docker.sock" in b for b in hc.get("Binds") or []):
            findings.append(Finding(module=NAME, check="sensitive-host-mount", severity=Severity.CRITICAL,
                                    title=f"Container {name} mounts the Docker socket", fix="Remove or proxy the socket mount.", evidence=ev))
    if hc.get("NetworkMode") == "host":
        findings.append(Finding(module=NAME, check="host-namespace", severity=Severity.MEDIUM,
                                title=f"Container {name} uses the host network namespace", fix="Use a bridge network and publish only needed ports.", evidence=ev))
    if hc.get("PidMode") == "host":
        findings.append(Finding(module=NAME, check="host-namespace", severity=Severity.HIGH,
                                title=f"Container {name} shares the host PID namespace", fix="Remove --pid=host; it allows ptrace/credential theft from host processes.", evidence=ev))
    caps = {str(x).removeprefix("CAP_") for x in hc.get("CapAdd") or []}
    bad = caps & DANGEROUS_CAPS
    if bad:
        findings.append(Finding(module=NAME, check="dangerous-capability", severity=Severity.HIGH,
                                title=f"Container {name} adds capabilities {', '.join(sorted(bad))}", fix="SYS_ADMIN/SYS_PTRACE/BPF/NET_ADMIN allow container escape or host tampering; drop them.", evidence=ev | {"caps": ", ".join(sorted(bad))}))
    if not cfg.get("User") and not hc.get("UsernsMode"):
        findings.append(Finding(module=NAME, check="container-runs-as-root", severity=Severity.LOW,
                                title=f"Container {name} runs as root inside the container",
                                fix="Set USER in the Dockerfile or `--user`, or enable userns-remap.", evidence=ev))
    if image.endswith(":latest") or (":" not in image and "@" not in image):
        findings.append(Finding(module=NAME, check="unpinned-image", severity=Severity.LOW,
                                title=f"Container {name} runs unpinned image {image}", fix="Pin by tag + digest so a hijacked 'latest' cannot be pulled silently.", evidence=ev))
    return findings


def analyze_image(img: dict, history: str) -> list[Finding]:
    findings: list[Finding] = []
    tags = img.get("RepoTags") or [img.get("Id", "")[:19]]
    label = tags[0]
    cfg = img.get("Config") or {}
    ev = {"image": label}
    for kind, sev, masked in scan_text("\n".join(cfg.get("Env") or [])):
        if kind == "Generic password assignment":
            sev = Severity.LOW
        findings.append(Finding(module=NAME, check="secret-in-image-env", severity=sev,
                                title=f"{kind} baked into ENV of image {label}",
                                detail=f"Value starts with {masked}. Anyone who pulls or inspects the image gets it (Flare: ~4,000 AI keys in Docker Hub images).",
                                fix="Never put secrets in ENV/ARG; inject at runtime; rotate and rebuild.", evidence=ev | {"kind": kind, "masked": masked}))
    for kind, sev, masked in scan_text(history):
        if kind == "Generic password assignment":
            continue
        findings.append(Finding(module=NAME, check="secret-in-image-history", severity=sev,
                                title=f"{kind} in build history of image {label}",
                                detail=f"Value starts with {masked}. Build ARG/RUN lines are stored in every layer's metadata.",
                                fix="Use BuildKit secret mounts (--mount=type=secret) and rebuild from scratch; rotate the key.", evidence=ev | {"kind": kind, "masked": masked}))
    return findings


def run(ctx: Context) -> list[Finding]:
    cli = _cli()
    if cli is None:
        return []
    cfg = ctx.config.containers
    findings: list[Finding] = []
    for c in running_containers(cli):
        findings += analyze_container(c)
    if cfg.scan_images:
        for img in local_images(cli)[: cfg.max_images]:
            findings += analyze_image(img, image_history(cli, img.get("Id", "")) if cfg.scan_history else "")
    return findings
