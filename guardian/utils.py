"""Small helpers shared by modules."""

from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path


def is_linux() -> bool:
    return platform.system() == "Linux"


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a command without a shell; never raises on non-zero exit."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def read_text(path: str | Path, limit: int | None = None) -> str | None:
    try:
        p = Path(path)
        if limit is None:
            return p.read_text(errors="replace")
        with p.open("rb") as fh:
            return fh.read(limit).decode(errors="replace")
    except OSError:
        return None


def detect_distro() -> dict[str, str]:
    info: dict[str, str] = {}
    text = read_text("/etc/os-release") or ""
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip('"')
    return info


def is_private_ip(ip: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local
