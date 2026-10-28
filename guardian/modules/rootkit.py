"""M6 Rootkit cross-check.

Instead of signature lists (rkhunter/chkrootkit are unmaintained), this looks
for the *inconsistencies* a rootkit creates:
  * PIDs that exist in /proc but are hidden from directory listings
  * new or unexpected eBPF programs (VoidLink, ShadowGuard, Atomic Arch)
  * new kernel modules and an unsigned/out-of-tree taint
  * setuid-root binaries whose page-cache content differs from disk
    (the Copy Fail CVE-2026-31431 technique that hash-based FIM cannot see)
  * LD_PRELOAD injected through environment files
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import re
import stat
from pathlib import Path

from ..models import Finding, Severity
from ..utils import have, read_text
from ..utils import run as sh
from . import Context

NAME = "rootkit"
CONFIG_KEY = "rootkit"

SUID_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib/openssh", "/usr/lib/policykit-1", "/usr/libexec", "/usr/lib/dbus-1.0")
TAINT_BITS = {12: "out-of-tree module (O)", 13: "unsigned module (E)", 0: "proprietary module (P)", 4: "firmware bug", 10: "kernel warning (W)", 11: "staging driver (C)"}


# --- hidden PIDs -------------------------------------------------------------

def listed_pids() -> set[int]:
    try:
        return {int(n) for n in os.listdir("/proc") if n.isdigit()}
    except OSError:
        return set()


def probed_pids(limit: int) -> set[int]:
    """Brute-force /proc/N/stat; a hooked getdents can hide a PID from
    listdir but stat() on the exact path usually still succeeds."""
    found: set[int] = set()
    for pid in range(1, limit + 1):
        try:
            os.stat(f"/proc/{pid}/stat")
            found.add(pid)
        except OSError:
            continue
    return found


def hidden_pids(limit: int) -> list[int]:
    listed = listed_pids()
    if not listed:
        return []
    return sorted(pid for pid in probed_pids(limit) - listed if _is_real_process(pid))


def _is_real_process(pid: int) -> bool:
    # Threads of listed processes show up in /proc/<tid>/ too; skip those.
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("Tgid:"):
                    return int(line.split()[1]) == pid
    except OSError:
        return False
    return False


# --- eBPF programs -----------------------------------------------------------

def bpf_programs() -> list[dict] | None:
    if not have("bpftool"):
        return None
    rc, out, _ = sh(["bpftool", "prog", "list", "-j"], timeout=15)
    if rc != 0:
        return None
    try:
        progs = json.loads(out)
    except ValueError:
        return None
    return [{"id": p.get("id"), "type": p.get("type"), "name": p.get("name", ""), "pids": [x.get("comm") for x in p.get("pids", [])]} for p in progs]


# --- kernel modules ----------------------------------------------------------

def loaded_modules() -> dict[str, int]:
    text = read_text("/proc/modules") or ""
    mods: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            mods[parts[0]] = int(parts[2]) if parts[2].isdigit() else 0
    return mods


def taint_flags() -> list[str]:
    text = (read_text("/proc/sys/kernel/tainted") or "0").strip()
    try:
        val = int(text)
    except ValueError:
        return []
    return [desc for bit, desc in TAINT_BITS.items() if val & (1 << bit)]


# --- page cache vs disk for setuid binaries ------------------------------------

def _sha_direct(path: str) -> str | None:
    """Hash the on-disk bytes bypassing the page cache (O_DIRECT)."""
    if not hasattr(os, "O_DIRECT"):
        return None
    try:
        size = os.stat(path).st_size
        fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
    except OSError:
        return None
    try:
        align = 4096
        buf = mmap.mmap(-1, max(align, ((size + align - 1) // align) * align))
        h = hashlib.sha256()
        total = 0
        while total < size:
            n = os.readv(fd, [memoryview(buf)[: len(buf)]])
            if n <= 0:
                break
            take = min(n, size - total)
            h.update(buf[:take])
            total += take
        return h.hexdigest() if total == size else None
    except OSError:
        return None
    finally:
        os.close(fd)


def _sha_cached(path: str) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def setuid_binaries() -> list[str]:
    out: list[str] = []
    for d in SUID_DIRS:
        dp = Path(d)
        if not dp.is_dir():
            continue
        for p in dp.iterdir():
            try:
                st = p.stat()
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_ISUID and st.st_uid == 0 and st.st_size < 50 * 1024 * 1024:
                out.append(str(p))
    return out


def page_cache_mismatches(paths: list[str]) -> list[str]:
    bad: list[str] = []
    for p in paths:
        a, b = _sha_cached(p), _sha_direct(p)
        if a and b and a != b:
            bad.append(p)
    return bad


# --- LD_PRELOAD via env files ------------------------------------------------

def preload_in_env_files() -> list[str]:
    hits: list[str] = []
    candidates = ["/etc/environment", "/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"] + [str(p) for p in Path("/etc/profile.d").glob("*") if Path("/etc/profile.d").is_dir()]
    for home in [Path("/root")] + ([h for h in Path("/home").iterdir() if h.is_dir()] if Path("/home").is_dir() else []):
        candidates += [str(home / f) for f in (".bashrc", ".profile", ".bash_profile", ".zshrc", ".pam_environment")]
    for c in candidates:
        text = read_text(c, limit=65536) or ""
        if re.search(r"^\s*(export\s+)?LD_PRELOAD\s*=", text, re.M):
            hits.append(c)
    return hits


def run(ctx: Context) -> list[Finding]:
    if not Path("/proc").is_dir():
        return [Finding(module=NAME, check="unsupported", severity=Severity.INFO, title="rootkit checks need /proc (Linux only)")]
    cfg = ctx.config.rootkit
    findings: list[Finding] = []

    for pid in hidden_pids(cfg.pid_probe_limit):
        comm = (read_text(f"/proc/{pid}/comm") or "?").strip()
        findings.append(Finding(module=NAME, check="hidden-pid", severity=Severity.CRITICAL,
                                title=f"PID {pid} ({comm}) is hidden from /proc listing",
                                fix="Process hiding = rootkit (eBPF getdents hook or LKM). Isolate the host and capture memory before rebooting.",
                                evidence={"pid": pid, "comm": comm}))

    progs = bpf_programs()
    if progs is not None:
        old = ctx.store.get("bpf_baseline")
        current = {f"{p['type']}:{p['name']}" for p in progs}
        if old is None:
            ctx.store.set("bpf_baseline", sorted(current))
        else:
            new = current - set(old)
            for key in sorted(new):
                ptype, pname = key.split(":", 1)
                sev = Severity.HIGH if ptype in ("kprobe", "tracepoint", "raw_tracepoint", "tracing", "lsm", "sched_cls", "xdp") else Severity.MEDIUM
                findings.append(Finding(module=NAME, check="new-bpf-program", severity=sev,
                                        title=f"New eBPF program loaded: {pname or '(unnamed)'} [{ptype}]",
                                        fix="Legit sources: Falco/Tetragon/Cilium/systemd. Otherwise an eBPF rootkit; `bpftool prog dump xlated id N` to inspect.",
                                        evidence={"type": ptype, "name": pname}))
            if new:
                ctx.store.set("bpf_baseline", sorted(current))
    else:
        findings.append(Finding(module=NAME, check="bpf-visibility", severity=Severity.INFO,
                                title="bpftool not installed: eBPF programs cannot be inventoried",
                                fix="apt install bpftool (linux-tools) so Guardian can baseline eBPF programs."))

    mods = loaded_modules()
    if mods:
        old_mods = ctx.store.get("modules_baseline")
        if old_mods is None:
            ctx.store.set("modules_baseline", sorted(mods))
        else:
            for m in sorted(set(mods) - set(old_mods)):
                findings.append(Finding(module=NAME, check="new-kernel-module", severity=Severity.MEDIUM,
                                        title=f"Kernel module loaded since baseline: {m}",
                                        fix="Verify with `modinfo` (signer, filename under /lib/modules). Unknown modules may be LKM rootkits (PUMAKIT).",
                                        evidence={"module": m}))
            if set(mods) - set(old_mods):
                ctx.store.set("modules_baseline", sorted(mods))
    for flag in taint_flags():
        if "unsigned" in flag or "out-of-tree" in flag:
            findings.append(Finding(module=NAME, check="kernel-taint", severity=Severity.MEDIUM,
                                    title=f"Kernel is tainted: {flag}",
                                    fix="Out-of-tree/unsigned modules weaken integrity; identify with `cat /proc/modules` and `dmesg | grep taint`.",
                                    evidence={"taint": flag}))

    if cfg.page_cache_check:
        for p in page_cache_mismatches(setuid_binaries()):
            findings.append(Finding(module=NAME, check="page-cache-mismatch", severity=Severity.CRITICAL,
                                    title=f"setuid binary {p} differs between page cache and disk",
                                    fix="Matches the Copy Fail (CVE-2026-31431) page-cache write technique. Drop caches is NOT enough: patch the kernel, blacklist algif_aead, reboot, and reinstall the package.",
                                    evidence={"path": p}))

    for f in preload_in_env_files():
        findings.append(Finding(module=NAME, check="ld-preload-env", severity=Severity.HIGH,
                                title=f"LD_PRELOAD is set in {f}", fix="Remove it unless you know the library; userland rootkits hook via LD_PRELOAD.",
                                evidence={"path": f}))
    return findings
