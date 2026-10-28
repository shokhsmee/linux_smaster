"""Security modules. Each exposes `NAME` and `run(ctx) -> list[Finding]`."""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config
from ..store import Store


@dataclass
class Context:
    config: Config
    store: Store
    exposed: bool = True  # treat host as internet-facing unless told otherwise


def all_modules():
    # Phase 1
    # Phase 2
    # Phase 3
    from . import agent_guard, containers, egress, exposure, kernel_hardening, package_provenance, patches, persistence, process_behavior, rootkit, secrets, ssh_guard

    return [exposure, ssh_guard, patches, secrets, persistence,
            process_behavior, rootkit, kernel_hardening, agent_guard, egress,
            package_provenance, containers]


def config_key(mod) -> str:
    return getattr(mod, "CONFIG_KEY", "ssh" if mod.NAME == "ssh_guard" else mod.NAME)
