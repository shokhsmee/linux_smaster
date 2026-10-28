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
    from . import exposure, patches, persistence, secrets, ssh_guard
    # Phase 2
    from . import agent_guard, egress, kernel_hardening, process_behavior, rootkit

    return [exposure, ssh_guard, patches, secrets, persistence,
            process_behavior, rootkit, kernel_hardening, agent_guard, egress]


def config_key(mod) -> str:
    return getattr(mod, "CONFIG_KEY", "ssh" if mod.NAME == "ssh_guard" else mod.NAME)
