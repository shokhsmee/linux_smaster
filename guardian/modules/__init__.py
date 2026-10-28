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
    from . import exposure, patches, persistence, secrets, ssh_guard

    return [exposure, ssh_guard, patches, secrets, persistence]
