"""Core data models shared by all modules."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Finding(BaseModel):
    """One security finding produced by a module.

    `fingerprint` identifies the same finding across runs so that the store can
    deduplicate it and alerting can fire only on new findings.
    """

    module: str
    check: str
    severity: Severity
    title: str
    detail: str = ""
    fix: str = ""
    evidence: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Stable identity for findings whose title carries changing numbers
    # ("90 failed logins from X"); defaults to the title.
    key: str | None = None

    @property
    def fingerprint(self) -> str:
        ident = f"{self.module}|{self.check}|{self.key or self.title}"
        return hashlib.sha256(ident.encode()).hexdigest()[:16]


class ModuleResult(BaseModel):
    module: str
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    skipped: str | None = None
    duration_ms: int = 0

    @property
    def worst(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
