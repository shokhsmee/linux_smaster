"""Runs modules, records results, returns a report."""

from __future__ import annotations

import time
import traceback

from .models import Finding, ModuleResult
from .modules import Context, all_modules


def run_modules(ctx: Context, only: list[str] | None = None) -> list[ModuleResult]:
    results: list[ModuleResult] = []
    for mod in all_modules():
        name = mod.NAME
        if only and name not in only:
            continue
        section = getattr(ctx.config, name if name != "ssh_guard" else "ssh")
        if not getattr(section, "enabled", True):
            results.append(ModuleResult(module=name, skipped="disabled in config"))
            continue
        t0 = time.monotonic()
        try:
            findings: list[Finding] = mod.run(ctx)
            results.append(ModuleResult(module=name, findings=findings, duration_ms=int((time.monotonic() - t0) * 1000)))
        except Exception:  # a broken module must not stop the others
            results.append(ModuleResult(module=name, error=traceback.format_exc(limit=3),
                                        duration_ms=int((time.monotonic() - t0) * 1000)))
    return results


def record_results(ctx: Context, results: list[ModuleResult]) -> list[Finding]:
    """Persist findings; return the ones that are new since the last run."""
    new: list[Finding] = []
    for r in results:
        if r.error or r.skipped:
            continue
        if r.findings:
            new.extend(ctx.store.record(r.findings))
        else:
            ctx.store.mark_module_clean(r.module)
    return new
