"""Console (rich) and JSON rendering of results."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import Finding, ModuleResult, Severity

STYLE = {
    Severity.CRITICAL: "bold white on red", Severity.HIGH: "bold red", Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan", Severity.INFO: "dim",
}
WEIGHT = {Severity.CRITICAL: 25, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 1, Severity.INFO: 0}


def score(results: list[ModuleResult]) -> int:
    """0-100 hardening score: 100 minus weighted findings, floored at 0."""
    penalty = sum(WEIGHT[f.severity] for r in results for f in r.findings)
    return max(0, 100 - penalty)


def render(results: list[ModuleResult], new: list[Finding] | None = None, console: Console | None = None) -> None:
    console = console or Console()
    new_fps = {f.fingerprint for f in (new or [])}
    total = sum(len(r.findings) for r in results)
    s = score(results)
    colour = "green" if s >= 80 else "yellow" if s >= 50 else "red"
    console.print(Panel(f"[bold]Guardian audit[/] on [bold]{socket.gethostname()}[/]  "
                        f"{datetime.now(UTC):%Y-%m-%d %H:%M UTC}\n"
                        f"Score: [{colour} bold]{s}/100[/]   Findings: {total}   New: {len(new_fps)}",
                        expand=False))
    for r in results:
        if r.skipped:
            console.print(f"[dim]• {r.module}: skipped ({r.skipped})[/]")
            continue
        if r.error:
            console.print(f"[red]• {r.module}: ERROR[/]\n[dim]{r.error}[/]")
            continue
        head = f"• [bold]{r.module}[/] ({len(r.findings)} finding(s), {r.duration_ms} ms)"
        console.print(head)
        if not r.findings:
            console.print("  [green]clean[/]")
            continue
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False, show_lines=False)
        table.add_column("Sev", width=9)
        table.add_column("Finding", overflow="fold")
        table.add_column("Fix", overflow="fold", style="dim")
        for f in sorted(r.findings, key=lambda x: -x.severity.rank):
            tag = f"[{STYLE[f.severity]}]{f.severity.upper():<8}[/]"
            mark = " [bold magenta]NEW[/]" if f.fingerprint in new_fps else ""
            table.add_row(tag, f.title + mark, f.fix)
        console.print(table)


def to_json(results: list[ModuleResult], new: list[Finding] | None = None) -> str:
    new_fps = {f.fingerprint for f in (new or [])}
    out = {
        "host": socket.gethostname(),
        "time": datetime.now(UTC).isoformat(),
        "score": score(results),
        "modules": [
            {
                "module": r.module, "error": r.error, "skipped": r.skipped, "duration_ms": r.duration_ms,
                "findings": [json.loads(f.model_dump_json()) | {"fingerprint": f.fingerprint, "new": f.fingerprint in new_fps}
                             for f in r.findings],
            }
            for r in results
        ],
    }
    return json.dumps(out, indent=2)
