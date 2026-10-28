"""Command-line interface."""

from __future__ import annotations

import time
from typing import Annotated

import typer
from rich.console import Console

from . import __version__, alerting
from .config import load_config
from .modules import Context, all_modules
from .report import render, to_json
from .runner import record_results, run_modules
from .store import Store

app = typer.Typer(help="Guardian: lightweight security manager for Linux servers.", no_args_is_help=True)
console = Console()

ConfigOpt = Annotated[str | None, typer.Option("--config", "-c", help="Path to config.toml")]


def _ctx(config: str | None, internal: bool = False) -> Context:
    cfg = load_config(config)
    store = Store(cfg.resolve_state_dir() / "guardian.db")
    return Context(config=cfg, store=store, exposed=not internal)


def _module_names() -> list[str]:
    return [m.NAME for m in all_modules()]


@app.callback()
def main() -> None:
    """Guardian CLI."""


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"guardian {__version__}")


@app.command()
def modules() -> None:
    """List available modules."""
    for m in all_modules():
        doc = (m.__doc__ or "").strip().splitlines()[0]
        console.print(f"[bold]{m.NAME:<18}[/] {doc}")


@app.command()
def audit(
    config: ConfigOpt = None,
    json_out: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table")] = False,
    alert: Annotated[bool, typer.Option("--alert", help="Send alerts for new findings")] = False,
    internal: Annotated[bool, typer.Option("--internal", help="Host is not internet-facing (relaxes KEV SLA severity)")] = False,
) -> None:
    """Run every module once and print a report."""
    ctx = _ctx(config, internal)
    results = run_modules(ctx)
    new = record_results(ctx, results)
    if json_out:
        typer.echo(to_json(results, new))
    else:
        render(results, new, console)
    if alert and new:
        sent = alerting.send(ctx.config.alerts, new)
        console.print(f"[dim]alerts sent via: {', '.join(sent) or 'none configured'}[/]")
    worst = max((f.severity.rank for r in results for f in r.findings), default=0)
    raise typer.Exit(code=2 if worst >= 3 else 0)  # non-zero when HIGH/CRITICAL present


@app.command()
def scan(
    module: Annotated[str, typer.Argument(help="Module name (see `guardian modules`)")],
    config: ConfigOpt = None,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run a single module."""
    if module not in _module_names():
        console.print(f"[red]unknown module '{module}'. Available: {', '.join(_module_names())}[/]")
        raise typer.Exit(code=1)
    ctx = _ctx(config)
    results = run_modules(ctx, only=[module])
    new = record_results(ctx, results)
    typer.echo(to_json(results, new)) if json_out else render(results, new, console)


@app.command()
def baseline(config: ConfigOpt = None) -> None:
    """(Re)create the persistence baseline from the current state of watched files."""
    from .modules import persistence

    ctx = _ctx(config)
    n = persistence.build_baseline(ctx)
    console.print(f"baseline recorded for {n} files")


@app.command()
def watch(
    config: ConfigOpt = None,
    interval: Annotated[int, typer.Option("--interval", "-i", help="Minutes between runs")] = 15,
    internal: Annotated[bool, typer.Option("--internal")] = False,
) -> None:
    """Run continuously and alert on new findings (use under systemd)."""
    ctx = _ctx(config, internal)
    console.print(f"guardian watch: every {interval} min; alerts >= {ctx.config.alerts.min_severity}")
    while True:
        results = run_modules(ctx)
        new = record_results(ctx, results)
        errors = [r.module for r in results if r.error]
        console.print(f"[dim]{time.strftime('%H:%M:%S')} run done: {sum(len(r.findings) for r in results)} findings, {len(new)} new"
                      + (f", errors in {errors}" if errors else "") + "[/]")
        if new:
            sent = alerting.send(ctx.config.alerts, new)
            if sent:
                console.print(f"[dim]alerted via {', '.join(sent)}[/]")
        time.sleep(interval * 60)


if __name__ == "__main__":
    app()
