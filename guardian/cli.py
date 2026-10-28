"""Command-line interface."""

from __future__ import annotations

import contextlib
import time
from pathlib import Path
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
    push: Annotated[bool, typer.Option("--push", help="Push the report to the fleet hub ([hub] url/token or GUARDIAN_HUB_URL/TOKEN)")] = False,
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
    if push:
        _push(ctx, results, new)
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
        if ctx.config.hub.url:
            _push(ctx, results, new)
        time.sleep(interval * 60)


def _push(ctx: Context, results, new) -> None:
    from . import hub as hubmod

    cfg = ctx.config.hub
    if not cfg.url or not cfg.token:
        console.print("[yellow]hub push skipped: set [hub] url and token (or GUARDIAN_HUB_URL / GUARDIAN_HUB_TOKEN)[/]")
        return
    ok = hubmod.push(cfg.url, cfg.token, to_json(results, new))
    console.print(f"[dim]hub push: {'ok' if ok else 'FAILED'} ({cfg.url})[/]")


# ---- Phase 3 commands ----------------------------------------------------------

@app.command("check-package")
def check_package(
    ecosystem: Annotated[str, typer.Argument(help="npm or pypi")],
    names: Annotated[list[str], typer.Argument(help="Package name(s) to check before installing")],
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Slopsquatting guard: check a package on its registry before you install it."""
    from rich.table import Table

    from .registry import check_package as _check

    eco = ecosystem.lower()
    if eco not in ("npm", "pypi"):
        console.print("[red]ecosystem must be npm or pypi[/]")
        raise typer.Exit(code=1)
    worst = 0
    reports = []
    for name in names:
        try:
            r = _check(name, eco)
        except Exception as exc:  # noqa: BLE001 - network errors should not crash the CLI
            console.print(f"[red]{name}: lookup failed ({exc})[/]")
            raise typer.Exit(code=1) from None
        reports.append(r)
        worst = max(worst, r.verdict.rank)
    if json_out:
        import json as _json

        typer.echo(_json.dumps([{
            "ecosystem": r.ecosystem, "name": r.name, "exists": r.exists, "latest": r.latest,
            "age_days": r.age_days, "weekly_downloads": r.weekly_downloads, "versions": r.versions,
            "repository": r.repository, "install_scripts": r.install_scripts, "verdict": r.verdict,
            "issues": [{"severity": s, "text": t} for s, t in r.issues],
        } for r in reports], indent=2))
    else:
        for r in reports:
            colour = {"critical": "bold white on red", "high": "bold red", "medium": "yellow", "low": "cyan", "info": "green"}[r.verdict]
            head = f"[{colour}] {r.verdict.upper()} [/] [bold]{eco}:{r.name}[/]"
            if r.exists:
                head += f"  v{r.latest} · {r.age_days}d old · {r.versions} versions · {r.weekly_downloads if r.weekly_downloads is not None else '?'} dl/week"
            console.print(head)
            if r.description:
                console.print(f"  [dim]{r.description[:100]}[/]")
            t = Table(show_header=False, box=None, pad_edge=False)
            for s, text in r.issues:
                t.add_row(f"  [{ {'critical': 'red', 'high': 'red', 'medium': 'yellow', 'low': 'cyan', 'info': 'dim'}[s] }]{s:<8}[/]", text)
            if not r.issues:
                t.add_row("  [green]ok[/]", "No red flags found. Still pin the version and read the code if it runs install scripts.")
            console.print(t)
    raise typer.Exit(code=2 if worst >= 3 else 0)


hub_app = typer.Typer(help="Lightweight fleet hub: hosts push audit summaries, you get one page for all of them.")
app.add_typer(hub_app, name="hub")


@hub_app.command("serve")
def hub_serve(
    token: Annotated[str, typer.Option("--token", envvar="GUARDIAN_HUB_TOKEN", help="Shared bearer token hosts must present")],
    bind: Annotated[str, typer.Option("--bind", help="Address to listen on (keep 127.0.0.1 and put TLS in front)")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p")] = 8787,
    db: Annotated[str | None, typer.Option("--db", help="SQLite file (default: state dir/hub.db)")] = None,
) -> None:
    """Run the fleet hub."""
    from pathlib import Path

    from . import hub as hubmod

    if len(token) < 16:
        console.print("[red]token must be at least 16 characters[/]")
        raise typer.Exit(code=1)
    path = Path(db) if db else load_config(None).resolve_state_dir() / "hub.db"
    console.print(f"guardian hub listening on http://{bind}:{port}  (db: {path})")
    if bind not in ("127.0.0.1", "localhost", "::1"):
        console.print("[yellow]bound to a non-loopback address: use a TLS reverse proxy in front of it[/]")
    with contextlib.suppress(KeyboardInterrupt):
        hubmod.serve(bind, port, token, path)


@app.command()
def triage(
    config: ConfigOpt = None,
    report: Annotated[str | None, typer.Option("--report", help="Use a saved `guardian audit --json` file instead of running an audit")] = None,
    model: Annotated[str | None, typer.Option("--model")] = None,
    internal: Annotated[bool, typer.Option("--internal")] = False,
) -> None:
    """Ask Claude to rank the findings and write a plain-language fix plan (nothing is applied)."""
    import json as _json

    from rich.markdown import Markdown

    from . import triage as triagemod

    ctx = _ctx(config, internal)
    if report:
        data = _json.loads(Path(report).read_text(encoding="utf-8"))
    else:
        results = run_modules(ctx)
        new = record_results(ctx, results)
        data = _json.loads(to_json(results, new))
    try:
        text = triagemod.triage(data, model or ctx.config.triage.model, ctx.config.triage.effort)
    except Exception as exc:  # noqa: BLE001 - auth/network: report, do not trace
        console.print(f"[red]triage failed: {type(exc).__name__}: {exc}[/]")
        console.print("[dim]Set ANTHROPIC_API_KEY (or run `ant auth login`).[/]")
        raise typer.Exit(code=1) from None
    console.print(Markdown(text))


if __name__ == "__main__":
    app()
