"""AI-assisted triage of audit results (optional, human-reviewed).

Sends the findings (titles, severities, fixes and already-masked evidence,
never raw secret values) to Claude and asks for a ranked, plain-language fix
plan plus likely false positives. The output is advice to read, not commands
Guardian will run: nothing is auto-applied.

Requires `ANTHROPIC_API_KEY` (or an `ant auth login` profile).
"""

from __future__ import annotations

import json
import socket

import anthropic

DEFAULT_MODEL = "claude-opus-5-5"

SYSTEM = """You are a senior Linux security engineer reviewing the output of Guardian, a host security scanner.
You receive JSON findings from one host. Produce a short, plain-language triage for a developer who runs servers but is not a security specialist.

Structure your answer as Markdown with exactly these sections:
1. **Verdict** - one or two sentences: is this host in trouble right now, or is this hygiene work?
2. **Fix first (today)** - a numbered list of at most 5 items, highest risk first. For each: what the finding means in one sentence, why it matters (name the real-world attack technique when relevant: credential-stealing worms, cryptominers, prompt injection of AI agents, kernel LPEs, etc.), and the exact command or config change to fix it.
3. **Fix this week** - the remaining medium/low items grouped by theme, briefly.
4. **Probably false positives** - findings that are likely benign given the context (e.g. a dev server intentionally bound to 0.0.0.0, generic password matches in example configs). Say what would confirm they are benign.
5. **What to check manually** - things the scanner cannot decide (e.g. whether a login from a new IP was the admin).

Rules: never invent findings that are not in the input; quote the finding title when referring to it; keep the total under 600 words; do not tell the reader to run destructive commands (rm -rf, reboot) without first saying what to back up or verify."""


def _slim(report: dict) -> dict:
    """Keep only what the model needs; evidence is already masked by the modules."""
    out = {"host": report.get("host"), "score": report.get("score"), "time": report.get("time"), "findings": []}
    for m in report.get("modules", []):
        for f in m.get("findings", []):
            if f.get("severity") == "info":
                continue
            out["findings"].append({
                "module": m["module"], "check": f.get("check"), "severity": f.get("severity"),
                "title": f.get("title"), "detail": (f.get("detail") or "")[:300], "fix": f.get("fix"),
                "evidence": {k: (str(v)[:120] if v is not None else None) for k, v in (f.get("evidence") or {}).items()},
            })
    out["findings"].sort(key=lambda x: ["low", "medium", "high", "critical"].index(x["severity"]) if x["severity"] in ("low", "medium", "high", "critical") else -1, reverse=True)
    out["findings"] = out["findings"][:150]
    return out


def triage(report: dict, model: str = DEFAULT_MODEL, effort: str = "high") -> str:
    """Return a Markdown triage for the audit report. Raises anthropic errors to the caller."""
    slim = _slim(report)
    if not slim["findings"]:
        return f"No findings above INFO on {slim['host'] or socket.gethostname()} - nothing to triage."
    client = anthropic.Anthropic()
    with client.beta.messages.stream(
        model=model,
        max_tokens=64000,
        system=[{"type": "text", "text": SYSTEM, "cache_control": {"type": "ephemeral"}}],
        output_config={"effort": effort},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        messages=[{"role": "user", "content": "Guardian audit results:\n\n" + json.dumps(slim, indent=1)}],
    ) as stream:
        response = stream.get_final_message()
    if response.stop_reason == "refusal":
        cat = response.stop_details.category if response.stop_details else "unknown"
        return f"Triage declined by the model's safety policy (category: {cat}). Review the findings manually."
    text = "".join(b.text for b in response.content if b.type == "text")
    if response.stop_reason == "max_tokens":
        text += "\n\n_(triage was cut off at max_tokens)_"
    return text
