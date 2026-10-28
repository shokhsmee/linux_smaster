# Guardian — Linux Security Manager

A lightweight security agent for Linux servers, built for the AI era: it finds
exposed services (including AI tools like Ollama, Ray, Jupyter and MCP servers),
SSH weaknesses, missing patches for actively exploited CVEs, leaked AI/cloud API
keys on the host, and persistence tricks used by attackers.

It does not replace fail2ban, Falco or Wazuh — it works with them and covers the
gaps they leave. See `docs/research-linux-threats-and-ai-risks.md` for the
research that drives the module plan.

## Phase 1 modules

| Module | What it checks |
|---|---|
| `exposure` | Listening sockets on public interfaces; AI/dev services (Ollama 11434, Ray 8265, Jupyter 8888, MCP, Open WebUI, vector DBs…) without auth; Docker ports bypassing the firewall |
| `ssh_guard` | `sshd_config` weaknesses, brute-force bursts in auth logs, fail2ban/CrowdSec presence |
| `patches` | Pending security updates, reboot-required, installed packages vs CISA KEV, 3-day SLA |
| `secrets` | Leaked AI/cloud keys in `.env`, compose files, shell history, agent configs, `/proc/*/environ`; world-readable secret files |
| `persistence` | Baseline + diff of cron, systemd, `authorized_keys`, sudoers, `ld.so.preload`, PAM, shell rc files |

## Install

```bash
uv sync
uv run guardian audit
```

Requires Python 3.15+. Run as root for full coverage (`sudo uv run guardian audit`).

## Commands

```bash
guardian audit            # run all modules, print a report
guardian audit --json     # machine-readable output
guardian scan secrets     # run one module
guardian baseline         # (re)create the persistence baseline
guardian watch            # loop every N minutes and alert on new findings
```

## Alerts

Set in `/etc/guardian/config.toml` or via environment:

```
GUARDIAN_TELEGRAM_TOKEN, GUARDIAN_TELEGRAM_CHAT, GUARDIAN_SLACK_WEBHOOK, GUARDIAN_WEBHOOK
```

## License

AGPL-3.0-or-later.
