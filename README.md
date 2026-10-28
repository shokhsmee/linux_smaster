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

## Phase 2 modules

| Module | What it checks |
|---|---|
| `process_behavior` | Binaries running from `/tmp`, `/dev/shm` or memfd; deleted executables; system-name mimicry; web servers spawning shells; download-and-execute command lines; known miners; high CPU from unpackaged binaries |
| `rootkit` | PIDs hidden from `/proc` listing; new eBPF programs and kernel modules since baseline; unsigned/out-of-tree taint; setuid binaries whose page cache differs from disk (Copy Fail); `LD_PRELOAD` in env files |
| `kernel_hardening` | Sysctls (unprivileged BPF, ptrace scope, kptr_restrict, protected_* …), unprivileged user namespaces, risky auto-loadable modules (`algif_aead`, `ksmbd`, `dccp` …), old `sudo`, lockdown mode, AppArmor/SELinux |
| `agent_guard` | AI coding agents and MCP servers: bypass flags (`--dangerously-skip-permissions`, `--yolo`), launched from `npm`/`pip` install chains, running as root or unsandboxed, credential files open; injected MCP servers, hooks and prompt-injection text in `.mcp.json`, `settings.json`, `CLAUDE.md`, `AGENTS.md` … with change tracking |
| `egress` | Outbound connections per process: mining-pool and IRC ports, Telegram/Discord/pastebin exfil from daemons, LLM API calls from unexpected binaries, worm-style scanning of admin ports |

All modules work from `/proc`, sysfs and the package manager — no eBPF or auditd required. `guardian modules` lists them.

## Phase 3: supply chain, containers, fleet, AI triage

| Piece | What it does |
|---|---|
| `package_provenance` module | Scans installed `node_modules` and Python site-packages for worm artifacts (Shai-Hulud, s1ngularity, 0x2ai), download-and-execute install hooks, typosquats and documented AI-hallucinated package names; wiper lines in shell rc files; missing lockfiles; npm lifecycle scripts enabled |
| `containers` module | Docker/Podman: secrets in container/image ENV and build history, `--privileged`, docker.sock and sensitive host mounts, host PID/network namespaces, dangerous capabilities, root user, unpinned `latest` images |
| `guardian check-package npm\|pypi NAME…` | Slopsquatting guard to run **before** installing an AI-suggested package: does it exist, how old, downloads, install hooks, one typo from a popular name |
| `guardian hub serve` + `guardian audit --push` | Tiny fleet view: hosts push a summary, the hub shows one page with scores and findings per host (SQLite, stdlib HTTP, bind to localhost + TLS proxy) |
| `guardian triage` | Sends the findings (masked, no secret values) to Claude and prints a ranked, plain-language fix plan plus likely false positives. Advice only — nothing is applied |

```bash
guardian check-package pypi reqeusts          # -> CRITICAL: does not exist, did you mean requests?
guardian hub serve --token "$(openssl rand -hex 24)" --port 8787
GUARDIAN_HUB_URL=http://hub:8787 GUARDIAN_HUB_TOKEN=... guardian audit --push
ANTHROPIC_API_KEY=... guardian triage
```

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

## Testing on Linux

`tests/linux/` holds a Docker harness that builds an Ubuntu 24.04 image with
uv + Python 3.15, runs the unit tests, plants real conditions (an
unauthenticated Ollama on 0.0.0.0:11434, a leaked key in `.env` and in a
process environment, a `curl | sh` cron job, a non-empty `ld.so.preload`,
sshd with password auth, a brute-force burst in `auth.log`, a Node project
with a typosquat and a `curl | sh` postinstall hook, a typosquatted PyPI
dist-info, a wiper line in `.bashrc`) and asserts that two consecutive
`guardian audit --json` runs report each of them with the expected severity,
with the second run diffing the persistence baseline. Docker-in-Docker is
impractical there, so a stub `docker` CLI on PATH answers `ps`, `inspect`,
`images` and `history` with a privileged container that mounts the Docker
socket and carries an OpenAI key in its environment.

```bash
tests/linux/run.sh            # build + run; audit JSON lands in .testout/
tests/linux/run.sh --shell    # same, then drop into a shell in the container
```

## Alerts

Set in `/etc/guardian/config.toml` or via environment:

```
GUARDIAN_TELEGRAM_TOKEN, GUARDIAN_TELEGRAM_CHAT, GUARDIAN_SLACK_WEBHOOK, GUARDIAN_WEBHOOK
```

## Hardening of Guardian itself

Guardian is a security tool, so it is held to the standards it checks for:

- **No secrets in the repo.** Keys and tokens come from the environment or
  `/etc/guardian/env`; nothing sensitive is committed, and the `secrets`
  module would flag it if it were.
- **Pinned, audited supply chain.** `uv.lock` is installed with `--locked`,
  every GitHub Action is pinned to a commit SHA, workflows default to
  `permissions: contents: read`, and Renovate proposes weekly, grouped updates
  for Python packages and Actions (7-day minimum release age, digests pinned).
- **Continuous SAST and fuzzing.** Each push runs `ruff`, `bandit` and the test
  suite, which includes [hypothesis](https://hypothesis.readthedocs.io/)
  property tests (`tests/test_fuzz.py`) asserting that the auth-log, secret,
  agent-config and package-name parsers never raise on arbitrary input.
- **Sandboxed service.** `deploy/guardian.service` runs with systemd
  hardening (`ProtectSystem=strict`, `NoNewPrivileges`,
  `MemoryDenyWriteExecute`, capability bounding set).
- **Signed releases.** Tags matching `v*` build the wheel and sdist with
  `uv build` and sign them keylessly with [Sigstore](https://www.sigstore.dev/)
  from the release workflow. See `SECURITY.md` for reporting vulnerabilities.

### Verifying a release

Each release attaches `guardian-<version>-py3-none-any.whl`,
`guardian-<version>.tar.gz` and a `.sigstore.json` bundle per file. Verify that
the file was built by this repository's release workflow for that tag:

```bash
uvx sigstore verify github \
  --bundle guardian-0.1.0-py3-none-any.whl.sigstore.json \
  --repository shokhsmee/linux_smaster \
  --ref refs/tags/v0.1.0 \
  guardian-0.1.0-py3-none-any.whl
```

`verify github` checks the certificate identity
(`https://github.com/shokhsmee/linux_smaster/.github/workflows/release.yml@refs/tags/v0.1.0`)
and the OIDC issuer (`https://token.actions.githubusercontent.com`) against
the Sigstore transparency log. Install the verified wheel with `uv pip install
guardian-0.1.0-py3-none-any.whl`.

## License

AGPL-3.0-or-later.
