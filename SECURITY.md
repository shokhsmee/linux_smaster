# Security policy

Guardian reads authentication logs, process environments, agent configuration
files and package metadata on the hosts it protects. A bug in any of its
parsers is therefore a security issue, not only a correctness one.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

1. Preferred: open a private report through GitHub's vulnerability reporting
   form for this repository
   (https://github.com/shokhsmee/linux_smaster/security/advisories/new).
2. If that form is not available to you, contact the maintainer directly:
   [@shokhsmee](https://github.com/shokhsmee) (contact details on the profile).

Include the Guardian version (`guardian --version`), the affected module or
command, and a minimal reproduction (for parser bugs: the exact input line or
file). You will get an acknowledgement within 7 days and a fix or a workaround
within 90 days of acceptance; coordinated disclosure after that is welcome.

Secrets found by Guardian are never needed in a report. Mask them the way
Guardian itself does (first six and last two characters).

## Supported versions

| Version | Supported |
|---|---|
| latest tagged `v0.x` release | yes |
| `main` branch | best effort |
| older tags | no |

Pre-1.0 releases may change behaviour between minor versions; security fixes
are released as a new tag, never as a replaced tag.

## How Guardian itself is hardened

- No secrets in the repository: API keys and tokens are read from the
  environment or `/etc/guardian/env` at runtime; the `secrets` module and the
  CI lint would flag anything committed.
- Dependencies are locked (`uv.lock`) and installed with `uv sync --locked`;
  Dependabot proposes updates weekly for Python packages and GitHub Actions.
- Every GitHub Action is pinned to a full commit SHA and the workflows run with
  `permissions: contents: read` by default.
- Each push runs `ruff`, `bandit` (SAST) and the test suite, which includes
  hypothesis-based fuzzing of the parsers that consume untrusted input.
- Releases are built with `uv build` and signed keylessly with Sigstore from
  the release workflow; see the README for how to verify a download.
- The shipped `deploy/guardian.service` unit runs with systemd sandboxing
  (`ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, a
  capability bounding set, and more).
