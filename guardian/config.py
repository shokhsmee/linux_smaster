"""Configuration loading (TOML) with safe defaults."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATHS = (
    Path("/etc/guardian/config.toml"),
    Path.home() / ".config" / "guardian" / "config.toml",
)


class ExposureConfig(BaseModel):
    enabled: bool = True
    probe_http: bool = True  # probe suspected AI/dev services for missing auth
    probe_timeout: float = 2.0


class SshConfig(BaseModel):
    enabled: bool = True
    auth_logs: list[str] = Field(
        default_factory=lambda: ["/var/log/auth.log", "/var/log/secure"]
    )
    window_minutes: int = 60
    brute_force_threshold: int = 50  # failed logins in window from one IP


class PatchConfig(BaseModel):
    enabled: bool = True
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_cache_hours: int = 12
    sla_days: int = 3  # BOD 26-04 style window for internet-exposed hosts


class SecretsConfig(BaseModel):
    enabled: bool = True
    paths: list[str] = Field(
        default_factory=lambda: ["/home", "/root", "/srv", "/opt", "/var/www", "/etc"]
    )
    max_file_kb: int = 512
    scan_proc_environ: bool = True
    exclude_dirs: list[str] = Field(
        default_factory=lambda: [
            "node_modules", ".git", ".venv", "venv", "__pycache__", ".cache",
            "site-packages", "dist", "build", "test", "tests", "testdata", "fixtures",
            "fixture", "sample", "samples", "example", "examples", "Cellar", "gems",
            "proc", "sys", "dev",
        ]
    )


class PersistenceConfig(BaseModel):
    enabled: bool = True
    extra_paths: list[str] = Field(default_factory=list)


class ProcessConfig(BaseModel):
    enabled: bool = True
    cpu_sample_seconds: float = 1.0
    cpu_threshold: float = 85.0


class RootkitConfig(BaseModel):
    enabled: bool = True
    pid_probe_limit: int = 131072  # brute-force /proc/N up to this PID
    page_cache_check: bool = True


class KernelConfig(BaseModel):
    enabled: bool = True


class AgentsConfig(BaseModel):
    enabled: bool = True
    extra_roots: list[str] = Field(default_factory=list)  # extra dirs holding agent configs/repos


class EgressConfig(BaseModel):
    enabled: bool = True
    reverse_dns: bool = True
    dns_timeout: float = 1.0
    scan_threshold: int = 15


class PackagesConfig(BaseModel):
    enabled: bool = True
    extra_roots: list[str] = Field(default_factory=list)
    project_depth: int = 4


class ContainersConfig(BaseModel):
    enabled: bool = True
    scan_images: bool = True
    scan_history: bool = True
    max_images: int = 50


class HubConfig(BaseModel):
    url: str = ""     # e.g. https://hub.example.com ; set GUARDIAN_HUB_URL / GUARDIAN_HUB_TOKEN in env
    token: str = ""


class TriageConfig(BaseModel):
    model: str = "claude-opus-5-5"
    effort: str = "high"


class AlertConfig(BaseModel):
    min_severity: str = "medium"
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    slack_webhook: str = ""
    generic_webhook: str = ""


class Config(BaseModel):
    state_dir: str = ""  # resolved in `resolve_state_dir`
    exposure: ExposureConfig = Field(default_factory=ExposureConfig)
    ssh: SshConfig = Field(default_factory=SshConfig)
    patches: PatchConfig = Field(default_factory=PatchConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    persistence: PersistenceConfig = Field(default_factory=PersistenceConfig)
    process: ProcessConfig = Field(default_factory=ProcessConfig)
    rootkit: RootkitConfig = Field(default_factory=RootkitConfig)
    kernel: KernelConfig = Field(default_factory=KernelConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)
    packages: PackagesConfig = Field(default_factory=PackagesConfig)
    containers: ContainersConfig = Field(default_factory=ContainersConfig)
    hub: HubConfig = Field(default_factory=HubConfig)
    triage: TriageConfig = Field(default_factory=TriageConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)

    def resolve_state_dir(self) -> Path:
        if self.state_dir:
            p = Path(self.state_dir)
        elif os.geteuid() == 0:
            p = Path("/var/lib/guardian")
        else:
            p = Path.home() / ".local" / "state" / "guardian"
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        return p


def load_config(path: str | None = None) -> Config:
    candidates = [Path(path)] if path else list(DEFAULT_CONFIG_PATHS)
    for p in candidates:
        if p.is_file():
            with p.open("rb") as fh:
                data = tomllib.load(fh)
            cfg = Config.model_validate(data)
            # Allow secrets to come from the environment instead of the file.
            _env_override(cfg)
            return cfg
    cfg = Config()
    _env_override(cfg)
    return cfg


def _env_override(cfg: Config) -> None:
    env = os.environ
    cfg.alerts.telegram_bot_token = env.get("GUARDIAN_TELEGRAM_TOKEN", cfg.alerts.telegram_bot_token)
    cfg.alerts.telegram_chat_id = env.get("GUARDIAN_TELEGRAM_CHAT", cfg.alerts.telegram_chat_id)
    cfg.alerts.slack_webhook = env.get("GUARDIAN_SLACK_WEBHOOK", cfg.alerts.slack_webhook)
    cfg.alerts.generic_webhook = env.get("GUARDIAN_WEBHOOK", cfg.alerts.generic_webhook)
    cfg.hub.url = env.get("GUARDIAN_HUB_URL", cfg.hub.url)
    cfg.hub.token = env.get("GUARDIAN_HUB_TOKEN", cfg.hub.token)
