"""Registry lookups for the `check-package` command (npm, PyPI).

This is the slopsquatting guard: run it before installing a package an AI
suggested. It checks that the package exists, how old it is, how many people
download it, whether it has install hooks, and whether its name is one typo
away from a popular package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from .models import Severity
from .popular import KNOWN_LEGIT_NEAR_NAMES, KNOWN_SLOPSQUATS, POPULAR_NPM, POPULAR_PYPI

UA = {"User-Agent": "guardian-check-package"}


@dataclass
class PackageReport:
    ecosystem: str
    name: str
    exists: bool = False
    latest: str = ""
    created: datetime | None = None
    versions: int = 0
    weekly_downloads: int | None = None
    maintainers: int | None = None
    repository: str = ""
    install_scripts: dict[str, str] = field(default_factory=dict)
    description: str = ""
    issues: list[tuple[Severity, str]] = field(default_factory=list)

    @property
    def age_days(self) -> int | None:
        return (datetime.now(UTC) - self.created).days if self.created else None

    @property
    def verdict(self) -> Severity:
        return max((s for s, _ in self.issues), key=lambda s: s.rank, default=Severity.INFO)


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return min(prev[-1], limit + 1)


def normalize(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def typosquat_candidates(name: str, ecosystem: str, max_distance: int = 2) -> list[str]:
    pool = POPULAR_NPM if ecosystem == "npm" else POPULAR_PYPI
    n = normalize(name)
    if n in {normalize(p) for p in pool} or len(n) < 4 or n in KNOWN_LEGIT_NEAR_NAMES.get(ecosystem, set()):
        return []
    # Short names reach too many popular packages within two edits (fine -> vite),
    # so require a single-edit match for them.
    if len(n) <= 5:
        max_distance = min(max_distance, 1)
    out = []
    for p in pool:
        d = edit_distance(n, normalize(p), max_distance)
        if 0 < d <= max_distance or n in (normalize(p) + "-js", normalize(p) + "js", normalize(p) + "-py", normalize(p) + "-python", "py" + normalize(p), "python-" + normalize(p)):
            out.append(p)
    return sorted(set(out))


def _parse_dt(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def check_npm(name: str, client: httpx.Client) -> PackageReport:
    r = PackageReport("npm", name)
    resp = client.get(f"https://registry.npmjs.org/{name}")
    if resp.status_code == 404:
        return r
    resp.raise_for_status()
    data = resp.json()
    r.exists = True
    r.latest = data.get("dist-tags", {}).get("latest", "")
    times = data.get("time", {})
    r.created = _parse_dt(times.get("created", ""))
    r.versions = len(data.get("versions", {}))
    r.maintainers = len(data.get("maintainers", []) or [])
    repo = data.get("repository")
    r.repository = repo.get("url", "") if isinstance(repo, dict) else (repo or "")
    r.description = data.get("description", "") or ""
    latest = data.get("versions", {}).get(r.latest, {})
    scripts = latest.get("scripts", {}) or {}
    r.install_scripts = {k: v for k, v in scripts.items() if k in ("preinstall", "install", "postinstall", "prepare")}
    dl = client.get(f"https://api.npmjs.org/downloads/point/last-week/{name}")
    if dl.is_success:
        r.weekly_downloads = int(dl.json().get("downloads", 0))
    return r


def check_pypi(name: str, client: httpx.Client) -> PackageReport:
    r = PackageReport("pypi", name)
    resp = client.get(f"https://pypi.org/pypi/{name}/json")
    if resp.status_code == 404:
        return r
    resp.raise_for_status()
    data = resp.json()
    info = data.get("info", {})
    r.exists = True
    r.latest = info.get("version", "")
    r.description = info.get("summary", "") or ""
    urls = info.get("project_urls") or {}
    r.repository = next((v for k, v in urls.items() if any(x in k.lower() for x in ("source", "repository", "github", "code", "homepage"))), "") or info.get("home_page", "") or ""
    uploads = [u.get("upload_time_iso_8601", "") for files in data.get("releases", {}).values() for u in files]
    dts = [d for d in (_parse_dt(u) for u in uploads) if d]
    r.created = min(dts) if dts else None
    r.versions = len(data.get("releases", {}))
    stats = client.get(f"https://pypistats.org/api/packages/{name.lower()}/recent")
    if stats.is_success:
        r.weekly_downloads = int(stats.json().get("data", {}).get("last_week", 0))
    return r


def assess(r: PackageReport) -> PackageReport:
    eco = r.ecosystem
    squats = typosquat_candidates(r.name, eco)
    if normalize(r.name) in {normalize(x) for x in KNOWN_SLOPSQUATS.get(eco, set())}:
        r.issues.append((Severity.CRITICAL, "This name is a documented AI-hallucinated package that was later registered (slopsquat)."))
    if not r.exists:
        if squats:
            r.issues.append((Severity.CRITICAL, f"Package does not exist on {eco}; did you mean {', '.join(squats[:3])}? An attacker can register this name."))
        else:
            r.issues.append((Severity.HIGH, f"Package does not exist on {eco}. If an AI suggested it, it was hallucinated: do not create or install it blindly."))
        return r
    if squats:
        r.issues.append((Severity.HIGH, f"Name is one or two edits from popular package(s): {', '.join(squats[:3])} (possible typosquat)."))
    age = r.age_days
    if age is not None and age < 30:
        r.issues.append((Severity.HIGH, f"Published only {age} day(s) ago."))
    elif age is not None and age < 180:
        r.issues.append((Severity.MEDIUM, f"Package is young ({age} days)."))
    if r.weekly_downloads is not None and r.weekly_downloads < 100:
        r.issues.append((Severity.MEDIUM, f"Very few downloads last week ({r.weekly_downloads})."))
    elif r.weekly_downloads is not None and r.weekly_downloads < 1000:
        r.issues.append((Severity.LOW, f"Low download count last week ({r.weekly_downloads})."))
    if r.install_scripts:
        hooks = ", ".join(f"{k}: {v[:60]}" for k, v in r.install_scripts.items())
        r.issues.append((Severity.MEDIUM, f"Has install hooks that run code on `npm install` ({hooks})."))
    if r.versions <= 1:
        r.issues.append((Severity.LOW, "Only one version has ever been published."))
    if not r.repository:
        r.issues.append((Severity.LOW, "No source repository URL."))
    if r.maintainers == 1 and eco == "npm":
        r.issues.append((Severity.INFO, "Single maintainer (account takeover affects it directly)."))
    return r


def check_package(name: str, ecosystem: str, timeout: float = 15.0) -> PackageReport:
    with httpx.Client(timeout=timeout, headers=UA, follow_redirects=True) as client:
        r = check_npm(name, client) if ecosystem == "npm" else check_pypi(name, client)
    return assess(r)
