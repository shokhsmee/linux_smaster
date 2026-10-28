# Ubuntu 24.04 test image for Guardian: installs uv + Python 3.15, copies the
# repo in and runs the unit tests plus an end-to-end audit against planted
# conditions (see tests/linux/plant.sh and tests/linux/check_findings.py).
#
# Build from the repo root:   docker build -f tests/linux/Dockerfile -t guardian-linux-test .
# Run:                        docker run --rm guardian-linux-test
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/guardian/.venv

# openssh-server + cron give the ssh_guard and persistence modules something
# real to inspect. apt lists are kept so the patches module can simulate upgrades.
# tzdata: the hypothesis timezone strategy in tests/test_fuzz.py needs zoneinfo.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl openssh-server cron tzdata \
    && mkdir -p /run/sshd

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /uvx /bin/

WORKDIR /opt/guardian
COPY pyproject.toml uv.lock .python-version README.md ./
RUN uv python install 3.15 && uv sync --frozen --no-install-project

COPY guardian ./guardian
COPY tests ./tests
COPY deploy ./deploy
COPY docs ./docs
RUN uv sync --frozen && chmod +x tests/linux/*.sh

ENTRYPOINT ["/opt/guardian/tests/linux/entrypoint.sh"]
