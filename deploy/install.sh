#!/usr/bin/env bash
# Install Guardian on a Linux server into /opt/guardian with uv + Python 3.15.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi

DEST=/opt/guardian
SRC="$(cd "$(dirname "$0")/.." && pwd)"

command -v uv >/dev/null 2>&1 || curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

mkdir -p "$DEST" /etc/guardian /var/lib/guardian
chmod 700 /var/lib/guardian
rsync -a --delete --exclude .venv --exclude .git "$SRC"/ "$DEST"/
cd "$DEST"
uv python install 3.15
uv sync --no-dev

[ -f /etc/guardian/config.toml ] || install -m 600 deploy/config.example.toml /etc/guardian/config.toml
[ -f /etc/guardian/env ] || { touch /etc/guardian/env; chmod 600 /etc/guardian/env; }
install -m 644 deploy/guardian.service /etc/systemd/system/guardian.service
ln -sf "$DEST/.venv/bin/guardian" /usr/local/bin/guardian

systemctl daemon-reload
systemctl enable --now guardian
echo "Guardian installed. Try: guardian audit"
