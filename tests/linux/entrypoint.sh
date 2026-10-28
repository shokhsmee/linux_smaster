#!/bin/bash
# Full Linux check: unit tests, then plant conditions and audit twice.
set -uo pipefail
cd /opt/guardian
HERE=/opt/guardian/tests/linux
OUT=${GUARDIAN_TEST_OUT:-/tmp/guardian-test}
mkdir -p "$OUT"
status=0

echo "### uv run pytest"
uv run --frozen pytest -q || status=1

echo "### guardian modules"
uv run --frozen guardian modules | tee "$OUT/modules.txt"
n=$(grep -c '^[a-z_]\+ ' "$OUT/modules.txt"); [ "$n" -eq 12 ] && echo "ok  12 modules listed" || { echo "FAIL expected 12 modules, got $n"; status=1; }

echo "### plant"
bash "$HERE/plant.sh" || status=1

echo "### first audit"
uv run --frozen guardian audit --json > "$OUT/audit1.json"; echo "exit=$?"
/opt/guardian/.venv/bin/python "$HERE/check_findings.py" first "$OUT/audit1.json" || status=1

echo "### mutate"
bash "$HERE/mutate.sh" || status=1

echo "### second audit"
uv run --frozen guardian audit --json > "$OUT/audit2.json"; echo "exit=$?"
/opt/guardian/.venv/bin/python "$HERE/check_findings.py" second "$OUT/audit2.json" || status=1

echo "### human-readable report"
uv run --frozen guardian audit || true

if [ -n "${GUARDIAN_TEST_SHELL:-}" ]; then exec bash; fi
exit $status
