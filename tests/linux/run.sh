#!/bin/bash
# Build the Ubuntu 24.04 test image and run the full Linux check:
# unit tests, planted conditions, two audits, expected-findings assertions.
# Audit JSON from both runs is left in .testout/ on the host.
# Usage: tests/linux/run.sh [--shell]   (--shell drops into bash afterwards)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$ROOT/.testout"
docker build -f "$ROOT/tests/linux/Dockerfile" -t guardian-linux-test "$ROOT"
if [ "${1:-}" = "--shell" ]; then
    docker run --rm -it -e GUARDIAN_TEST_SHELL=1 -v "$ROOT/.testout:/tmp/guardian-test" guardian-linux-test
else
    docker run --rm -v "$ROOT/.testout:/tmp/guardian-test" guardian-linux-test
fi
