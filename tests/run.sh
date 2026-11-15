#!/usr/bin/env bash
# Runs check.sql against two throwaway databases and compares the findings with the expected list.
# Needs a local PostgreSQL 15+ where the current user can create databases.
set -euo pipefail
cd "$(dirname "$0")/.."
run() { psql -X -q -d "$1" -f check.sql -At -F '|' | cut -d'|' -f1-3 | grep -E '^(high|medium|low|info)\|' || true; }
dropdb --if-exists kodev_check_bad >/dev/null 2>&1; createdb kodev_check_bad
psql -X -q -v ON_ERROR_STOP=1 -d kodev_check_bad -f tests/fixture.sql >/dev/null
if ! diff <(run kodev_check_bad) tests/expected.txt; then echo "FAIL: findings differ from tests/expected.txt"; exit 1; fi
echo "PASS: planted problems found, nothing extra"
dropdb --if-exists kodev_check_clean >/dev/null 2>&1; createdb kodev_check_clean
psql -X -q -v ON_ERROR_STOP=1 -d kodev_check_clean -f tests/clean.sql >/dev/null
out="$(run kodev_check_clean)"; [ -z "$out" ] && echo "PASS: clean project, no findings" || { echo "FAIL: clean project produced:"; echo "$out"; exit 1; }
dropdb kodev_check_bad; dropdb kodev_check_clean
