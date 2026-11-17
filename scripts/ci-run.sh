#!/usr/bin/env bash
# Runs check.sql against a database and reports the findings for CI.
# Used by action.yml; also works on its own:
#   DB_URL=postgresql://postgres:postgres@127.0.0.1:54322/postgres FAIL_ON=high bash scripts/ci-run.sh
# Writes a table to $GITHUB_STEP_SUMMARY and counts to $GITHUB_OUTPUT when those are set.
# Exits 1 when a finding at or above FAIL_ON (high, medium, low, info; "never" to only report) is present.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
db_url="${DB_URL:-postgresql://postgres:postgres@127.0.0.1:54322/postgres}"
fail_on="${FAIL_ON:-high}"
case "$fail_on" in high|medium|low|info|never) ;; *) echo "FAIL_ON must be high, medium, low, info or never (got: $fail_on)"; exit 2 ;; esac

raw="$(mktemp)"; out="$(mktemp)"
# A check that could not run must never look like a pass.
if ! psql -X -q -v ON_ERROR_STOP=1 "$db_url" -f "$here/check.sql" -At -F $'\t' > "$raw"; then
  echo "supabase-check could not run: psql failed (see the error above). Nothing was checked."
  exit 2
fi
grep -E $'^(high|medium|low|info)\t' "$raw" > "$out" || true

count() { awk -F'\t' -v s="$1" '$1 == s' "$out" | wc -l | tr -d ' '; }
high=$(count high); medium=$(count medium); low=$(count low); info=$(count info)
total=$((high + medium + low + info))

echo "supabase-check: $high high, $medium medium, $low low, $info info"
awk -F'\t' '{ printf "%-6s %s  %s\n       %s\n", $1, $2, $3, $4 }' "$out"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## supabase-check"
    echo
    echo "$high high, $medium medium, $low low, $info info. Checked on the database built from this commit's migrations."
    echo
    if [ "$total" -gt 0 ]; then
      echo "| Severity | Check | Object | Finding | Fix |"
      echo "|---|---|---|---|---|"
      awk -F'\t' '{ for (i = 1; i <= 5; i++) gsub(/\|/, "\\|", $i); printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5 }' "$out"
      echo
    fi
    echo "An empty result is not a clean bill: it means none of these patterns were found in this commit."
    echo "What each check covers: https://github.com/kodev-team/supabase-check#what-it-checks"
  } >> "$GITHUB_STEP_SUMMARY"
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  { echo "high=$high"; echo "medium=$medium"; echo "low=$low"; echo "info=$info"; echo "total=$total"; } >> "$GITHUB_OUTPUT"
fi

failing=0
case "$fail_on" in
  high)   failing=$high ;;
  medium) failing=$((high + medium)) ;;
  low)    failing=$((high + medium + low)) ;;
  info)   failing=$total ;;
esac
rm -f "$raw" "$out"
if [ "$failing" -gt 0 ]; then
  echo "Failing: $failing finding(s) at or above \"$fail_on\"."
  exit 1
fi
