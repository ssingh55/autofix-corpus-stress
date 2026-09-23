#!/usr/bin/env bash
# Usage: wait_knoxiq.sh <appknox-bin> <file_id>. Exits 0 once KnoxIQ triage has
# COMPLETED for the file; 1 on timeout.
#
# Why: KnoxIQ can rewrite Analysis.risk after SAST finishes, so a snapshot taken
# as soon as wait_scan.sh returns can straddle triage. And `appknox autofix`
# does NOT wait for KnoxIQ: it checks once (helper/knoxiq.go checkKnoxIQReady)
# and exits 1 if triage is not COMPLETED yet.
#
# No new API: `appknox autofix --file-id <id> --list-analyses` runs that same
# checkKnoxIQReady gate first and exits 1 until KnoxIQ is COMPLETED, so polling
# it is the CLI's own readiness check. It also exits 1 on other errors (bad
# token, unknown file), which this loop can only surface at the deadline, so the
# last attempt's output is printed then.
set -uo pipefail
bin="$1"
file_id="$2"
deadline=$(( $(date +%s) + 60 * 60 ))
log=$(mktemp)
while :; do
  if "$bin" autofix --file-id "$file_id" --list-analyses >"$log" 2>&1; then
    echo "KnoxIQ triage of ${file_id} completed"
    rm -f "$log"
    exit 0
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "::error::KnoxIQ triage of ${file_id} not completed in 60m; last check said:"
    tail -5 "$log"
    exit 1
  fi
  sleep 30
done
