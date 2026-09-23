#!/usr/bin/env bash
# Usage: wait_scan.sh <file_id>. Exits 0 when the static scan is done; 1 on
# timeout or a 4xx response (e.g. bad/expired token) that retrying cannot fix.
# Never returns early: a partial scan lacks findings and would score as "fixed".
set -uo pipefail
file_id="$1"
url="${APPKNOX_API_HOST}api/v3/files/${file_id}/scans_status_summary"
deadline=$(( $(date +%s) + 45 * 60 ))
while :; do
  # -w appends "\n<http_code>" to stdout so we can branch on the status
  # without a temp file; no -f here since we need the 4xx/5xx distinction
  # ourselves. curl's own exit code still covers network-level failures
  # (DNS, connect, TLS, timeout), which are retried like a 5xx.
  if response=$(curl -s --max-time 60 -H "Authorization: Token $APPKNOX_ACCESS_TOKEN" \
      -w '\n%{http_code}' "$url"); then
    http_status="${response##*$'\n'}"
    body="${response%$'\n'*}"
    case "$http_status" in
      2??)
        done_flag=$(echo "$body" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(int(bool(d.get("is_static_done")) or d.get("static_scan_progress", 0) >= 100))')
        [ "$done_flag" = "1" ] && { echo "static scan of ${file_id} finished"; exit 0; }
        ;;
      4??)
        echo "::error::scan status check for ${file_id} got HTTP ${http_status}; not retrying (check APPKNOX_ACCESS_TOKEN / file id)"
        exit 1
        ;;
      *)
        echo "status check for ${file_id} got HTTP ${http_status}; retrying"
        ;;
    esac
  else
    echo "status check failed (curl exit $?); retrying"
  fi
  [ "$(date +%s)" -ge "$deadline" ] && { echo "::error::scan ${file_id} not finished in 45m"; exit 1; }
  sleep 30
done
