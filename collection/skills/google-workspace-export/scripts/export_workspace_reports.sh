#!/usr/bin/env bash
set -euo pipefail

START=""
END=""
OUTPUT_DIR=""
PAGE_LIMIT=50
MAX_RESULTS=1000
APPS="admin,drive,login,token,access_evaluation,gemini_in_workspace_apps,user_accounts"

usage() {
  cat >&2 <<'EOF'
Usage: export_workspace_reports.sh --start <iso-utc> --end <iso-utc> --output-dir <dir> [options]

Options:
  --apps <csv>           Comma-separated Admin Reports applications to export.
  --page-limit <n>       Maximum pages per application. Default: 50.
  --max-results <n>      API maxResults per page. Default: 1000.

Example:
  ./export_workspace_reports.sh \
    --start 2026-07-06T00:00:00Z \
    --end 2026-07-11T23:59:59Z \
    --output-dir evidence/google-workspace/week
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --start) START="$2"; shift 2 ;;
    --end) END="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --apps) APPS="$2"; shift 2 ;;
    --page-limit) PAGE_LIMIT="$2"; shift 2 ;;
    --max-results) MAX_RESULTS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$START" || -z "$END" || -z "$OUTPUT_DIR" ]]; then
  usage
  exit 1
fi

if ! command -v gws >/dev/null 2>&1; then
  echo "gws not found in PATH" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
MANIFEST="$OUTPUT_DIR/export_manifest.json"

echo "{" >"$MANIFEST"
echo "  \"start\": \"$START\"," >>"$MANIFEST"
echo "  \"end\": \"$END\"," >>"$MANIFEST"
echo "  \"apps\": \"$APPS\"," >>"$MANIFEST"
echo "  \"files\": [" >>"$MANIFEST"
FIRST_FILE=1

for APP in ${APPS//,/ }; do
  OUT_FILE="$OUTPUT_DIR/$APP.ndjson"
  ERR_FILE="$OUTPUT_DIR/$APP.err"
  : >"$OUT_FILE"
  : >"$ERR_FILE"
  PAGE=0
  PAGE_TOKEN=""

  while :; do
    PARAMS="$(python3 - "$APP" "$START" "$END" "$MAX_RESULTS" "$PAGE_TOKEN" <<'PY'
import json
import sys
app, start, end, max_results, page_token = sys.argv[1:6]
params = {
    "userKey": "all",
    "applicationName": app,
    "startTime": start,
    "endTime": end,
    "maxResults": int(max_results),
}
if page_token:
    params["pageToken"] = page_token
print(json.dumps(params, separators=(",", ":")))
PY
)"

    RESPONSE_FILE="$(mktemp)"
    if ! gws reports activities list --params "$PARAMS" >"$RESPONSE_FILE" 2>>"$ERR_FILE"; then
      rm -f "$RESPONSE_FILE"
      break
    fi
    cat "$RESPONSE_FILE" >>"$OUT_FILE"
    printf '\n' >>"$OUT_FILE"

    NEXT_PAGE_TOKEN="$(python3 - "$RESPONSE_FILE" <<'PY'
import json
import sys
from pathlib import Path
try:
    payload = json.loads(Path(sys.argv[1]).read_text())
except Exception:
    payload = {}
print(payload.get("nextPageToken", ""))
PY
)"
    rm -f "$RESPONSE_FILE"

    PAGE=$((PAGE + 1))
    if [[ -z "$NEXT_PAGE_TOKEN" || "$PAGE" -ge "$PAGE_LIMIT" ]]; then
      break
    fi
    PAGE_TOKEN="$NEXT_PAGE_TOKEN"
  done

  if [[ "$FIRST_FILE" -eq 0 ]]; then echo "," >>"$MANIFEST"; fi
  FIRST_FILE=0
  BYTES=$(wc -c <"$OUT_FILE" | tr -d ' ')
  ERR_BYTES=$(wc -c <"$ERR_FILE" | tr -d ' ')
  printf '    {"application":"%s","file":"%s.ndjson","error_file":"%s.err","bytes":%s,"error_bytes":%s}' "$APP" "$APP" "$APP" "$BYTES" "$ERR_BYTES" >>"$MANIFEST"
done

USAGE_DATE="$(python3 - "$END" <<'PY'
from datetime import datetime, timedelta, timezone
import sys
moment = datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")).astimezone(timezone.utc)
print((moment - timedelta(days=1)).date().isoformat())
PY
)"

if gws reports customerUsageReports get --params "{\"date\":\"$USAGE_DATE\"}" >"$OUTPUT_DIR/customerUsageReports-$USAGE_DATE.json" 2>"$OUTPUT_DIR/customerUsageReports-$USAGE_DATE.err"; then
  :
else
  true
fi

echo "" >>"$MANIFEST"
echo "  ]," >>"$MANIFEST"
echo "  \"customer_usage_date\": \"$USAGE_DATE\"" >>"$MANIFEST"
echo "}" >>"$MANIFEST"
echo "Export complete: $OUTPUT_DIR"
