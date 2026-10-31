#!/usr/bin/env bash
# End-to-end smoke test against the deterministic loopback lab.
#
# This script exercises the same policy, execution, evidence, validation,
# review, reporting, and audit paths as an operator, but only against
# 127.0.0.1. It never contacts a public target, Docker, Exegol, or a model
# provider.
#
# Environment:
#   HUNTRESS_SMOKE_KEEP=1       keep the temporary data directory
#   HUNTRESS_SMOKE_DATA_DIR=... use an explicit (empty) data directory
#   LAB_PORT=...                use a fixed lab port instead of a free one
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SMOKE_ROOT="${HUNTRESS_SMOKE_ROOT:-/tmp/opencode}"
mkdir -p "$SMOKE_ROOT"

if [[ -n "${HUNTRESS_SMOKE_DATA_DIR:-}" ]]; then
  DATA_DIR="$HUNTRESS_SMOKE_DATA_DIR"
  OWN_DATA_DIR=0
  if [[ -e "$DATA_DIR" ]]; then
    echo "error: HUNTRESS_SMOKE_DATA_DIR must not already exist: $DATA_DIR" >&2
    exit 1
  fi
else
  DATA_DIR="$(mktemp -d "$SMOKE_ROOT/huntress-smoke.XXXXXX")"
  OWN_DATA_DIR=1
fi

LAB_LOG="$DATA_DIR/lab.log"
LAB_PID=""
CLEANED=0

cleanup() {
  local status=$?
  if [[ "$CLEANED" -eq 1 ]]; then
    return
  fi
  CLEANED=1
  if [[ -n "$LAB_PID" ]] && kill -0 "$LAB_PID" 2>/dev/null; then
    kill "$LAB_PID" 2>/dev/null || true
    wait "$LAB_PID" 2>/dev/null || true
  fi
  if [[ "$OWN_DATA_DIR" -eq 1 && "${HUNTRESS_SMOKE_KEEP:-0}" != "1" ]]; then
    rm -rf "$DATA_DIR"
  else
    echo "smoke data retained: $DATA_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

step() {
  printf '\n==> %s\n' "$*"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

json_get() {
  "$PYTHON_BIN" - "$1" "$2" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[int(part)] if isinstance(value, list) else value[part]
print(value)
PY
}

json_assert() {
  "$PYTHON_BIN" - "$1" "$2" "$3" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[int(part)] if isinstance(value, list) else value[part]
try:
    expected = json.loads(sys.argv[3])
except json.JSONDecodeError:
    expected = sys.argv[3]
if value != expected:
    raise SystemExit(f"assertion failed: {sys.argv[2]}={value!r}, expected {expected!r}")
PY
}

select_finding() {
  "$PYTHON_BIN" - "$1" "$2" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
matches = [
    finding
    for finding in payload["outcome"]["findings"]
    if finding["finding_type"] == sys.argv[2]
]
if not matches:
    types = [finding["finding_type"] for finding in payload["outcome"]["findings"]]
    raise SystemExit(f"no {sys.argv[2]!r} finding in scan output; got {types}")
print(matches[0]["finding_id"])
PY
}

pick_port() {
  "$PYTHON_BIN" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN=python
fi
require_command "$PYTHON_BIN"
require_command uv
require_command curl

export HUNTRESS_DATA_DIR="$DATA_DIR"
export HUNTRESS_MODE=lab
export HUNTRESS_OPERATOR=smoke-operator
export HUNTRESS_EXEGOL_BACKEND=auto
export HUNTRESS_REASONING_ENABLED=false
export HUNTRESS_CONFIG_FILE="${HUNTRESS_CONFIG_FILE:-$ROOT_DIR/config/defaults.toml}"

LAB_HOST=127.0.0.1
LAB_PORT="${LAB_PORT:-$(pick_port)}"
LAB_URL="http://$LAB_HOST:$LAB_PORT"
REVIEWER="Smoke Reviewer"

step "Starting deterministic lab on $LAB_URL"
uv run huntress lab serve --host "$LAB_HOST" --port "$LAB_PORT" >"$LAB_LOG" 2>&1 &
LAB_PID=$!

ready=0
for _ in $(seq 1 100); do
  if curl -fsS --max-time 1 "$LAB_URL/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$LAB_PID" 2>/dev/null; then
    echo "error: lab server exited before becoming ready" >&2
    cat "$LAB_LOG" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  echo "error: lab server did not become ready at $LAB_URL" >&2
  cat "$LAB_LOG" >&2
  exit 1
fi

step "Initializing a fresh data directory: $DATA_DIR"
uv run huntress init >/dev/null
uv run huntress health --no-probe-exegol >/dev/null

step "Creating the lab engagement"
uv run huntress --json engagement create \
  --name "policy-enforced lab smoke" \
  --mode lab \
  --program-id local-lab \
  --notes "scripts/lab-smoke.sh" >"$DATA_DIR/engagement.json"
ENGAGEMENT_ID="$(json_get "$DATA_DIR/engagement.json" engagement_id)"

step "Sealing a low-risk scope for $LAB_URL"
uv run huntress --json scope set "$ENGAGEMENT_ID" \
  --asset "url:$LAB_URL" \
  --authorization-ref "smoke:local-lab" \
  --approved-by "$REVIEWER" \
  --program-id local-lab \
  --hours 1 \
  --max-risk low \
  --approval-note "Local loopback smoke test." >"$DATA_DIR/scope.json"
SCOPE_ID="$(json_get "$DATA_DIR/scope.json" scope_id)"

step "Registering the approved target"
uv run huntress --json target sync "$ENGAGEMENT_ID" >"$DATA_DIR/targets.json"
TARGET_ID="$(json_get "$DATA_DIR/targets.json" 0.target_id)"

step "Running the preauthorized exposed-files profile"
uv run huntress --json scan "$ENGAGEMENT_ID" \
  --profile http.exposed_files \
  --target "$TARGET_ID" >"$DATA_DIR/scan.json"
json_assert "$DATA_DIR/scan.json" decision.allowed true
json_assert "$DATA_DIR/scan.json" outcome.backend builtin
TOOL_FINDING_ID="$(select_finding "$DATA_DIR/scan.json" http.env_exposure)"

step "Validating $TOOL_FINDING_ID through all six gates"
uv run huntress --json validate "$ENGAGEMENT_ID" \
  --finding "$TOOL_FINDING_ID" \
  --bug-class bug_env_exposure \
  --title "Publicly exposed dotenv configuration" \
  --claim "The approved lab target served a dotenv file with credential-shaped assignments." \
  --severity high \
  --impact "Credential-shaped configuration was disclosed without authentication." \
  --exploitability "No authentication is required to read the exposed file." \
  --uncertainty "Lab fixture only; no real credentials are present." >"$DATA_DIR/validation.json"
VALIDATED_FINDING_ID="$(json_get "$DATA_DIR/validation.json" finding.finding_id)"
json_assert "$DATA_DIR/validation.json" status passed

step "Recording the named-human review"
uv run huntress --json review "$VALIDATED_FINDING_ID" \
  --reviewer "$REVIEWER" \
  --decision approved \
  --notes "Verified the preserved response and dotenv assignments." >"$DATA_DIR/review.json"

step "Drafting and approving the report"
uv run huntress --json report draft "$ENGAGEMENT_ID" \
  --finding "$VALIDATED_FINDING_ID" \
  --title "Lab exposed configuration report" \
  --summary "The loopback lab exposed a dotenv file containing credential-shaped assignments." \
  --impact "Unauthenticated configuration disclosure." \
  --remediation "Remove the file from the web root and rotate any exposed secrets." \
  --destination manual >"$DATA_DIR/report.json"
REPORT_ID="$(json_get "$DATA_DIR/report.json" report_id)"
json_assert "$DATA_DIR/report.json" status draft

uv run huntress --json report request "$REPORT_ID" >"$DATA_DIR/report-request.json"
json_assert "$DATA_DIR/report-request.json" status pending_approval

uv run huntress --json report approve "$REPORT_ID" \
  --by "$REVIEWER" \
  --destination manual \
  --note "Approved for local lab submission." >"$DATA_DIR/report-approve.json"
json_assert "$DATA_DIR/report-approve.json" status approved

step "Submitting the approved report"
uv run huntress --json report submit "$REPORT_ID" >"$DATA_DIR/report-submit.json"
json_assert "$DATA_DIR/report-submit.json" status submitted

step "Verifying the audit chain and terminal state"
uv run huntress --json audit verify --engagement "$ENGAGEMENT_ID" >"$DATA_DIR/audit.json"
json_assert "$DATA_DIR/audit.json" valid true
uv run huntress --json status "$ENGAGEMENT_ID" >"$DATA_DIR/status.json"
json_assert "$DATA_DIR/status.json" engagement.state CLOSED

printf '\nLab smoke passed.\n'
printf '  engagement: %s\n' "$ENGAGEMENT_ID"
printf '  scope:      %s\n' "$SCOPE_ID"
printf '  target:     %s\n' "$TARGET_ID"
printf '  finding:    %s\n' "$VALIDATED_FINDING_ID"
printf '  report:     %s\n' "$REPORT_ID"
printf '  audit:      valid\n'
