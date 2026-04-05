#!/bin/bash


FIX_MODE=0

for arg in "$@"; do
	case "$arg" in
		--fix)
			FIX_MODE=1
			;;
		--help|-h)
			printf 'Usage: %s [--fix] [--help]\n' "$0"
			exit 0
			;;
		*)
			printf 'Unknown option: %s\n' "$arg"
			printf 'Usage: %s [--fix] [--help]\n' "$0"
			exit 1
			;;
	esac
done

export FIX_MODE


set -u

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$BASE_DIR/libs"
CHECKS_DIR="$BASE_DIR/checks"
CONF_FILE="$BASE_DIR/config/scanner.conf"
REPORT_DIR="$BASE_DIR/reports"
REPORT_STAMP=$(date '+%F_%H%M%S')
REPORT_FILE="$REPORT_DIR/report_${REPORT_STAMP}.txt"
JSON_FILE="$REPORT_DIR/report_${REPORT_STAMP}.json"
JSON_TMP=$(mktemp)
JSON_MODULES_TMP=$(mktemp)
export JSON_TMP JSON_MODULES_TMP
CURRENT_MODULE=""
export CURRENT_MODULE
mkdir -p "$REPORT_DIR"
chmod 750 "$REPORT_DIR"


PASS=0; WARN=0; FAIL=0; SKIP=0; ERR=0

# Load libs
source "$LIB_DIR/output.sh"

# Load config 
if [ -f "$CONF_FILE" ]; then
	source "$CONF_FILE"
else
	record_err "Missing config/scanner.conf"
	exit 2
fi

# Load modules
source "$CHECKS_DIR/permissions.sh"
source "$CHECKS_DIR/ssh.sh"
source "$CHECKS_DIR/users.sh"
source "$CHECKS_DIR/services.sh"
source "$CHECKS_DIR/network.sh"
source "$CHECKS_DIR/logs.sh"



run_check() {
	local name="$1"
	local fn="$2"

	printf '\n== %s ==\n' "$name"

	if ! command -v "$fn" >/dev/null 2>&1; then
		record_err "Missing function: $fn"
		_json_record_module "$name" "ERR"
		return 2
	fi

	CURRENT_MODULE="$name"
	"$fn"
	local rc=$?

	case "$rc" in
		0) record_pass "$name"; _json_record_module "$name" "PASS" ;;
		1) record_fail "$name"; _json_record_module "$name" "FAIL" ;;
		2) record_warn "$name"; _json_record_module "$name" "WARN" ;;
		*) record_err  "$name returned invalid code ($rc)"; _json_record_module "$name" "ERR"; return 2 ;;
	esac

	return 0
}

SCAN_START=$(date '+%F %T')

{
printf '======================================\n'
printf ' Linux Hardening & Compliance Scan\n'
printf ' Started: %s\n' "$SCAN_START"
printf ' Scan root: %s\n' "${SCAN_ROOT:-/}"
printf '======================================\n'



run_check "Filesystem Permissions" audit_permissions
run_check "SSH Configuration" audit_ssh
run_check "User Accounts" audit_users
run_check "Running Services" audit_services
run_check "Network Configuration" audit_network
run_check "Logging Configuration" audit_logs


printf '\n======================================\n'
printf ' Summary\n'
printf '======================================\n'
printf 'PASS: %s\nWARN: %s\nFAIL: %s\nERR : %s\n' "$PASS" "$WARN" "$FAIL" "$ERR"

if [ "$ERR" -gt 0 ]; then
  printf '\nOverall status: ERROR\n'
  exit 2
fi

if [ "$FAIL" -gt 0 ]; then
  printf '\nOverall status: FAIL\n'
  exit 1
fi

printf '\nOverall status: PASS\n'
exit 0
} 2>&1 | tee "$REPORT_FILE"

write_json_report "$JSON_FILE" "$SCAN_START" "${SCAN_ROOT:-/}"
chmod 440 "$REPORT_FILE" "$JSON_FILE"
printf '\nJSON report: %s\n' "$JSON_FILE"
