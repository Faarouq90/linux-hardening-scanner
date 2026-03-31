

record_pass() { PASS=$((PASS + 1)); printf '\n[PASS] %s\n' "$1"; }
record_warn() { WARN=$((WARN + 1)); printf '\n[WARN] %s\n' "$1"; }
record_fail() { FAIL=$((FAIL + 1)); printf '\n[FAIL] %s\n' "$1"; }
record_skip() { SKIP=$((SKIP + 1)); printf '\n[SKIP] %s\n' "$1"; }
record_err()  { ERR=$((ERR + 1));  printf '\n[ERR ] %s\n' "$1"; }


# ---------------------------------------------------------------------------
# JSON reporting helpers
# ---------------------------------------------------------------------------

# Append a finding line to the findings temp file.
# Usage: json_finding <module> <check> <status> <value>
json_finding() {
    [ -z "${JSON_TMP:-}" ] && return 0
    local module="$1" check="$2" status="$3" value="$4"
    # escape pipe chars so IFS='|' read is safe
    value="${value//|/\\|}"
    printf '%s|%s|%s|%s\n' "$module" "$check" "$status" "$value" >> "$JSON_TMP"
}

# Record the aggregate status for a module (called from run_check).
_json_record_module() {
    [ -z "${JSON_MODULES_TMP:-}" ] && return 0
    printf '%s|%s\n' "$1" "$2" >> "$JSON_MODULES_TMP"
}

# Escape a string for embedding in a JSON double-quoted value.
_json_str() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# Assemble and write the JSON report file.
# Usage: write_json_report <json_file> <started> [scan_root]
write_json_report() {
    local json_file="$1"
    local started="$2"
    local scan_root="${3:-/}"

    # Summarise module-level statuses
    local pass=0 warn=0 fail=0 err=0
    if [ -s "${JSON_MODULES_TMP:-}" ]; then
        while IFS='|' read -r _mod stat; do
            case "$stat" in
                PASS) pass=$((pass+1)) ;;
                WARN) warn=$((warn+1)) ;;
                FAIL) fail=$((fail+1)) ;;
                ERR)  err=$((err+1))  ;;
            esac
        done < "$JSON_MODULES_TMP"
    fi

    local overall="PASS"
    [ "$warn" -gt 0 ] && overall="WARN"
    [ "$fail" -gt 0 ] && overall="FAIL"
    [ "$err"  -gt 0 ] && overall="ERROR"

    {
        printf '{\n'
        printf '  "scan": {\n'
        printf '    "started": "%s",\n' "$(_json_str "$started")"
        printf '    "scan_root": "%s"\n' "$(_json_str "$scan_root")"
        printf '  },\n'
        printf '  "results": [\n'

        local prev_module="" first_module=1 first_finding=1

        if [ -s "${JSON_TMP:-}" ]; then
            while IFS='|' read -r module check fstatus value; do
                [ -z "$module" ] && continue

                if [ "$module" != "$prev_module" ]; then
                    # close previous module block
                    if [ "$first_module" -eq 0 ]; then
                        printf '\n      ]\n    },\n'
                    fi
                    # look up this module's aggregate status
                    local mstatus
                    mstatus=$(grep -F "${module}|" "$JSON_MODULES_TMP" 2>/dev/null \
                              | tail -1 | cut -d'|' -f2)
                    printf '    {\n'
                    printf '      "module": "%s",\n' "$(_json_str "$module")"
                    printf '      "status": "%s",\n' "${mstatus:-PASS}"
                    printf '      "findings": ['
                    first_finding=1
                    first_module=0
                    prev_module="$module"
                fi

                [ "$first_finding" -eq 0 ] && printf ','
                printf '\n        {"check":"%s","status":"%s","value":"%s"}' \
                    "$(_json_str "$check")" "$fstatus" "$(_json_str "$value")"
                first_finding=0
            done < "$JSON_TMP"
        fi

        # close last module block
        if [ "$first_module" -eq 0 ]; then
            printf '\n      ]\n    }\n'
        fi

        printf '  ],\n'
        printf '  "summary": {\n'
        printf '    "pass": %s,\n' "$pass"
        printf '    "warn": %s,\n' "$warn"
        printf '    "fail": %s,\n' "$fail"
        printf '    "err": %s,\n'  "$err"
        printf '    "overall": "%s"\n' "$overall"
        printf '  }\n'
        printf '}\n'
    } > "$json_file"

    rm -f "$JSON_TMP" "$JSON_MODULES_TMP"
}
