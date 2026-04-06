
# Log file paths to check permissions on (space-separated, overridable via scanner.conf)
LOG_FILES=${LOG_FILES:-"/var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/kern.log /var/log/audit/audit.log"}

# Maximum acceptable permissions (octal) for sensitive log files
LOG_FILE_MAX_PERMS=${LOG_FILE_MAX_PERMS:-640}


# ---- helpers ----------------------------------------------------------------

_svc_active() {
	local svc=$1
	command -v systemctl >/dev/null 2>&1 || return 2
	systemctl is-active --quiet "$svc" 2>/dev/null
}

_svc_enabled() {
	local svc=$1
	command -v systemctl >/dev/null 2>&1 || return 2
	systemctl is-enabled --quiet "$svc" 2>/dev/null
}

# Return the numeric permissions of a file (e.g. 640)
_file_perms() {
	stat -c '%a' "$1" 2>/dev/null
}

# Return 0 if $1 <= $2 (octal string comparison via decimal conversion)
_perms_ok() {
	local actual=$1 limit=$2
	[ "$(printf '%d' "0$actual")" -le "$(printf '%d' "0$limit")" ]
}


# ---- checks -----------------------------------------------------------------

check_logging_daemons() {

	printf '\nLogging Daemons (auditd / rsyslog / syslog-ng / journald):\n'

	local found=0
	local active_svcs=""
	local inactive_svcs=""

	# auditd — kernel-level audit daemon
	if _svc_active auditd; then
		printf '\t- auditd: ACTIVE\n'
		active_svcs="${active_svcs:+$active_svcs,}auditd"
		found=1
	else
		printf '\t- auditd: INACTIVE (kernel audit events not collected)\n'
		inactive_svcs="${inactive_svcs:+$inactive_svcs,}auditd"
	fi

	# rsyslog
	if _svc_active rsyslog; then
		printf '\t- rsyslog: ACTIVE\n'
		active_svcs="${active_svcs:+$active_svcs,}rsyslog"
		found=1
	else
		printf '\t- rsyslog: INACTIVE\n'
		inactive_svcs="${inactive_svcs:+$inactive_svcs,}rsyslog"
	fi

	# syslog-ng (alternative to rsyslog)
	if _svc_active syslog-ng; then
		printf '\t- syslog-ng: ACTIVE\n'
		active_svcs="${active_svcs:+$active_svcs,}syslog-ng"
		found=1
	fi

	# systemd-journald — always present on systemd systems
	if _svc_active systemd-journald; then
		printf '\t- systemd-journald: ACTIVE\n'
		active_svcs="${active_svcs:+$active_svcs,}journald"
		found=1
	else
		printf '\t- systemd-journald: INACTIVE\n'
		inactive_svcs="${inactive_svcs:+$inactive_svcs,}journald"
	fi

	# Need at least one syslog daemon (rsyslog or syslog-ng) AND journald
	local need_syslog=1
	for svc in rsyslog syslog-ng; do
		_svc_active "$svc" && need_syslog=0
	done

	if [ "$found" -eq 0 ]; then
		printf '\t- No active logging daemons detected\n'
		json_finding "$CURRENT_MODULE" "LoggingDaemons" "FAIL" "none_active" "6.1.3.1"
		return 1
	fi

	if [ "$need_syslog" -eq 1 ]; then
		json_finding "$CURRENT_MODULE" "LoggingDaemons" "WARN" \ "6.1.3.1"
			"active:${active_svcs:-none};inactive:${inactive_svcs}"
		return 2
	fi

	json_finding "$CURRENT_MODULE" "LoggingDaemons" "OK" "active:${active_svcs}" "6.1.3.1"
	return 0
}


check_auditd_enabled() {

	printf '\nauditd Enabled at Boot:\n'

	if ! command -v systemctl >/dev/null 2>&1; then
		printf '\t- SKIP: systemctl not available\n'
		json_finding "$CURRENT_MODULE" "AuditdEnabled" "ERR" "systemctl_unavailable" "6.2.1.2"
		return 2
	fi

	if _svc_enabled auditd; then
		printf '\t- auditd: enabled\n'
		json_finding "$CURRENT_MODULE" "AuditdEnabled" "OK" "enabled" "6.2.1.2"
		return 0
	fi

	printf '\t- auditd: NOT enabled at boot\n'
	json_finding "$CURRENT_MODULE" "AuditdEnabled" "WARN" "not_enabled" "6.2.1.2"
	return 2
}


check_log_file_permissions() {

	printf '\nLog File Permissions (max: %s):\n' "$LOG_FILE_MAX_PERMS"

	local found=0
	local bad_files=""

	for log_file in $LOG_FILES; do
		[ -e "$log_file" ] || continue

		local perms
		perms=$(_file_perms "$log_file")
		if [ -z "$perms" ]; then
			printf '\t- %s: unable to stat\n' "$log_file"
			continue
		fi

		if _perms_ok "$perms" "$LOG_FILE_MAX_PERMS"; then
			printf '\t- %s: OK (%s)\n' "$log_file" "$perms"
		else
			printf '\t- %s: FAIL (%s, expected <= %s)\n' \
				"$log_file" "$perms" "$LOG_FILE_MAX_PERMS"
			bad_files="${bad_files:+$bad_files,}${log_file}(${perms})"
			found=1
		fi
	done

	# Check if none of the log files exist at all
	local any_exist=0
	for log_file in $LOG_FILES; do
		[ -e "$log_file" ] && any_exist=1 && break
	done

	if [ "$any_exist" -eq 0 ]; then
		printf '\t- No log files found to check\n'
		json_finding "$CURRENT_MODULE" "LogFilePermissions" "ERR" "no_log_files_found" "6.1.3.4"
		return 2
	fi

	if [ "$found" -eq 0 ]; then
		printf '\t- All checked log files have acceptable permissions\n'
		json_finding "$CURRENT_MODULE" "LogFilePermissions" "OK" "none" "6.1.3.4"
		return 0
	fi
	json_finding "$CURRENT_MODULE" "LogFilePermissions" "FAIL" "$bad_files" "6.1.3.4"
	return 1
}


fix_log_file_permissions() {

	if [ "$FIX_MODE" -ne 1 ]; then
		return 1
	fi

	for log_file in $LOG_FILES; do
		[ -e "$log_file" ] || continue

		local perms
		perms=$(_file_perms "$log_file")
		[ -z "$perms" ] && continue

		if ! _perms_ok "$perms" "$LOG_FILE_MAX_PERMS"; then
			if chmod "$LOG_FILE_MAX_PERMS" "$log_file" 2>/dev/null; then
				printf '\t- %s FIX: OK (set to %s)\n' "$log_file" "$LOG_FILE_MAX_PERMS"
			else
				printf '\t- %s FIX: FAIL (chmod failed)\n' "$log_file"
			fi
		fi
	done

	return 0
}


check_journal_persistent() {

	printf '\nJournald Persistence:\n'

	local conf_file="/etc/systemd/journald.conf"
	local dropin_dir="/etc/systemd/journald.conf.d"

	if [ ! -f "$conf_file" ]; then
		printf '\t- SKIP: %s not found\n' "$conf_file"
		json_finding "$CURRENT_MODULE" "JournaldPersistent" "ERR" "conf_not_found" "6.1.2.4"
		return 2
	fi

	# Collect Storage= from main conf and any drop-ins; last value wins
	local storage=""
	storage=$(grep -h '^[[:space:]]*Storage=' "$conf_file" \
		"${dropin_dir}"/*.conf 2>/dev/null \
		| tail -1 | cut -d= -f2 | tr -d '[:space:]')

	case "${storage:-auto}" in
		persistent)
			printf '\t- Storage=persistent (logs survive reboots)\n'
			json_finding "$CURRENT_MODULE" "JournaldPersistent" "OK" "persistent" "6.1.2.4"
			return 0
			;;
		auto)
			# "auto" persists if /var/log/journal exists
			if [ -d /var/log/journal ]; then
				printf '\t- Storage=auto with /var/log/journal present (persistent)\n'
				json_finding "$CURRENT_MODULE" "JournaldPersistent" "OK" "auto_persistent" "6.1.2.4"
				return 0
			fi
			printf '\t- Storage=auto but /var/log/journal absent (volatile — logs lost on reboot)\n'
			json_finding "$CURRENT_MODULE" "JournaldPersistent" "WARN" "auto_volatile" "6.1.2.4"
			return 2
			;;
		volatile|none)
			printf '\t- Storage=%s (logs are NOT persisted to disk)\n' "$storage"
			json_finding "$CURRENT_MODULE" "JournaldPersistent" "WARN" "storage_${storage}" "6.1.2.4"
			return 2
			;;
		*)
			printf '\t- Storage=%s (unknown value)\n' "$storage"
			json_finding "$CURRENT_MODULE" "JournaldPersistent" "ERR" "unknown_storage:${storage}" "6.1.2.4"
			return 2
			;;
	esac
}


# ---- module entry point -----------------------------------------------------

audit_logs() {

	local rc=0
	local ret

	check_logging_daemons
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_auditd_enabled
	ret=$?
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_log_file_permissions
	ret=$?
	if [ "$ret" -ne 0 ]; then
		if [ "$FIX_MODE" -eq 1 ]; then
			fix_log_file_permissions
			check_log_file_permissions
			ret=$?
		fi
		[ "$ret" -eq 1 ] && rc=1
		[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2
	fi

	check_journal_persistent
	ret=$?
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	return "$rc"
}
