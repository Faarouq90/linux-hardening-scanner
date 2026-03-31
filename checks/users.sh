

PASSWORD_MAX_AGE=${PASSWORD_MAX_AGE:-90}


check_uid0_nonroot() {

	printf '\nUID 0 Accounts (non-root):\n'

	local found=0
	local users=""
	while IFS=: read -r username _ uid _; do
		if [ "$uid" -eq 0 ] && [ "$username" != "root" ]; then
			printf '\t- %s (UID 0)\n' "$username"
			users="${users:+$users,}$username"
			found=1
		fi
	done < /etc/passwd

	if [ "$found" -eq 0 ]; then
		printf '\t- None detected\n'
		json_finding "$CURRENT_MODULE" "UID0NonRoot" "OK" "none"
		return 0
	fi
	json_finding "$CURRENT_MODULE" "UID0NonRoot" "FAIL" "$users"
	return 1
}


check_empty_passwords() {

	printf '\nEmpty Passwords:\n'

	if [ ! -r /etc/shadow ]; then
		printf '\t- /etc/shadow not readable (run as root)\n'
		json_finding "$CURRENT_MODULE" "EmptyPasswords" "ERR" "shadow_unreadable"
		return 2
	fi

	local found=0
	local users=""
	while IFS=: read -r username password _; do
		if [ -z "$password" ]; then
			printf '\t- %s (empty password)\n' "$username"
			users="${users:+$users,}$username"
			found=1
		fi
	done < /etc/shadow

	if [ "$found" -eq 0 ]; then
		printf '\t- None detected\n'
		json_finding "$CURRENT_MODULE" "EmptyPasswords" "OK" "none"
		return 0
	fi
	json_finding "$CURRENT_MODULE" "EmptyPasswords" "FAIL" "$users"
	return 1
}


fix_empty_passwords() {

	if [ "$FIX_MODE" -ne 1 ]; then
		return 1
	fi

	if [ ! -r /etc/shadow ]; then
		printf '\t- /etc/shadow not readable\n'
		return 1
	fi

	while IFS=: read -r username password _; do
		if [ -z "$password" ]; then
			if passwd -l "$username" >/dev/null 2>&1; then
				printf '\t- %s FIX: OK (account locked)\n' "$username"
			else
				printf '\t- %s FIX: FAIL (could not lock account)\n' "$username"
			fi
		fi
	done < /etc/shadow

	return 0
}


check_locked_accounts() {

	printf '\nLocked User Accounts (UID >= %s):\n' "${USER_UID_MIN:-100}"

	if [ ! -r /etc/shadow ]; then
		printf '\t- /etc/shadow not readable (run as root)\n'
		json_finding "$CURRENT_MODULE" "LockedAccounts" "ERR" "shadow_unreadable"
		return 2
	fi

	local found=0
	local users=""
	while IFS=: read -r username _ uid _; do
		[ "$uid" -lt "${USER_UID_MIN:-100}" ] && continue

		local password
		password=$(grep -m1 "^${username}:" /etc/shadow 2>/dev/null | cut -d: -f2)

		case "$password" in
			'!'*|'!!'*)
				printf '\t- %s (locked, UID %s)\n' "$username" "$uid"
				users="${users:+$users,}$username"
				found=1
				;;
		esac
	done < /etc/passwd

	if [ "$found" -eq 0 ]; then
		printf '\t- None detected\n'
		json_finding "$CURRENT_MODULE" "LockedAccounts" "OK" "none"
		return 0
	fi
	json_finding "$CURRENT_MODULE" "LockedAccounts" "WARN" "$users"
	return 2
}


check_no_shell_users() {

	printf '\nAccounts with Invalid/Missing Shell (UID >= %s):\n' "${USER_UID_MIN:-100}"

	local found=0
	local users=""
	while IFS=: read -r username _ uid _ _ _ shell; do
		[ "$uid" -lt "${USER_UID_MIN:-100}" ] && continue

		if [ -z "$shell" ]; then
			printf '\t- %s (no shell defined)\n' "$username"
			users="${users:+$users,}$username"
			found=1
		elif [ "$shell" != "/bin/false" ] && \
		     [ "$shell" != "/sbin/nologin" ] && \
		     [ "$shell" != "/usr/sbin/nologin" ]; then
			if [ ! -f "$shell" ]; then
				printf '\t- %s (shell not found: %s)\n' "$username" "$shell"
				users="${users:+$users,}$username"
				found=1
			fi
		fi
	done < /etc/passwd

	if [ "$found" -eq 0 ]; then
		printf '\t- None detected\n'
		json_finding "$CURRENT_MODULE" "InvalidShellUsers" "OK" "none"
		return 0
	fi
	json_finding "$CURRENT_MODULE" "InvalidShellUsers" "WARN" "$users"
	return 2
}


check_password_age() {

	printf '\nStale Passwords (older than %s days):\n' "${PASSWORD_MAX_AGE:-90}"

	if [ ! -r /etc/shadow ]; then
		printf '\t- /etc/shadow not readable (run as root)\n'
		json_finding "$CURRENT_MODULE" "PasswordAge" "ERR" "shadow_unreadable"
		return 2
	fi

	local today threshold found
	today=$(( $(date +%s) / 86400 ))
	threshold="${PASSWORD_MAX_AGE:-90}"
	found=0
	local users=""

	while IFS=: read -r username password last_changed _ max_age _; do
		# skip locked, unset, or no-login accounts
		case "$password" in
			'!'*|'!!'*|'*'|'') continue ;;
		esac

		# skip if last_changed is missing or 0 (must change on next login)
		if [ -z "$last_changed" ] || [ "$last_changed" -eq 0 ]; then
			continue
		fi

		local age=$(( today - last_changed ))

		if [ "$age" -gt "$threshold" ]; then
			printf '\t- %s (password age: %s days)\n' "$username" "$age"
			users="${users:+$users,}$username(${age}d)"
			found=1
		fi
	done < /etc/shadow

	if [ "$found" -eq 0 ]; then
		printf '\t- None detected\n'
		json_finding "$CURRENT_MODULE" "PasswordAge" "OK" "none"
		return 0
	fi
	json_finding "$CURRENT_MODULE" "PasswordAge" "WARN" "$users"
	return 2
}


fix_password_age() {

	if [ "$FIX_MODE" -ne 1 ]; then
		return 1
	fi

	if [ ! -r /etc/shadow ]; then
		printf '\t- /etc/shadow not readable\n'
		return 1
	fi

	local today threshold
	today=$(( $(date +%s) / 86400 ))
	threshold="${PASSWORD_MAX_AGE:-90}"

	while IFS=: read -r username password last_changed _ max_age _; do
		case "$password" in
			'!'*|'!!'*|'*'|'') continue ;;
		esac

		if [ -z "$last_changed" ] || [ "$last_changed" -eq 0 ]; then
			continue
		fi

		local age=$(( today - last_changed ))

		if [ "$age" -gt "$threshold" ]; then
			if chage -d 0 "$username" 2>/dev/null; then
				printf '\t- %s FIX: OK (password expiry forced on next login)\n' "$username"
			else
				printf '\t- %s FIX: FAIL (chage failed)\n' "$username"
			fi
		fi
	done < /etc/shadow

	return 0
}


audit_users() {

	local rc=0
	local ret

	check_uid0_nonroot
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_empty_passwords
	ret=$?
	if [ "$ret" -ne 0 ]; then
		if [ "$FIX_MODE" -eq 1 ]; then
			fix_empty_passwords
			check_empty_passwords
			ret=$?
		fi
		[ "$ret" -eq 1 ] && rc=1
		[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2
	fi

	check_locked_accounts
	ret=$?
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_no_shell_users
	ret=$?
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_password_age
	ret=$?
	if [ "$ret" -ne 0 ]; then
		if [ "$FIX_MODE" -eq 1 ]; then
			fix_password_age
			check_password_age
			ret=$?
		fi
		[ "$ret" -eq 1 ] && rc=1
		[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2
	fi

	return "$rc"
}
