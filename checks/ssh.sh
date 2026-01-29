
ssh_config_file="/etc/ssh/sshd_config"
SSHD_BACKUP_DONE=0


get_sshd_value(){

	local key=$1



	grep -Ei "^[[:space:]]*$key[[:space:]]+" "$ssh_config_file" | awk '{print $2}' | tail -n 1 
}


backup_sshd_config() {
	#To backup the ssh folder once
	
	if [ "$SSHD_BACKUP_DONE" -eq 1 ]; then
		return 0
	fi

	local backup="${ssh_config_file}_$(date '+%F_%H%M%S')"

	if ! cp -p "$ssh_config_file" "$backup" 2>/dev/null; then
		printf '\t- %s FIX: FAIL (backup failed)\n' "$ssh_config_file"
		return 1
	fi

	SSHD_BACKUP_DONE=1
	printf '\t- %s FIX: Backup created (%s)\n' "$ssh_config_file" "$backup"
	return 0
}


set_sshd_kv() {
        #To set KEY VALUE in sshd_config (replace if present, append if missing)
        local key="$1"
        local value="$2"

        # if key exists , replace the whole line
        if grep -qEi "^[[:space:]]*$key[[:space:]]+" "$ssh_config_file"; then
                
                sed -i -E "s|^[[:space:]]*($key)[[:space:]]+.*|\1 $value|I" "$ssh_config_file"
        else
                printf '\n%s %s\n' "$key" "$value" >> "$ssh_config_file"
        fi

        return 0
}



probe_permit_root_login(){


	if [ ! -f "$ssh_config_file" ]; then
		printf '\t-Missing/Unreadble File (%s)\n' "$ssh_config_file"
		return 2
	fi

	local ssh_config_file=/etc/ssh/sshd_config
        local value=$(get_sshd_value PermitRootLogin)

	if [ -z "$value" ]; then
		printf '\t- PermitRootLogin: WARN (Missing Key)\n'
		return 2
	fi

	case "$value" in
		no|prohibit-password)
			printf '\t- PermitRootLogin: OK (%s)\n' "$value"
			return 0
			;;
		yes)
			printf '\t- PermitRootLogin: FAIL (%s)\n' "$value"
			return 1
			;;
		*)
			printf '\t- PermitRootLogin: WARN (%s)\n' "$value"
			return 2
			;;
	esac


}

fix_permit_root_login() {
	if [ "$FIX_MODE" -ne 1 ]; then
                return 0
	fi
	if [ ! -f "$ssh_config_file" ]; then
	printf '\t- %s FIX: FAIL (missing/unreadable)\n' "$ssh_config_file"
	return 1
	fi

	backup_sshd_config || return 1
	set_sshd_kv "PermitRootLogin" "no"

        printf '\t- PermitRootLogin FIX: OK (set to no)\n'
        return 0
}




probe_password_authentication(){

	local ssh_config_file=/etc/ssh/sshd_config
	local value=$(get_sshd_value PasswordAuthentication)


	if [ ! -f "$ssh_config_file" ]; then
		printf '\t-Missing/Unreadble File (%s)\n' "$ssh_config_file"
		return 2
	fi

	if [ -z "$value" ]; then
               printf '\t- PasswordAuthentication: WARN (Missing Key)\n'
		return 2
	fi

        case "$value" in
                no)
			printf '\t- PasswordAuthentication: OK (%s)\n' "$value"
			return 0
			;;
		yes)
			printf '\t- PasswordAuthentication: WARN (%s)\n' "$value"
			return 2
			;;
		*)
			printf '\t- PasswordAuthentication: WARN (%s)\n' "$value"
			return 2
			;;
	esac


}

fix_password_authentication() {
	if [ "$FIX_MODE" -ne 1 ]; then
		return 0
	fi
	if [ ! -f "$ssh_config_file" ]; then
		printf '\t- %s FIX: FAIL (missing/unreadable)\n' "$ssh_config_file"
		return 1
	fi

	backup_sshd_config || return 1
	set_sshd_kv "PasswordAuthentication" "no"

	printf '\t- PasswordAuthentication FIX: OK (set to no)\n'
	return 0
}




probe_max_auth_tries(){

        local ssh_config_file=/etc/ssh/sshd_config
        local value=$(get_sshd_value MaxAuthTries)


        if [ ! -f "$ssh_config_file" ]; then
                printf '\t-Missing/Unreadble File (%s)\n' "$ssh_config_file"
                return 2
        fi

        if [ -z "$value" ]; then
               printf '\t- MaxAuthTries: WARN (Missing)\n'
                return 2
        fi

	if [ "$value" -le 4 ]; then
		printf '\t- MaxAuthTries: OK (%s)\n' "$value"
		return 0
	elif [ "$value" -le 6 ]; then
		printf '\t- MaxAuthTries: WARN (%s)\n' "$value"
		return 2
	else
		printf '\t- MaxAuthTries: FAIL (%s)\n' "$value"
		return 1
	fi

}

fix_max_auth_tries() {
        if [ "$FIX_MODE" -ne 1 ]; then
                return 0
        fi
        if [ ! -f "$ssh_config_file" ]; then
                printf '\t- %s FIX: FAIL (missing/unreadable)\n' "$ssh_config_file"
                return 1
        fi

        backup_sshd_config || return 1
        set_sshd_kv "MaxAuthTries" "4"

        printf '\t- MaxAuthTries FIX: OK (set to 4)\n'
        return 0
}

audit_ssh(){

	local rc=0

	probe_permit_root_login
	ret=$?
	#To implement fix for root login
	if [ "$ret" -ne 0 ] && [ "$FIX_MODE" -eq 1 ]; then
		fix_permit_root_login
		probe_permit_root_login
		ret=$?
        fi
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	#To implement fix for max auth tries
	probe_max_auth_tries
	ret=$?
	if [ "$ret" -ne 0 ] && [ "$FIX_MODE" -eq 1 ]; then
		fix_max_auth_tries
		probe_max_auth_tries
		ret=$?
        fi
	[ "$ret" -eq 1 ] && rc=1
        [ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	#To implement fix for passwd auth
	probe_password_authentication
	ret=$?
	if [ "$ret" -ne 0 ] && [ "$FIX_MODE" -eq 1 ]; then
		fix_password_authentication
		probe_password_authentication
		ret=$?
        fi
	[ "$ret" -eq 1 ] && rc=1
        [ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2
	
	return "$rc"
}


