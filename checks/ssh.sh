


get_sshd_value(){

	local key=$1



	grep -Ei "^[[:space:]]*$key[[:space:]]+" "$ssh_config_file" | awk '{print $2}' | tail -n 1 
}


probe_permit_root_login(){

	local ssh_config_file=/etc/ssh/sshd_config
	local value=$(get_sshd_value PermitRootLogin)


	if [ ! -f "$ssh_config_file" ]; then
		printf '\t-Missing/Unreadble File (%s)\n' "$ssh_config_file"
		return 2
	fi

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

audit_ssh(){

	local rc=0
	ret=$?

	probe_permit_root_login
	ret=$?
	[ "$ret" -eq 1 ] && return 1
	[ "$ret" -eq 2 ] && rc=2
	probe_max_auth_tries
	ret=$?
	[ "$ret" -eq 1 ] && return 1
        [ "$ret" -eq 2 ] && rc=2
	probe_password_authentication
	ret=$?
	[ "$ret" -eq 1 ] && return 1
        [ "$ret" -eq 2 ] && rc=2
	
	return "$rc"
}


