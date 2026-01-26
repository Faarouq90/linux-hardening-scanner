

check_world_writable_files(){

	printf '\nWorld Writable Files:\n'
	result=$(find $HOME -type f -perm -0002 -print 2> /dev/null)

	if [ -z "$result" ]; then 
		printf '\t- None Detected\n'
		return 0
	else
		printf '%s\n' "$result" | sed 's/^/\t- /'
		return 2
	fi
	
}


check_world_writable_dirs(){

	printf '\nWord Writable Directories:\n'
	result=$(find $HOME \
		\( -path "/sys/*" -o -path "/dev/*" -o -path "/proc/*" \) -prune -o \
		-type d -perm -0002 -print 2> /dev/null)

	if [ -z "$result" ]; then
		printf '\t- None Detected\n'
		return 0
	else
		printf '%s\n' "$result" | sed 's/^/\t- /'
		return 2
	fi
}


check_suid_sgid(){

	printf '\nSUID/SGID binaries:\n'
	found=0

    # SUID
	while read -r file; do
		[ -z "$file" ] && continue
		printf '\t- %s (SUID)\n' "$file"
		found=1
	done < <(
		find /home \
			\( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" \)-prune -o \
			-type f -perm -4000 -print 2>/dev/null
	)

    # SGID
	while read -r file; do
		[ -z "$file" ] && continue
		printf '\t- %s (SGID)\n' "$file"
		found=1
	done < <(
		find /home \
			\( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" \) -prune -o \
			-type f -perm -2000 -print 2>/dev/null
	)

	if [ "$found" -eq 0 ]; then
		printf '\t-None detected.\n'
		return 0
	else
		return 2
	fi


}

check_shadow_perms(){

	local file=/etc/shadow

	actual_perm=$(stat -c %a "$file" 2> /dev/null)
	required_perm=600
	acceptable_perm=640

	printf '\nCrtictical File (/etc/shadow)'

	if [ ! -e "$file" ]; then
                printf '\n %s FAIL (missing)\n' "$file"
                return 1
        fi

	if [ ! -f "$file" ]; then
		printf '\n %s is not a regular file\n' "$file"
		return 1
	fi

	
	if [ "$actual_perm" = "$required_perm" ] || [ "$actual_perm" = "$acceptable_perm" ]; then
		printf '\n\t- File Permission OK (%s)\n' "$actual_perm"
		return 0
	else
		printf '\n\t- File Permission FAIL (%s)\n' "$actual_perm"
		return 1
	fi
}

fix_shadow_perms(){

	local file=/etc/shadow
	local backup="${file}_$(date '+%F_%H%M%S')"

	if [ "$FIX_MODE" -ne 1 ]; then
		return 1
	fi

	if [ ! -e "$file" ]; then
		printf '\t- %s FIX: FAIL (missing)\n' "$file"
		return 1
	fi

	if ! cp -p "$file" "$backup" 2>/dev/null; then
                printf '\t- %s FIX: FAIL (backup failed)\n' "$file"
                return 1
        fi

        if chmod 600 "$file" 2>/dev/null; then
                printf '\t- %s FIX: OK (set 600, backup %s)\n' "$file" "$backup"
                return 0
	else
		printf '\t- %s FIX: FAIL (chmod failed, backup %s)\n' "$file" "$backup"
                return 1
        fi

	
}

check_passwd_perms(){

        file=/etc/passwd

	actual_perm=$(stat -c %a "$file" 2> /dev/null)
	required_perm=644

	printf '\nCrtictical File (%s)' "$file"

	if [ ! -e "$file" ]; then
		printf '\n %s FAIL (missing)\n' "$file"
		return 1
	fi

	if [ ! -f "$file" ]; then
		printf '\n %s is not a regular file\n' "$file"
		return 1
	fi


	if [ "$actual_perm" = "$required_perm" ]; then
		printf '\n\t- File Permission OK (%s)\n' "$actual_perm"
		return 0
	else
		printf '\n\t- File Permission FAIL (%s)\n' "$actual_perm"
		return 1
	fi
}


check_group_perms(){

        file=/etc/group

        actual_perm=$(stat -c %a "$file" 2> /dev/null)
        required_perm=644

        printf '\nCrtictical File (%s)' "$file"

        if [ ! -e "$file" ]; then
                printf '\n %s FAIL (missing)\n' "$file"
                return 1
        fi

        if [ ! -f "$file" ]; then
                printf '\n %s is not a regular file\n' "$file"
                return 1
        fi


        if [ "$actual_perm" = "$required_perm" ]; then
                printf '\n\t- File Permission OK (%s)\n' "$actual_perm"
                return 0
        else
                printf '\n\t- File Permission FAIL (%s)\n' "$actual_perm"
                return 1
        fi
}
check_sudoers_perms(){

        file=/etc/sudoers

        actual_perm=$(stat -c %a "$file" 2> /dev/null)
        required_perm=440

        printf '\nCrtictical File (%s)' "$file"

        if [ ! -e "$file" ]; then
                printf '\n %s FAIL (missing)\n' "$file"
                return 1
        fi

        if [ ! -f "$file" ]; then
                printf '\n %s is not a regular file\n' "$file"
                return 1
        fi


        if [ "$actual_perm" = "$required_perm" ]; then
                printf '\n\t- File Permission OK (%s)\n' "$actual_perm"
                return 0
        else
                printf '\n\t- File Permission FAIL (%s)\n' "$actual_perm"
                return 1
        fi
}




audit_permissions(){

	local rc=0
	local ret

	check_world_writable_dirs
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_world_writable_files
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_suid_sgid
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_shadow_perms 
	ret=$?

	#Fix mode for etc/shadow
	if [ "$ret" -ne 0 ]; then
		if [ "$FIX_MODE" -eq 1 ]; then
			fix_shadow_perms
			check_shadow_perms
			ret=$?
		fi

		if [ "$ret" -ne 0 ]; then
			rc=1
		fi
	fi

	check_passwd_perms || rc=1
	check_group_perms || rc=1
	check_sudoers_perms || rc=1
	return "$rc"

}
