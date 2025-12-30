

check_world_writable_files(){

	printf '\nWorld Writable Files:\n'
	result=$(find $HOME -type f -perm -0002 -print 2> /dev/null)

	if [ -z "$result" ]; then 
		printf '\t- None Detected\n'
		return 1
	else
		printf '%s\n' "$result" | sed 's/^/\t- /'
		return 0
	fi
	
}


check_world_writable_dirs(){

	printf '\nWord Writable Directories:\n'
	result=$(find $HOME \
		\( -path "/sys/*" -o -path "/dev/*" -o -path "/proc/*" \) -prune -o \
		-type d -perm -0002 -print 2> /dev/null)

	if [ -z "$result" ]; then
		printf '\t- None Detected\n'
		return 1
	else
		printf '%s\n' "$result" | sed 's/^/\t- /'
		return 0
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
            \( -path "/proc/*" -o -path "/sys/*" -o -path "/dev/*" \) -prune -o \
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
        printf '\tNone detected.\n'
	return 1
    fi

   return 0


}

check_shadow_perms(){

	file=/etc/shadow

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

	check_world_writable_dirs && [ "$rc" -eq 0 ] && rc=2
	check_world_writable_files && [ "$rc" -eq 0 ] && rc=2
	check_suid_sgid && [ "$rc" -eq 0 ] && rc=2
	
	check_shadow_perms || rc=1
	check_passwd_perms || rc=1
	check_group_perms || rc=1
	check_sudoers_perms || rc=1
	return "$rc"

}
