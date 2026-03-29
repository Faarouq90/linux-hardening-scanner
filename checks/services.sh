
# Insecure service definitions: "label:port"
INSECURE_DEFS="telnet:23 ftp:21 rexec:512 rlogin:513 rsh:514"

# systemd service/socket names for the same insecure services
INSECURE_SYSTEMD_SVCS="telnet.socket telnetd vsftpd proftpd pure-ftpd ftpd rsh.socket rlogin.socket rexec.socket"

# Space-separated list of expected listening ports (overridable in scanner.conf)
ALLOWED_PORTS=${ALLOWED_PORTS:-"22"}


_ss_available() {
	command -v ss >/dev/null 2>&1
}

_netstat_available() {
	command -v netstat >/dev/null 2>&1
}

# Print all unique TCP listening port numbers, one per line
_get_listening_ports() {
	if _ss_available; then
		ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -oE '[0-9]+$' | sort -un
	elif _netstat_available; then
		netstat -tlnp 2>/dev/null | awk 'NR>2 {print $4}' | grep -oE '[0-9]+$' | sort -un
	fi
}

# Return 0 if the given port is currently listening
_port_listening() {
	local port=$1
	if _ss_available; then
		ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"
	elif _netstat_available; then
		netstat -tlnp 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"
	else
		return 2
	fi
}

# Print the process name listening on a port (empty string if unavailable/no root)
_process_on_port() {
	local port=$1
	if _ss_available; then
		ss -tlnp 2>/dev/null \
			| awk -v p="$port" 'NR>1 && $4 ~ ":"p"$"' \
			| sed -n 's/.*users:(("\([^"]*\)".*/\1/p' \
			| head -1
	fi
}


check_insecure_services() {

	printf '\nInsecure Services (telnet/ftp/rsh):\n'
	local found=0

	# ---- check by listening port ----
	for def in $INSECURE_DEFS; do
		local label="${def%%:*}"
		local port="${def##*:}"

		if _port_listening "$port"; then
			local proc
			proc=$(_process_on_port "$port")
			if [ -n "$proc" ]; then
				printf '\t- %s: ACTIVE on port %s (process: %s)\n' "$label" "$port" "$proc"
			else
				printf '\t- %s: ACTIVE on port %s\n' "$label" "$port"
			fi
			found=1
		fi
	done

	# ---- check via systemctl (catches services not yet accepting connections) ----
	if command -v systemctl >/dev/null 2>&1; then
		for svc in $INSECURE_SYSTEMD_SVCS; do
			if systemctl is-active --quiet "$svc" 2>/dev/null; then
				printf '\t- %s: ACTIVE (systemctl)\n' "$svc"
				found=1
			fi
		done
	fi

	if [ "$found" -eq 0 ]; then
		printf '\t- None detected\n'
		return 0
	fi
	return 1
}


check_unexpected_ports() {

	printf '\nListening Ports (allowed: %s):\n' "$ALLOWED_PORTS"

	if ! _ss_available && ! _netstat_available; then
		printf '\t- SKIP: ss/netstat not available (install iproute2 or net-tools)\n'
		return 2
	fi

	local found=0
	while read -r port; do
		[ -z "$port" ] && continue

		local expected=0
		for allowed in $ALLOWED_PORTS; do
			if [ "$port" = "$allowed" ]; then
				expected=1
				break
			fi
		done

		if [ "$expected" -eq 0 ]; then
			local proc
			proc=$(_process_on_port "$port")
			if [ -n "$proc" ]; then
				printf '\t- Port %s: unexpected (process: %s)\n' "$port" "$proc"
			else
				printf '\t- Port %s: unexpected\n' "$port"
			fi
			found=1
		fi
	done < <(_get_listening_ports)

	if [ "$found" -eq 0 ]; then
		printf '\t- All listening ports are within allowed list\n'
		return 0
	fi
	return 2
}


audit_services() {

	local rc=0
	local ret

	check_insecure_services
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_unexpected_ports
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	return "$rc"
}
