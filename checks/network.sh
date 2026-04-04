
_sysctl_available() {
	command -v sysctl >/dev/null 2>&1
}

_sysctl_get() {
	sysctl -n "$1" 2>/dev/null
}

_net_ss_available() {
	command -v ss >/dev/null 2>&1
}

_net_netstat_available() {
	command -v netstat >/dev/null 2>&1
}

# Print port numbers of TCP sockets listening on all interfaces, one per line
_get_wildcard_ports() {
	local raw
	if _net_ss_available; then
		raw=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}')
	elif _net_netstat_available; then
		raw=$(netstat -tlnp 2>/dev/null | awk 'NR>2 {print $4}')
	else
		return
	fi

	printf '%s\n' "$raw" | while read -r addr; do
		case "$addr" in
			0.0.0.0:*|'*:'*|'[::]:*'|':::*')
				printf '%s\n' "${addr##*:}"
				;;
		esac
	done | sort -un
}

_net_process_on_port() {
	local port=$1
	if _net_ss_available; then
		ss -tlnp 2>/dev/null \
			| awk -v p="$port" 'NR>1 && $4 ~ ":"p"$"' \
			| sed -n 's/.*users:(("\([^"]*\)".*/\1/p' \
			| head -1
	fi
}


check_ip_forwarding() {
	printf '\nIP Forwarding:\n'

	if ! _sysctl_available; then
		printf '\t- SKIP: sysctl not available\n'
		json_finding "$CURRENT_MODULE" "IPForwarding" "ERR" "sysctl_unavailable"
		return 2
	fi

	local value
	value=$(_sysctl_get "net.ipv4.ip_forward")

	if [ -z "$value" ]; then
		printf '\t- net.ipv4.ip_forward: WARN (could not read)\n'
		json_finding "$CURRENT_MODULE" "IPForwarding" "WARN" "unreadable"
		return 2
	fi

	if [ "$value" -eq 0 ]; then
		printf '\t- net.ipv4.ip_forward: OK (%s)\n' "$value"
		json_finding "$CURRENT_MODULE" "IPForwarding" "OK" "$value"
		return 0
	else
		printf '\t- net.ipv4.ip_forward: FAIL (%s)\n' "$value"
		json_finding "$CURRENT_MODULE" "IPForwarding" "FAIL" "$value"
		return 1
	fi
}


fix_ip_forwarding() {
	if [ "$FIX_MODE" -ne 1 ]; then
		return 0
	fi

	if ! _sysctl_available; then
		printf '\t- IPForwarding FIX: FAIL (sysctl not available)\n'
		return 1
	fi

	if ! sysctl -w "net.ipv4.ip_forward=0" >/dev/null 2>&1; then
		printf '\t- net.ipv4.ip_forward FIX: FAIL (sysctl -w failed)\n'
		return 1
	fi
	printf '\t- net.ipv4.ip_forward FIX: OK (set to 0 at runtime)\n'

	local conf=/etc/sysctl.d/99-hardening.conf
	if grep -q "^net.ipv4.ip_forward" "$conf" 2>/dev/null; then
		sed -i "s|^net.ipv4.ip_forward.*|net.ipv4.ip_forward = 0|" "$conf"
	else
		printf 'net.ipv4.ip_forward = 0\n' >> "$conf"
	fi
	printf '\t- net.ipv4.ip_forward FIX: OK (persisted to %s)\n' "$conf"
	return 0
}


check_icmp_redirects() {
	printf '\nICMP Redirects:\n'

	if ! _sysctl_available; then
		printf '\t- SKIP: sysctl not available\n'
		json_finding "$CURRENT_MODULE" "ICMPRedirects" "ERR" "sysctl_unavailable"
		return 2
	fi

	local rc=0
	local failed_keys=""

	for key in \
		net.ipv4.conf.all.accept_redirects \
		net.ipv4.conf.default.accept_redirects \
		net.ipv4.conf.all.send_redirects \
		net.ipv4.conf.default.send_redirects; do

		local value
		value=$(_sysctl_get "$key")

		if [ -z "$value" ]; then
			printf '\t- %s: WARN (could not read)\n' "$key"
			[ "$rc" -eq 0 ] && rc=2
			continue
		fi

		if [ "$value" -eq 0 ]; then
			printf '\t- %s: OK (%s)\n' "$key" "$value"
		else
			printf '\t- %s: FAIL (%s)\n' "$key" "$value"
			failed_keys="${failed_keys:+$failed_keys,}$key"
			rc=1
		fi
	done

	if [ "$rc" -eq 0 ]; then
		json_finding "$CURRENT_MODULE" "ICMPRedirects" "OK" "all_disabled"
	elif [ "$rc" -eq 1 ]; then
		json_finding "$CURRENT_MODULE" "ICMPRedirects" "FAIL" "$failed_keys"
	else
		json_finding "$CURRENT_MODULE" "ICMPRedirects" "WARN" "some_unreadable"
	fi

	return "$rc"
}


fix_icmp_redirects() {
	if [ "$FIX_MODE" -ne 1 ]; then
		return 0
	fi

	if ! _sysctl_available; then
		printf '\t- ICMPRedirects FIX: FAIL (sysctl not available)\n'
		return 1
	fi

	local conf=/etc/sysctl.d/99-hardening.conf
	local failed=0

	for key in \
		net.ipv4.conf.all.accept_redirects \
		net.ipv4.conf.default.accept_redirects \
		net.ipv4.conf.all.send_redirects \
		net.ipv4.conf.default.send_redirects; do

		local value
		value=$(_sysctl_get "$key")
		[ -z "$value" ] && continue
		[ "$value" -eq 0 ] && continue

		if ! sysctl -w "${key}=0" >/dev/null 2>&1; then
			printf '\t- %s FIX: FAIL (sysctl -w failed)\n' "$key"
			failed=1
			continue
		fi
		printf '\t- %s FIX: OK (set to 0 at runtime)\n' "$key"

		if grep -q "^${key}" "$conf" 2>/dev/null; then
			sed -i "s|^${key}.*|${key} = 0|" "$conf"
		else
			printf '%s = 0\n' "$key" >> "$conf"
		fi
	done

	[ "$failed" -eq 0 ] && printf '\t- ICMPRedirects FIX: OK (persisted to %s)\n' "$conf"
	return "$failed"
}


check_open_ports() {
	printf '\nOpen Ports (listening on all interfaces):\n'

	if ! _net_ss_available && ! _net_netstat_available; then
		printf '\t- SKIP: ss/netstat not available (install iproute2 or net-tools)\n'
		json_finding "$CURRENT_MODULE" "OpenPorts" "ERR" "tools_unavailable"
		return 2
	fi

	local found=0
	local ports=""

	while read -r port; do
		[ -z "$port" ] && continue
		local proc
		proc=$(_net_process_on_port "$port")
		if [ -n "$proc" ]; then
			printf '\t- Port %s: listening on all interfaces (process: %s)\n' "$port" "$proc"
		else
			printf '\t- Port %s: listening on all interfaces\n' "$port"
		fi
		ports="${ports:+$ports,}$port"
		found=1
	done < <(_get_wildcard_ports)

	if [ "$found" -eq 0 ]; then
		printf '\t- No ports listening on all interfaces\n'
		json_finding "$CURRENT_MODULE" "OpenPorts" "OK" "none"
		return 0
	fi
	json_finding "$CURRENT_MODULE" "OpenPorts" "WARN" "$ports"
	return 2
}


check_firewall() {
	printf '\nFirewall Status:\n'

	local active=0
	local detected=""

	# ufw
	if command -v ufw >/dev/null 2>&1; then
		if ufw status 2>/dev/null | head -1 | grep -qi "active"; then
			printf '\t- ufw: OK (active)\n'
			detected="ufw"
			active=1
		else
			printf '\t- ufw: present but inactive\n'
		fi
	fi

	# firewalld
	if command -v firewall-cmd >/dev/null 2>&1; then
		if firewall-cmd --state 2>/dev/null | grep -qi "running"; then
			printf '\t- firewalld: OK (running)\n'
			detected="${detected:+$detected,}firewalld"
			active=1
		else
			printf '\t- firewalld: present but not running\n'
		fi
	fi

	# nftables
	if command -v nft >/dev/null 2>&1; then
		local nft_chains
		nft_chains=$(nft list ruleset 2>/dev/null | grep -c "chain" || true)
		if [ "${nft_chains:-0}" -gt 0 ]; then
			printf '\t- nftables: OK (active ruleset)\n'
			detected="${detected:+$detected,}nftables"
			active=1
		else
			printf '\t- nftables: present but no rules loaded\n'
		fi
	fi

	# iptables (only if nothing else found active)
	if [ "$active" -eq 0 ] && command -v iptables >/dev/null 2>&1; then
		local ipt_rules
		ipt_rules=$(iptables -S 2>/dev/null)
		if printf '%s' "$ipt_rules" | grep -qE "^-P (INPUT|OUTPUT|FORWARD) (DROP|REJECT)"; then
			printf '\t- iptables: OK (restrictive default policy)\n'
			detected="iptables"
			active=1
		elif printf '%s' "$ipt_rules" | grep -q "^-A "; then
			printf '\t- iptables: OK (rules present)\n'
			detected="iptables"
			active=1
		else
			printf '\t- iptables: present but no active rules\n'
		fi
	fi

	if [ "$active" -eq 0 ]; then
		if ! command -v ufw >/dev/null 2>&1 && \
		   ! command -v firewall-cmd >/dev/null 2>&1 && \
		   ! command -v nft >/dev/null 2>&1 && \
		   ! command -v iptables >/dev/null 2>&1; then
			printf '\t- WARN: no firewall tools detected\n'
			json_finding "$CURRENT_MODULE" "Firewall" "WARN" "no_tools_found"
			return 2
		fi
		printf '\t- FAIL: no active firewall detected\n'
		json_finding "$CURRENT_MODULE" "Firewall" "FAIL" "inactive"
		return 1
	fi

	json_finding "$CURRENT_MODULE" "Firewall" "OK" "$detected"
	return 0
}


audit_network() {
	local rc=0
	local ret

	check_ip_forwarding
	ret=$?
	if [ "$ret" -ne 0 ] && [ "$FIX_MODE" -eq 1 ]; then
		fix_ip_forwarding
		check_ip_forwarding
		ret=$?
	fi
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_icmp_redirects
	ret=$?
	if [ "$ret" -ne 0 ] && [ "$FIX_MODE" -eq 1 ]; then
		fix_icmp_redirects
		check_icmp_redirects
		ret=$?
	fi
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_open_ports
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	check_firewall
	ret=$?
	[ "$ret" -eq 1 ] && rc=1
	[ "$ret" -eq 2 ] && [ "$rc" -eq 0 ] && rc=2

	return "$rc"
}
