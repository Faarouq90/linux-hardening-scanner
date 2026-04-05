# Linux Hardening & Compliance Scanner

A modular Linux security auditing tool written in Bash. It checks common misconfigurations and insecure system settings across six security domains, with optional safe remediation via `--fix`.

---

## Features

- **Audit mode (default):** reads system state, flags issues, makes no changes
- **Fix mode (`--fix`):** applies targeted remediations with backups before any change
- **Dual reporting:** timestamped `.txt` and `.json` reports, locked read-only after each run
- **Modular design:** each security domain is an independent `checks/` module
- **Re-probe after fix:** remediations are verified immediately after being applied

---

## Security Checks

### Filesystem Permissions (`checks/permissions.sh`)

| Check | Fix |
|---|---|
| World-writable directories | — |
| World-writable files | — |
| SUID / SGID binaries | — |
| `/etc/shadow` permissions | Enforces `600` |
| `/etc/passwd` permissions | Enforces `644` |
| `/etc/group` permissions | Enforces `644` |
| `/etc/sudoers` permissions | Enforces `440` |

Fix mode creates a backup before modifying any file.

---

### SSH Configuration (`checks/ssh.sh`)

Audits `/etc/ssh/sshd_config` for:

| Setting | Secure value |
|---|---|
| `PermitRootLogin` | `no` |
| `PasswordAuthentication` | `no` |
| `MaxAuthTries` | `≤ 3` |

Fix mode uses a safe replace/append strategy and re-probes each setting after applying changes.

---

### User Accounts (`checks/users.sh`)

| Check | Fix |
|---|---|
| Non-root accounts with UID 0 | — |
| Accounts with empty passwords | Locks account (`passwd -l`) |
| System accounts without shell lockout | — |
| Accounts with interactive shell but no activity | — |
| Password max age exceeds policy (`PASSWORD_MAX_AGE`, default 90 days) | Sets `chage -M` |

---

### Running Services (`checks/services.sh`)

| Check | Fix |
|---|---|
| Insecure services active: `telnet`, `ftp`, `rexec`, `rlogin`, `rsh` | — |
| Unexpected TCP listening ports (compared against `ALLOWED_PORTS`) | — |

Supports both `ss` and `netstat` for port discovery.

---

### Network Configuration (`checks/network.sh`)

| Check | Fix |
|---|---|
| IP forwarding enabled (`net.ipv4.ip_forward`) | Disables via `sysctl` |
| ICMP redirects accepted (`net.ipv4.conf.*.accept_redirects`) | Disables via `sysctl` |
| ICMP redirects sent (`net.ipv4.conf.*.send_redirects`) | Disables via `sysctl` |
| TCP ports listening on all interfaces (wildcard bind) | — |
| Firewall status (`iptables` / `ufw` / `firewalld`) | — |

---

### Logging Configuration (`checks/logs.sh`)

| Check | Fix |
|---|---|
| Logging daemon running (`rsyslog`, `syslog-ng`, `syslog`) | — |
| `auditd` enabled and active | — |
| Log file permissions exceed `LOG_FILE_MAX_PERMS` (default `640`) | Enforces max permissions |
| `systemd-journald` persistence (`Storage=persistent`) | — |

---

## Usage

```bash
# Audit only (no changes)
./scanner.sh

# Audit with remediation
sudo ./scanner.sh --fix

# Help
./scanner.sh --help
```

Fix mode requires `sudo` / root for most remediations (file permission changes, sysctl writes, account locking).

---

## Configuration

`config/scanner.conf` controls policy-level defaults:

| Variable | Default | Description |
|---|---|---|
| `SCAN_ROOT` | `/` | Filesystem root for permission scans |
| `USER_UID_MIN` | `100` | Minimum UID considered a regular user |
| `DISK_THRESHOLD` | `80` | Disk usage warning threshold (%) |
| `ALLOWED_PORTS` | `"22"` | Space-separated list of expected listening TCP ports |
| `LOG_FILES` | `"/var/log/syslog ..."` | Space-separated log files checked for permissions |
| `LOG_FILE_MAX_PERMS` | `640` | Maximum octal permissions allowed on log files |

Extend `ALLOWED_PORTS` to match your environment:

```bash
ALLOWED_PORTS="22 80 443"
```

---

## Reports

Each run produces two timestamped, read-only report files:

```
reports/report_YYYY-MM-DD_HHMMSS.txt
reports/report_YYYY-MM-DD_HHMMSS.json
```

Reports are locked to `440` (owner+group read-only) after writing. The `reports/` directory is `750` — inaccessible to other local users. This prevents tampering and keeps findings confidential.

The JSON report includes:
- Scan metadata (host, start time, scan root)
- Per-module status (`PASS` / `WARN` / `FAIL` / `ERR`)
- Individual finding records with status and detail

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more checks failed |
| `2` | Scanner error (missing config, missing module, etc.) |

Module-level return codes: `0` = OK, `1` = FAIL, `2` = WARN.

---

## Project Structure

```
linux-hardening-scanner/
├── scanner.sh              # Main orchestrator
├── config/
│   └── scanner.conf        # Policy defaults (editable)
├── checks/
│   ├── permissions.sh      # Filesystem permission checks
│   ├── ssh.sh              # SSH hardening checks
│   ├── users.sh            # User account checks
│   ├── services.sh         # Running services checks
│   ├── network.sh          # Network configuration checks
│   └── logs.sh             # Logging configuration checks
├── libs/
│   ├── output.sh           # Reporting, JSON helpers, summary counters
│   ├── common.sh           # Shared utilities
│   └── deps.sh             # Dependency checks
└── reports/                # Generated scan reports (auto-created)
```

---

## Safety Principles

- Fix mode only runs when explicitly passed `--fix` — audit is always the default
- Every config file modification is preceded by a timestamped backup
- Each remediation is re-probed after applying to confirm enforcement
- Reports are immediately locked read-only after writing to prevent post-scan tampering
- All checks are independently testable modules
