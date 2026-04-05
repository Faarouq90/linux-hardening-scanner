---
name: Project Overview
description: High-level status of the linux-hardening-scanner modules and roadmap
type: project
---

Bash Linux security scanner with 5 complete modules and dual txt+JSON reporting.

**Modules complete:** permissions.sh, ssh.sh, users.sh, services.sh, network.sh, logs.sh

**logs.sh checks:**
- `check_logging_daemons` — auditd / rsyslog / syslog-ng / journald active status
- `check_auditd_enabled` — auditd enabled at boot via systemctl
- `check_log_file_permissions` — perms on configurable log file list (<= LOG_FILE_MAX_PERMS, default 640); supports --fix
- `check_journal_persistent` — journald Storage= setting; warns if volatile

**Config knobs added to scanner.conf:** `LOG_FILES`, `LOG_FILE_MAX_PERMS`

**Next:** CIS benchmark mapping → done.

**Why:** Security hardening scanner for Linux systems, building module by module.
**How to apply:** Follow the pattern in existing modules — `check_*` functions, `fix_*` for --fix mode, `audit_*` entry point aggregating return codes, `json_finding` for JSON output.
