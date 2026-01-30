# Linux Hardening & Compliance Scanner (Bash)

A **Linux security auditing and hardening tool** written in Bash that performs automated checks against common misconfigurations and insecure system settings, with optional remediation via `--fix`.

This project demonstrates practical DevSecOps engineering skills: Bash scripting, Linux security controls, modular design, safe configuration handling, reporting, and probe/fix logic.

---

## Key Features

### Audit + Remediation Workflow
- **Audit mode (default):** detects insecure settings (no changes applied)
- **Fix mode (`--fix`):** applies safe remediation for supported findings (with backups)

###  Security Checks Implemented
#### Filesystem Permissions (`checks/permissions.sh`)
- Detects:
  - **World-writable directories**
  - **World-writable files**
  - **SUID / SGID binaries**
  - Critical file permission compliance:
    - `/etc/shadow`
    - `/etc/passwd`
    - `/etc/group`
    - `/etc/sudoers`
- Fix mode:
  - Enforces secure permissions on critical files
  - Performs backup before changes

#### SSH Hardening (`checks/ssh.sh`)
Audits and optionally remediates SSH server configuration in:

- `/etc/ssh/sshd_config`

Checks include:
- `PermitRootLogin`
- `PasswordAuthentication`
- `MaxAuthTries`

Fix mode:
- Updates SSH settings using a safe replace/append strategy
- Re-probes settings after applying remediation to confirm enforcement


##  What each folder/file does

- **`scanner.sh`** → main orchestrator: loads config + modules, runs checks, prints summary  
- **`checks/`** → modular security controls (each module returns standardized status codes)  
- **`libs/`** → shared helper functions (output formatting, summary tracking, utilities)  
- **`config/`** → scanner configuration (policy-level defaults)  
- **`reports/`** → generated scan reports (one per run, timestamped)


##  Usage

### Run audit (no changes applied)
```bash
./scanner.sh

### Run audit with remediation enabled
```bash
sudo ./scanner.sh --fix
## Help
./scanner.sh --help

## Reporting
reports/report_YYYY-MM-DD_HHMMSS.txt

The report captures:

-Full scan output
-Module findings
-PASS/WARN/FAIL summary
-Overall exit status


This makes the tool usable for:
-Compliance evidence
-Troubleshooting / debugging
-Automation / scheduled scans

 Exit Codes

The scanner uses Linux-friendly exit codes:

Code	Meaning
0	PASS (secure / compliant)
1	FAIL (one or more critical findings)
2	ERROR (tool/system error e.g., missing config/module)

Module return codes follow:

0 = OK
1 = FAIL
2 = WARN

 Safety Design Principles

This tool is designed to be safe and predictable:
Fix mode only runs when explicitly enabled: --fix
Backups are created before modifying configs
Checks are independently testable
Results are re-probed after remediation to verify enforcement
