# SysAdmin & DFIR Automation Toolkit

Collection of operational scripts developed for Linux/Windows system administration, Active Directory security auditing, and rapid Digital Forensics & Incident Response (DFIR) triage.

## Included Modules

| Script | Platform | Purpose |
| :--- | :--- | :--- |
| `linux/volatile_triage.sh` | Linux (Debian/RHEL) | Collects volatile system state (processes, sockets, kernel modules, auth logs) and generates a SHA-256 chain-of-custody manifest. |
| `windows/Get-AuthAnomalies.ps1` | Windows Server / AD | Queries Security & Sysmon event logs for failed logons (`4625`), special privilege assignments (`4672`), and suspicious process creation (`Event ID 1`). |
| `forensics/evidence_hasher.py` | Cross-Platform | Generates recursive SHA-256/SHA-512 cryptographic manifests to verify digital evidence integrity. |

## Usage Example

```bash
chmod +x linux/volatile_triage.sh
sudo ./linux/volatile_triage.sh /tmp/case_001
