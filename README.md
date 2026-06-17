# PowerShell SOC Automation — Threat Reporting Script

**Tools:** PowerShell | Windows Event Log | HTML Report Generation  
**Techniques Monitored:** MITRE ATT&CK T1110, T1136, T1059.001  
**Author:** Takejah O'Neal | Former MDDR Analyst Intern — Varonis Systems

---

## Overview
Built a PowerShell automation script that pulls Windows Security 
and PowerShell Operational event logs, analyzes them for indicators 
of suspicious activity, calculates an overall risk level, and 
generates a formatted HTML threat report. Designed to reduce manual 
log review time and standardize daily SOC reporting output.

---

## What It Does

The script automatically:
1. Queries Windows Event Logs for the last 24 hours (configurable)
2. Collects 5 categories of security-relevant events
3. Analyzes volume and applies risk-scoring logic
4. Generates a styled HTML report with metric cards and event tables
5. Opens the report automatically in the default browser

---

## Events Monitored

| Category | Event ID | MITRE ATT&CK |
|----------|----------|--------------|
| Failed Login Attempts | 4625 | T1110 — Brute Force |
| Successful Logins | 4624 | — |
| New User Account Created | 4720 | T1136 — Create Account |
| PowerShell Script Block Execution | 4104 | T1059.001 — PowerShell |
| Account Lockouts | 4740 | — |

---

## Risk Scoring Logic

The script assigns an overall risk level based on event volume:

| Risk Level | Trigger Conditions |
|-----------|---------------------|
| LOW | Default — no significant indicators |
| MEDIUM | More than 10 failed logins, any new account created, or any lockout |
| HIGH | More than 50 failed logins, or more than 20 PowerShell script block events |

---

## Sample Output

The generated report includes:
- Overall risk badge (color-coded: green/orange/red)
- Summary metric cards for each event category
- Detailed tables for failed logins, new accounts, and PowerShell activity
- Timestamped, hostname-tagged report header for audit trail

See [screenshots/](screenshots/) for a live example.

---

## How to Run

```powershell
cd C:\Projects\SOC-Automation
.\SOC-Report.ps1
```

The script requires no parameters and pulls live data directly 
from the local Windows Event Log. Adjust the `$HoursBack` variable 
at the top of the script to change the analysis window.

---

## Skills Demonstrated
- PowerShell scripting and automation
- Windows Event Log querying and XML parsing
- Security event analysis and risk-scoring logic
- Automated report generation (HTML/CSS)
- Practical SOC workflow automation

---

## Related Projects
- [SIEM Home Lab](https://github.com/Toneal92/siem-home-lab)
- [Incident Response Simulation](https://github.com/Toneal92/incident-response-simulation)
