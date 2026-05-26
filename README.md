# SOC Log Analyzer

Python-based SOC (Security Operations Center) log analysis tool that detects suspicious security events from authentication logs.

Built to simulate SOC analyst workflows including detection engineering, alert triage, and MITRE ATT&CK mapping.

## Features

- Brute Force Detection
- Successful Login After Failed Attempts Detection
- Suspicious PowerShell Detection
- User Account Creation Detection
- Port Scan Detection
- MITRE ATT&CK Mapping
- Severity Classification
- Automated Alert Report Generation

## Example Output

```
=== SOC Log Analyzer ===

[HIGH] Possible Brute Force Attack

[CRITICAL] Successful Login After Failed Attempts

[HIGH] Suspicious PowerShell Activity

[MEDIUM] New User Account Created

[MEDIUM] Possible Port Scan Detected
```

## Technologies Used

- Python
- Regex Parsing
- Log Analysis
- MITRE ATT&CK Framework

## Skills Demonstrated

- Security Monitoring
- Detection Engineering
- SOC Operations
- Threat Detection
- Log Analysis
- Alert Triage

## Project Structure

```

soc-log-analyzer/
│
├── main.py
├── sample_logs/
├── reports/
└── README.md

```

## Future Improvements

- Windows Event Log Support
- Sigma Rule Integration
- IOC Detection
- Threat Intelligence Integration
- Dashboard Visualization
