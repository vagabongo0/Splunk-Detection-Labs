# Analysis Summary – Splunk Detection Labs

## Objective
Summarise outcomes of Splunk detections (what we looked for, why it matters, what we found).

## Dataset
- Source: Windows Security logs (Event ID 4625), optionally Sysmon + PowerShell Operational (4104)
- Ingestion: CSV upload into Splunk (index=main, sourcetype=WinEventLog:Security)

## Detection(s)
### 1) Brute-force logons (Event ID 4625)
- SPL: see `queries/brute_force_detection.spl`
- Threshold: ≥10 failed logons from same IP or against same user within 5 minutes
- MITRE: T1110 – Brute Force

### 2) Suspicious PowerShell (optional, next)
- SPL: to be added
- MITRE: T1059 – Command and Scripting Interpreter

## Findings (example – replace with your results)
- Peak failed-logon burst detected against user `testuser` from `192.0.2.15` at 11:05–11:10.
- Multiple hosts showed repeated logon failures outside business hours.

## Recommendations
- Enforce account lockout policy; review MFA coverage.
- Monitor after-hours logon attempts; block offending IPs if external.
- Add correlation with successful logon (4624) following failures.

## Evidence
- Dashboard screenshots in `/dashboards`
- Raw queries in `/queries`
