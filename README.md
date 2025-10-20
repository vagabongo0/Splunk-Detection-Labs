Splunk Detection Labs

🧠 Objective

Create and test custom Splunk detection rules to identify suspicious activity in a simulated SOC environment.

🛠 Tools
	•	Splunk Cloud Platform
	•	Windows Event Logs (Security, Sysmon)
	•	MITRE ATT&CK Framework

🧩 Example Detections
	•	Failed logon correlation (Event ID 4625)
	•	Privilege escalation attempts
	•	Suspicious PowerShell activity

⚙️ SPL Queries

Brute Force Detection

index=main sourcetype=“WinEventLog:Security” EventCode=4625
| stats count as failed by Account_Name, src_ip, _time
| bin _time span=5m
| stats sum(failed) as failed by Account_Name, src_ip, _time
| where failed >= 10
Suspicious PowerShell Execution

index=main (sourcetype=“WinEventLog:Microsoft-Windows-PowerShell/Operational” OR EventCode=4104)
| search Message=”EncodedCommand” OR Message=”FromBase64String”
| table _time, user, host, Message

📊 Splunk Dashboards & Visualizations

Below are examples from a lab simulating failed logons (Event ID 4625).
These are lab-generated artifacts to demonstrate SIEM search, detection and dashboarding skills.

Artifacts:
📁 Download sample_4625_events.csv
🔍 Search Results
Search results showing aggregated failed logon events (Event ID 4625). Columns show TimeCreated, Account, Source IP, and Message.

📈 Brute Force Dashboard
Dashboard visualising number of failed logons per source IP — used to prioritise investigation and create alert thresholds.
🔖 MITRE ATT&CK Mapping
	•	T1110 – Brute Force
	•	T1059 – Command and Scripting Interpreter

📈 Results

Successfully created and tested detections in a simulated environment using lab-generated Windows Security and Sysmon logs.

📚 Next Steps

Add correlation searches, scheduled alerts, and more advanced detections as skills progress.
