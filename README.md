# Splunk Detection Labs

## 🧠 Objective  
Create and test custom Splunk detection rules to identify suspicious activity in a simulated SOC environment.

## 🛠 Tools  
- Splunk Enterprise / Splunk Cloud  
- Windows Event Logs (Security, Sysmon)  
- MITRE ATT&CK Framework  

## 🧩 Example Detections  
- Failed logon correlation (Event ID 4625)  
- Privilege escalation attempts  
- Suspicious PowerShell activity  

## ⚙️ SPL Queries  
**Brute Force Detection**
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count as failed by Account_Name, src_ip, _time
| bin _time span=5m
| stats sum(failed) as failed by Account_Name, src_ip, _time
| where failed >= 10
```

**Suspicious PowerShell Execution**
```spl
index=main (sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" OR EventCode=4104)
| search Message="*EncodedCommand*" OR Message="*FromBase64String*"
| table _time, user, host, Message
```

## 📊 Dashboard Examples  


![Splunk Search](dashboards/splunk_search_4625.png)
*Search results showing failed logon attempts (Event ID 4625).*

![Brute Force Dashboard] https://github.com/vagabongo0/Splunk-Detection-Labs/tree/main
*Dashboard view aggregating failed logons per IP address.*
## 🔖 MITRE ATT&CK Mapping  
- T1110 – Brute Force  
- T1059 – Command and Scripting Interpreter  

## 📈 Results  
Successfully created and tested detections in a simulated environment using lab-generated Windows Security and Sysmon logs.

## 📚 Next Steps  
Add dashboards, correlation searches, and more advanced detections as your skills progress.
