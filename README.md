# 🛡️ Splunk Threat Hunting Scenarios

This document contains 10 real-world threat hunting use cases designed for SOC analysts and Splunk Power Users. Each scenario includes:

- 📘 Description of the threat behavior  
- 🔍 SPL Code used for detection  
- ✅ What was achieved  
- 🎯 MITRE ATT&CK Mapping  

---

## ✅ Scenario 01: High Volume of Failed Logins

### 📝 Description:
Detect users with more than 10 failed login attempts within a short timeframe, which may indicate a brute force attack.

### 🔍 SPL Code:
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
| stats count by user, src_ip
| where count > 10
```

### 🎯 What We Achieved:
Identified potential brute force attempts by flagging users with high login failures.

### 🧠 MITRE Mapping:
T1110 - Brute Force

---

## ✅ Scenario 02: Successful Login After Multiple Failures

### 📝 Description:
Detect users who had several failed logins (EventCode 4625) followed by a successful login (EventCode 4624), potentially indicating credential guessing.

### 🔍 SPL Code:
```spl
index=windows sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failed, count(eval(EventCode=4624)) as success by user, src_ip
| where failed >= 5 AND success >= 1
```

### 🎯 What We Achieved:
Spotted accounts that eventually logged in after repeated failures, possible signs of compromise.

### 🧠 MITRE Mapping:
T1110.001 - Password Guessing

---

## ✅ Scenario 03: Account Disabled Detection

### 📝 Description:
Alert when user accounts are disabled, which could indicate insider sabotage or legitimate administrative action.

### 🔍 SPL Code:
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4725
| stats count by user, ComputerName
```

### 🎯 What We Achieved:
Captured instances where accounts were disabled.

### 🧠 MITRE Mapping:
T1489 - Account Access Removal

---

## ✅ Scenario 04: Suspicious PowerShell Execution

### 📝 Description:
Detect any PowerShell command-line usage that includes encoded or suspicious flags (e.g., -enc, -e).

### 🔍 SPL Code:
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4104
| search Message="*-enc*" OR Message="*-e*"
| table _time, user, Message
```

### 🎯 What We Achieved:
Detected possible PowerShell obfuscation or encoded payloads often used by attackers.

### 🧠 MITRE Mapping:
T1059.001 - PowerShell

---

## ✅ Scenario 05: Large File Downloads Detected

### 📝 Description:
Track downloads over a threshold size, useful for detecting data exfiltration via legitimate channels.

### 🔍 SPL Code:
```spl
index=proxy sourcetype=squid OR sourcetype=zscaler
| stats sum(bytes) as totalBytes by user, uri_path
| where totalBytes > 50000000
```

### 🎯 What We Achieved:
Flagged users downloading unusually large files, which may indicate malicious activity or exfiltration.

### 🧠 MITRE Mapping:
T1048 - Exfiltration Over Alternative Protocol

---
