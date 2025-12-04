# Executive Summary

**Impact:** Critical – Full Server Compromise

**TL;DR:** SharePoint server compromised via authentication bypass in ToolPane.aspx. 
Attacker executed encoded PowerShell via w3wp.exe, dropped ASPX webshell...

---

## 🔍 Visual Evidence

![Alert Dashboard](assets/alert-dashboard.png)
![Network Flow](assets/network-flow.png)

---

## Investigation Process

### Step 1: Initial Alert
SIEM alert triggered due to suspicious POST request >7KB to ToolPane.aspx.

### Step 2: Proxy Logs Analysis  
Proxy logs revealed encoded PowerShell payload inside the HTTP request.

### Step 3: EDR Correlation
EDR showed w3wp.exe spawning powershell.exe → suspicious behavior.

### Step 4: Webshell Discovery
Webshell found in SharePoint LAYOUTS folder → persistence confirmed.

---

## MITRE ATT&CK Mapping

- **T1190** – Exploit Public-Facing Application  
- **T1059.001** – PowerShell Execution  
- **T1505** – Web Shell Persistence  
- **T1552** – Credential Access (MachineKey)

---

## Timeline

- **13:07** Exploit request received  
- **13:08** PowerShell launched  
- **13:09** Webshell deployed  
- **13:10** Attacker extracts MachineKey

---

## 🛡️ Lessons Learned

- Monitor w3wp.exe child processes
- File Integrity Monitoring required on SharePoint LAYOUTS path
- Restrict outbound traffic from critical servers
- MachineKey must not remain in plain config files

---

## Conclusion

High-severity incident. Full compromise possible but contained quickly.
Zero-day exploited. Improvements deployed to prevent recurrence.
