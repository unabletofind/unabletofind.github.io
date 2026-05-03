/* =================================================
   DETECTION RULES — central data source
   Add new rules here. index.html shows latest 3.
   detections.html shows all with platform filter.

   HOW TO ADD A NEW RULE:
   Copy the template block below, fill it in,
   and add it at the TOP of the array (newest first).
   ================================================= */
const detections = [
  {
    id: 'powershell-encoded',
    title: 'Suspicious PowerShell Encoded Command Execution',
    platform: 'kql',
    date: 'April 2026',
    desc: 'Catches base64-encoded PowerShell payloads — a classic loader pattern used by Emotet, Qakbot, and modern AiTM kits.',
    severity: 'high',
    mitre: ['T1059.001', 'T1027'],
    tags: ['PowerShell', 'Defense Evasion', 'Sentinel'],
    code: `DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ")
| where ProcessCommandLine matches regex @"[A-Za-z0-9+/]{50,}={0,2}"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc`,
  },
  {
    id: 'aitm-multi-asn',
    title: 'AiTM Phishing — Suspicious Sign-in from New ASN',
    platform: 'kql',
    date: 'April 2026',
    desc: 'Hunts adversary-in-the-middle session hijacks by flagging sign-ins where the user authenticates from a brand-new ASN within minutes of a known-good one.',
    severity: 'high',
    mitre: ['T1557', 'T1078.004'],
    tags: ['Identity', 'AiTM', 'EntraID'],
    code: `let lookback = 1h;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| summarize ASNs = make_set(NetworkLocationDetails)
            by UserPrincipalName, bin(TimeGenerated, 5m)
| where array_length(ASNs) > 1
| extend Suspicious = "Multi-ASN signin within 5 min"`,
  },
  {
    id: 'onenote-child-proc',
    title: 'OneNote Spawning Suspicious Child Process',
    platform: 'sigma',
    date: 'March 2026',
    desc: 'OneNote attachments became a favored phishing payload after macro restrictions. This rule fires when ONENOTE.EXE spawns scripting engines or LOLBins.',
    severity: 'high',
    mitre: ['T1204.002', 'T1059'],
    tags: ['Phishing', 'Initial Access', 'OneNote'],
    code: `title: OneNote Suspicious Child Process
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\\ONENOTE.EXE'
    Image|endswith:
      - '\\powershell.exe'
      - '\\cmd.exe'
      - '\\wscript.exe'
      - '\\mshta.exe'
  condition: selection
level: high`,
  },
  {
    id: 'stx-rat-cpuid',
    title: 'STX RAT — CPUID-based Anti-VM Strings',
    platform: 'yara',
    date: 'April 2026',
    desc: 'Static rule for the STX RAT family I analyzed in my CPUID writeup. Matches the unique CPUID instruction pattern used to evade sandbox detonation.',
    severity: 'medium',
    mitre: ['T1497.001'],
    tags: ['Malware', 'Anti-VM', 'STX RAT'],
    code: `rule STX_RAT_CPUID_AntiVM
{
  meta:
    author = "Swetha Devi"
    description = "Detects STX RAT CPUID anti-analysis"
    date = "2026-04"

  strings:
    $cpuid_check = { 0F A2 81 FB ?? ?? ?? ?? }
    $vbox = "VBoxService" ascii wide
    $vmware = "vmtoolsd" ascii wide

  condition:
    uint16(0) == 0x5A4D and
    $cpuid_check and any of ($vbox, $vmware)
}`,
  },
  {
    id: 'office-rundll32',
    title: 'Office Application Spawning rundll32',
    platform: 'kql',
    date: 'March 2026',
    desc: 'Word/Excel spawning rundll32.exe is a common Cobalt Strike + macro loader pattern. Low false-positive rate in most enterprises.',
    severity: 'medium',
    mitre: ['T1218.011', 'T1204.002'],
    tags: ['Macros', 'Office', 'CobaltStrike'],
    code: `DeviceProcessEvents
| where InitiatingProcessFileName in~
    ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName =~ "rundll32.exe"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc`,
  },
  {
    id: 'impossible-travel-tuned',
    title: 'Impossible Travel — Sentinel Built-in Tuned',
    platform: 'kql',
    date: 'February 2026',
    desc: 'Tightened version of the built-in impossible-travel rule. Filters out known VPN egress IPs and SaaS automation accounts to cut noise ~70%.',
    severity: 'low',
    mitre: ['T1078'],
    tags: ['Identity', 'Travel', 'Tuning'],
    code: `SigninLogs
| where ResultType == 0
| where AppDisplayName !in ("Microsoft Graph", "PowerShell")
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries = make_set(Country),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
| where datetime_diff('minute', LastSeen, FirstSeen) < 60`,
  },
  /* ── Add new rules above this line ──────────────────────────────────────
  {
    id: 'your-rule-id',
    title: 'Your Rule Title',
    platform: 'kql',         // 'kql' | 'sigma' | 'yara'
    date: 'May 2026',
    desc: 'Short description of what this detects and why it matters.',
    severity: 'high',        // 'high' | 'medium' | 'low'
    mitre: ['T1059.001'],
    tags: ['Tag1', 'Tag2'],
    code: `your query here`,
  },
  ─────────────────────────────────────────────────────────────────────── */
];
