/* ============================================= */
/* DETECTION RULES DATA */
/* ============================================= */
/* Add a new detection rule by appending to the array below.
   Required: title, platform (kql|sigma|yara), desc, severity (high|medium|low), mitre[], tags[], code, date.
   Optional: featured (boolean) - shows on homepage with priority. */

window.DETECTIONS = [
  {
    id: 'powershell-encoded-cmd',
    title: 'Suspicious PowerShell Encoded Command Execution',
    platform: 'kql',
    desc: "Catches base64-encoded PowerShell payloads — a classic loader pattern used by Emotet, Qakbot, and modern AiTM kits.",
    severity: 'high',
    mitre: ['T1059.001', 'T1027'],
    tags: ['PowerShell', 'Defense Evasion', 'Sentinel'],
    date: 'April 2026',
    featured: true,
    code: `DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ")
| where ProcessCommandLine matches regex @"[A-Za-z0-9+/]{50,}={0,2}"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc`
  },
  {
    id: 'aitm-multi-asn',
    title: 'AiTM Phishing — Suspicious Sign-in from New ASN',
    platform: 'kql',
    desc: 'Hunts adversary-in-the-middle session hijacks by flagging sign-ins where the user authenticates from a brand-new ASN within minutes of a known-good one.',
    severity: 'high',
    mitre: ['T1557', 'T1078.004'],
    tags: ['Identity', 'AiTM', 'EntraID'],
    date: 'March 2026',
    featured: true,
    code: `let lookback = 1h;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| summarize ASNs = make_set(NetworkLocationDetails)
            by UserPrincipalName, bin(TimeGenerated, 5m)
| where array_length(ASNs) > 1
| extend Suspicious = "Multi-ASN signin within 5 min"`
  },
  {
    id: 'onenote-child-process',
    title: 'OneNote Spawning Suspicious Child Process',
    platform: 'sigma',
    desc: 'OneNote attachments became a favored phishing payload after macro restrictions. This rule fires when ONENOTE.EXE spawns scripting engines or LOLBins.',
    severity: 'high',
    mitre: ['T1204.002', 'T1059'],
    tags: ['Phishing', 'Initial Access', 'OneNote'],
    date: 'March 2026',
    featured: true,
    code: `title: OneNote Suspicious Child Process
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\\\\ONENOTE.EXE'
    Image|endswith:
      - '\\\\powershell.exe'
      - '\\\\cmd.exe'
      - '\\\\wscript.exe'
      - '\\\\mshta.exe'
  condition: selection
level: high`
  },
  {
    id: 'stx-rat-yara',
    title: 'STX RAT — CPUID-based Anti-VM Strings',
    platform: 'yara',
    desc: 'Static rule for the STX RAT family analyzed in the CPUID writeup. Matches the unique CPUID instruction pattern used to evade sandbox detonation.',
    severity: 'medium',
    mitre: ['T1497.001'],
    tags: ['Malware', 'Anti-VM', 'STX'],
    date: 'February 2026',
    featured: false,
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
}`
  },
  {
    id: 'office-rundll32',
    title: 'Office Application Spawning rundll32',
    platform: 'kql',
    desc: 'Word/Excel spawning rundll32.exe is a common Cobalt Strike + macro loader pattern. Low false-positive rate in most enterprises.',
    severity: 'medium',
    mitre: ['T1218.011', 'T1204.002'],
    tags: ['Macros', 'Office', 'CobaltStrike'],
    date: 'January 2026',
    featured: false,
    code: `DeviceProcessEvents
| where InitiatingProcessFileName in~
    ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName =~ "rundll32.exe"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc`
  },
  {
    id: 'impossible-travel-tuned',
    title: 'Impossible Travel — Sentinel Built-in Tuned',
    platform: 'kql',
    desc: 'Tightened version of the built-in impossible-travel rule. Filters out known VPN egress IPs and SaaS automation accounts to cut noise ~70%.',
    severity: 'low',
    mitre: ['T1078'],
    tags: ['Identity', 'Travel', 'Tuning'],
    date: 'December 2025',
    featured: false,
    code: `SigninLogs
| where ResultType == 0
| where AppDisplayName !in ("Microsoft Graph", "PowerShell")
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries = make_set(Country),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
            by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
| where datetime_diff('minute', LastSeen, FirstSeen) < 60`
  }
  /* ----------------------------------------------------------------
   * To add a new rule, copy this template:
   *
   * {
   *   id: 'unique-slug-here',
   *   title: 'Rule Title',
   *   platform: 'kql',           // 'kql' | 'sigma' | 'yara'
   *   desc: 'What this rule detects and why it matters.',
   *   severity: 'high',          // 'high' | 'medium' | 'low'
   *   mitre: ['T1059.001'],
   *   tags: ['PowerShell', 'IR'],
   *   date: 'May 2026',
   *   featured: false,           // true to show on homepage
   *   code: `your detection
   * query goes here`
   * }
   * ---------------------------------------------------------------- */
];

/* Helper: parse "Month YYYY" into a Date for sorting */
window.parseDetDate = function(s){
  const months = {January:0,February:1,March:2,April:3,May:4,June:5,July:6,August:7,September:8,October:9,November:10,December:11};
  const m = String(s||'').match(/(\w+)\s+(\d{4})/);
  if(!m) return new Date(0);
  return new Date(parseInt(m[2]), months[m[1]] || 0, 1);
};

/* Helper: render detection cards into a target grid.
   Used by both index.html (limit=3, only featured) and detections.html (no limit, with filters). */
window.buildDetectionCards = function(targetId, opts){
  opts = opts || {};
  const grid = document.getElementById(targetId);
  if(!grid) return;

  let list = window.DETECTIONS.slice();

  // Sort newest first by default
  list.sort((a,b) => window.parseDetDate(b.date) - window.parseDetDate(a.date));

  if(opts.featuredOnly){
    list = list.filter(r => r.featured);
  }
  if(opts.platform && opts.platform !== 'all'){
    list = list.filter(r => r.platform === opts.platform);
  }
  if(opts.search){
    const q = opts.search.toLowerCase();
    list = list.filter(r =>
      r.title.toLowerCase().includes(q) ||
      r.desc.toLowerCase().includes(q) ||
      r.tags.some(t => t.toLowerCase().includes(q)) ||
      r.mitre.some(m => m.toLowerCase().includes(q))
    );
  }
  if(opts.limit){
    list = list.slice(0, opts.limit);
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  if(!list.length){
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:40px;color:var(--muted);font-family:var(--mono);font-size:12px">// no rules match the current filter</div>';
    return;
  }

  grid.innerHTML = list.map((r, i) => `
    <div class="det-card">
      <div class="det-card-head">
        <div class="det-card-title">${escapeHtml(r.title)}</div>
        <div class="det-platform ${r.platform}">${r.platform === 'kql' ? 'KQL' : r.platform === 'sigma' ? 'Sigma' : 'YARA'}</div>
      </div>
      <div class="det-desc">${escapeHtml(r.desc)}</div>
      <div class="det-meta">
        <span class="det-sev ${r.severity}">${r.severity.toUpperCase()}</span>
        ${r.tags.map(t => `<span class="det-tag">${escapeHtml(t)}</span>`).join('')}
      </div>
      <pre class="det-code"><code>${escapeHtml(r.code)}</code></pre>
      <div class="det-actions">
        <span class="det-mitre">MITRE: ${r.mitre.join(' · ')}</span>
        <button class="det-copy" data-rule-id="${r.id}"><i class="fas fa-copy"></i> Copy</button>
      </div>
    </div>
  `).join('');

  // wire up copy buttons (look up code by id, not list index — survives filtering)
  grid.querySelectorAll('.det-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const rule = window.DETECTIONS.find(x => x.id === btn.dataset.ruleId);
      if(!rule) return;
      navigator.clipboard.writeText(rule.code).then(() => {
        btn.classList.add('copied');
        btn.innerHTML = '<i class="fas fa-check"></i> Copied';
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.innerHTML = '<i class="fas fa-copy"></i> Copy';
        }, 1800);
      });
    });
  });
};
