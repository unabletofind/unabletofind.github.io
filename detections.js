/* ============================================= */
/* DETECTION RULES DATA */
/* ============================================= */
/* Add a new detection rule by appending to the array below.
   Required: title, platform (kql|sigma|yara), desc, severity (high|medium|low), mitre[], tags[], code, date.
   Optional: featured (boolean) - shows on homepage with priority. */

window.DETECTIONS = [
   {
  id: 'enum-burst-10s',
  title: 'Post-Compromise Enumeration Burst — 2+ Commands in 10 Seconds',
  platform: 'kql',
  desc: 'Detects rapid execution of discovery commands within a 10-second window on a single device — strong indicator of post-exploitation scripted enumeration.',
  severity: 'high',
  mitre: ['T1082', 'T1016', 'T1083', 'T1033', 'T1057'],
  tags: ['Enumeration', 'Post-Exploitation', 'Endpoint', 'MDE'],
  date: 'May 2026',
  featured: true,
  code: `let EnumCommands = dynamic(["net view", "net user", "net group", "ipconfig",
    "arp", "nslookup", "systeminfo", "hostname", "whoami", "nltest",
    "netstat", "tasklist", "dir", "wmic"]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("cmd.exe", "powershell.exe")
| where InitiatingProcessCommandLine has_any (EnumCommands)
    or ProcessCommandLine has_any (EnumCommands)
| summarize
    CommandCount = dcount(ProcessCommandLine),
    CommandsRun = make_set(ProcessCommandLine),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, AccountName, bin(Timestamp, 10s)
| where CommandCount >= 2
| extend TimeDiffSeconds = datetime_diff('second', LastSeen, FirstSeen)
| where TimeDiffSeconds <= 10
| project Timestamp, DeviceName, AccountName,
    CommandCount, CommandsRun, TimeDiffSeconds
| order by Timestamp desc`
},

{
  id: 'zip-download-browser',
  title: 'ZIP File Downloaded via Browser or Email Client',
  platform: 'kql',
  desc: 'Detects .zip file creation in user-accessible folders initiated by a browser or email client — common delivery mechanism for phishing payloads.',
  severity: 'medium',
  mitre: ['T1566.001', 'T1105'],
  tags: ['Phishing', 'ZIP', 'Download', 'MDE'],
  date: 'May 2026',
  featured: false,
  code: `DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
| where InitiatingProcessFileName in~ (
    "chrome.exe", "msedge.exe", "firefox.exe",
    "outlook.exe", "iexplore.exe", "brave.exe"
    )
| where FolderPath has_any ("Downloads", "Temp", "AppData", "Desktop")
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    FileSize,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| extend VTLink = strcat("https://www.virustotal.com/gui/file/", SHA256)
| order by Timestamp desc`
},

{
  id: 'email-threat-intel-ip',
  title: 'Inbound Email from Threat Intel Watchlist IP',
  platform: 'kql',
  desc: 'Detects inbound emails where the sender IP matches an entry in the Sentinel threat intelligence watchlist — high confidence phishing or BEC indicator.',
  severity: 'high',
  mitre: ['T1566.001', 'T1078'],
  tags: ['Phishing', 'Threat Intel', 'Email', 'Sentinel'],
  date: 'May 2026',
  featured: true,
  code: `let ThreatIntelIPs = _GetWatchlist('ThreatIntelFeed')
| project SenderIP = SearchKey;
EmailEvents
| where Timestamp > ago(24h)
| where EmailDirection == "Inbound"
| extend SenderIP = tostring(parse_json(AuthenticationDetails).SenderIP)
| join kind=inner ThreatIntelIPs on SenderIP
| project
    Timestamp,
    SenderAddress,
    SenderIP,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    DeliveryLocation,
    UrlCount,
    AttachmentCount,
    ThreatTypes,
    DetectionMethods
| extend
    Urgency = "HIGH — Sender IP matches threat intel feed",
    RecommendedAction = "Quarantine email, investigate recipient device"
| order by Timestamp desc`
}
  /* ----------------------------------------------------------------
   * To add a new rule, copy this template:
   *
   * {
   *   id: 'unique-slug-here',
   *   title: 'Rule Title',
   *   platform: 'kql',           // 'kql' | 'spl' | 'sigma' | 'yara'
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
        <div class="det-platform ${r.platform}">${({kql:'KQL',spl:'SPL',sigma:'Sigma',yara:'YARA'})[r.platform] || r.platform.toUpperCase()}</div>
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
