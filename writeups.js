/* ============================================= */
/* CTFs & LABS DATA */
/* ============================================= */
/* Add a new lab/CTF entry by appending to the array below.
   Required: id, name, platform, icon (FA class), diff (easy|medium|hard|insane), date, color, bg, border, summary.
   Optional: featured (boolean), writeup (URL), tags[]. */

window.LABS = [
  {
    id: 'Phishing Alert, ID: 257',
    name: 'Phishing Alert',
    platform: 'LetsDefend',
    icon: 'fa-shield-halved',
    diff: 'medium',
    date: 'May 2026',
    color: '#f43f5e',
    bg: 'rgba(244,63,94,0.08)',
    border: 'rgba(244,63,94,0.25)',
    summary: 'Phishing Email which led to user compromise by downloading the malicious attachment',
    tags: ['Phishing', 'Email', 'KQL'],
    featured: true,
    writeup: 'phishing-alert-257.html'
  }
  /* ----------------------------------------------------------------
   * To add a new lab, copy this template:
   *
   * {
   *   id: 'unique-slug-here',
   *   name: 'Lab Name',
   *   platform: 'Hack The Box',
   *   icon: 'fa-flag',           // any Font Awesome 6 solid icon
   *   diff: 'medium',            // 'easy' | 'medium' | 'hard' | 'insane'
   *   date: 'May 2026',
   *   color: '#9fef00',          // platform brand color (used for accent)
   *   bg: 'rgba(159,239,0,0.08)',
   *   border: 'rgba(159,239,0,0.25)',
   *   summary: 'One sentence on what you learned.',
   *   tags: ['Tag1', 'Tag2'],
   *   featured: false,
   *   writeup: ''                // optional URL to a writeup
   * }
   * ---------------------------------------------------------------- */
];

/* Helper: parse "Month YYYY" or "In Progress" */
window.parseLabDate = function(s){
  if(s === 'In Progress') return new Date(2099, 0, 1); // pin to top
  const months = {January:0,February:1,March:2,April:3,May:4,June:5,July:6,August:7,September:8,October:9,November:10,December:11};
  const m = String(s||'').match(/(\w+)\s+(\d{4})/);
  if(!m) return new Date(0);
  return new Date(parseInt(m[2]), months[m[1]] || 0, 1);
};

/* Helper: render lab cards into a target grid */
window.buildLabCards = function(targetId, opts){
  opts = opts || {};
  const grid = document.getElementById(targetId);
  if(!grid) return;

  let list = window.LABS.slice();

  // Sort: In Progress first, then newest first
  list.sort((a,b) => window.parseLabDate(b.date) - window.parseLabDate(a.date));

  if(opts.featuredOnly){
    list = list.filter(l => l.featured);
  }
  if(opts.platform && opts.platform !== 'all'){
    list = list.filter(l => l.platform === opts.platform);
  }
  if(opts.search){
    const q = opts.search.toLowerCase();
    list = list.filter(l =>
      l.name.toLowerCase().includes(q) ||
      l.platform.toLowerCase().includes(q) ||
      (l.summary || '').toLowerCase().includes(q) ||
      (l.tags || []).some(t => t.toLowerCase().includes(q))
    );
  }
  if(opts.limit){
    list = list.slice(0, opts.limit);
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  if(!list.length){
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:40px;color:var(--muted);font-family:var(--mono);font-size:12px">// no labs match the current filter</div>';
    return;
  }

  // Compact card variant for homepage (no summary/tags), full for dedicated page
  const compact = opts.compact;

  grid.innerHTML = list.map(lab => {
    const inner = compact
      ? `
        <div class="lab-icon"><i class="fas ${lab.icon}"></i></div>
        <div class="lab-body">
          <div class="lab-title">${escapeHtml(lab.name)}</div>
          <div class="lab-platform">${escapeHtml(lab.platform)}</div>
          <div class="lab-foot">
            <span class="lab-diff ${lab.diff}">${lab.diff}</span>
            <span class="lab-date">${escapeHtml(lab.date)}</span>
          </div>
        </div>
      `
      : `
        <div class="lab-icon"><i class="fas ${lab.icon}"></i></div>
        <div class="lab-body">
          <div class="lab-title">${escapeHtml(lab.name)}</div>
          <div class="lab-platform">${escapeHtml(lab.platform)}</div>
          ${lab.summary ? `<div class="lab-summary">${escapeHtml(lab.summary)}</div>` : ''}
          ${(lab.tags || []).length ? `<div class="lab-tags">${lab.tags.map(t => `<span class="lab-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
          <div class="lab-foot">
            <span class="lab-diff ${lab.diff}">${lab.diff}</span>
            <span class="lab-date">${escapeHtml(lab.date)}</span>
            ${lab.writeup ? `<a href="${lab.writeup}" target="_blank" rel="noopener" class="lab-writeup">writeup →</a>` : ''}
          </div>
        </div>
      `;

    const wrapTag = lab.writeup && !compact ? 'a' : 'div';
    const wrapAttrs = lab.writeup && !compact
      ? `href="${lab.writeup}" target="_blank" rel="noopener"`
      : '';

    return `
      <${wrapTag} class="lab-card" ${wrapAttrs} style="--platform-color:${lab.color};--platform-bg:${lab.bg};--platform-border:${lab.border}">
        ${inner}
      </${wrapTag}>
    `;
  }).join('');
};
