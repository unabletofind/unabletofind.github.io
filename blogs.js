/* =================================================
   BLOG / RESEARCH POSTS — central data source
   Add new posts to this array. Both index.html and
   research.html will pick them up automatically.
   ================================================= */
const blogs = [
  {
    id: 'cpuid-stx-rat',
    url: 'CPUID.html',
    cat: 'Trojan',
    catLabel: 'Trojan',
    catColor: 'rgba(244,63,94,0.12)',
    catBorder: 'rgba(244,63,94,0.2)',
    catText: '#f43f5e',
    icon: 'fas fa-skull',
    readTime: '20 min',
    title: 'CPUID Breach: STX RAT Delivered via Trojanized CPU-Z & HWMonitor Downloads',
    date: 'April 2026',
    featured: true,
    excerpt: 'A threat actor compromised CPUID\'s secondary download API for approximately six hours, redirecting users to Cloudflare R2-hosted trojanized installers for CPU-Z, HWMonitor, HWMonitor Pro, and PerfMonitor. The payload was STX RAT — a multi-stage in-memory RAT with credential theft and browser harvesting.',
    mitre: ['T1195.002', 'T1204.002', 'T1027.002', 'T1571'],
  },
  /* ── Add new posts below this line ──────────────────────────────────────
  {
    id: 'your-post-id',
    url: 'your-post.html',
    cat: 'Phishing',          // used for filter buttons
    catLabel: 'Phishing',
    catColor: 'rgba(245,158,11,0.12)',
    catBorder: 'rgba(245,158,11,0.2)',
    catText: '#f59e0b',
    icon: 'fas fa-fish',
    readTime: '15 min',
    title: 'Your Post Title Here',
    date: 'May 2026',
    featured: false,
    excerpt: 'Short summary shown on the card...',
    mitre: ['T1566.001', 'T1078'],
  },
  ─────────────────────────────────────────────────────────────────────── */
];

/* =================================================
   Render blog cards into #blogGrid
   buildBlogCards(limit) — pass a number to show
   only the latest N, or omit for all.
   Note: index.html has its own renderer; this is
   used by other pages that want auto-render.
   ================================================= */
function buildBlogCards(limit) {
  const grid = document.getElementById('blogGrid');
  if (!grid) return;
  grid.innerHTML = '';
  const list = limit ? blogs.slice(0, limit) : blogs;
  list.forEach((b, i) => {
    const card = document.createElement('div');
    card.className = 'blog-card';
    card.style.transitionDelay = (i * 0.1) + 's';
    card.innerHTML = `
      <span class="blog-cat-badge" style="background:${b.catColor};border-color:${b.catBorder};color:${b.catText}">
        <i class="${b.icon}" style="font-size:9px"></i> ${b.catLabel}
      </span>
      <div class="blog-title">${b.title}</div>
      <div class="blog-meta">
        <span><i class="far fa-calendar-alt"></i> ${b.date}</span>
        <span><i class="fas fa-clock"></i> ${b.readTime} read</span>
      </div>
      <div class="blog-excerpt">${b.excerpt}</div>
      <div class="blog-footer">
        <span class="blog-read">Read Analysis <i class="fas fa-arrow-right"></i></span>
        <div class="blog-tags">${b.mitre.map(m => `<span class="blog-tag">${m}</span>`).join('')}</div>
      </div>`;
    card.addEventListener('click', () => window.location.href = b.url);
    grid.appendChild(card);
  });

  /* Sync the "Published Research" counter in the stats bar */
  const countEl = document.getElementById('researchCount');
  if (countEl) {
    countEl.dataset.count = blogs.length;
    countEl.dataset.counted = '';
  }
}
