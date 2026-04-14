const blogs = [

  {
    id: 'Cpuid',
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
    excerpt: 'A threat actor compromised CPUID\'s secondary download API for approximately six hours, redirecting users to Cloudflare R2-hosted trojanized installers for CPU-Z, HWMonitor, HWMonitor Pro, and PerfMonitor. The payload was STX RAT',
    mitre: ['T1195.002', 'T1204.002', 'T1027.002', 'T1571'],
  },

];
