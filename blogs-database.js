/* ── BLOG DATA FROM CENTRAL DATABASE ── */
function buildBlogsFromDatabase(limit = 3) {
    const grid = document.getElementById('blogGrid');
    if (!grid) return;
    
    // Get latest blogs from the central database
    const latestBlogs = getLatestBlogs(limit);
    
    grid.innerHTML = '';
    
    latestBlogs.forEach((b, i) => {
        const card = document.createElement('div');
        card.className = 'blog-card reveal';
        card.style.transitionDelay = (i * .1) + 's';
        
        card.innerHTML = `
            <div class="blog-cat"><i class="${b.icon}" style="font-size:10px"></i>${b.catLabel}</div>
            <div class="blog-title">${b.title}</div>
            <div class="blog-meta"><i class="far fa-calendar-alt"></i> ${b.date}</div>
            <div class="blog-excerpt">${b.excerpt}</div>
            <div class="blog-footer">
                <span class="blog-read">Read Analysis <i class="fas fa-arrow-right"></i></span>
                <div class="blog-tags">${b.mitre.slice(0, 3).map(m => `<span class="blog-tag">${m}</span>`).join('')}</div>
            </div>
        `;
        
        card.addEventListener('click', () => {
            window.location.href = `research.html#${b.id}`;
        });
        
        grid.appendChild(card);
        setTimeout(() => card.classList.add('visible'), 50 + i * 100);
    });
}

// Call the function
buildBlogsFromDatabase(3);

// Update stats count
document.addEventListener('DOMContentLoaded', () => {
    const blogCountElement = document.querySelector('[data-count="4"]');
    if (blogCountElement && typeof getAllBlogs === 'function') {
        const totalBlogs = getAllBlogs().length;
        blogCountElement.setAttribute('data-count', totalBlogs);
    }
});
