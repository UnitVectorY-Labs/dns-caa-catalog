// Local shell enhancement; existing URLs, fragment routes and AND filters are retained.
(() => {
  const panel = document.querySelector('#leftPanel');
  const overlay = document.querySelector('#navOverlay');
  const toggle = document.querySelector('#navToggle');
  const setOpen = open => {
    panel.classList.toggle('open', open); overlay.classList.toggle('open', open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close domain navigation' : 'Open domain navigation');
  };
  toggle.addEventListener('click', () => setOpen(!panel.classList.contains('open')));
  overlay.addEventListener('click', () => setOpen(false));
  document.addEventListener('keydown', event => { if(event.key === 'Escape' && panel.classList.contains('open')) { setOpen(false); toggle.focus(); } });
  function applyFilters() {
    const query = document.querySelector('#searchInput')?.value.toLowerCase() || '';
    const hideMissing = document.querySelector('#hideMissingCaa')?.checked || false;
    const filters = Array.from(document.querySelectorAll('[data-filter]:checked')).map(input => input.dataset.filter);
    panel.querySelectorAll('.domain-link').forEach(link => {
      link.hidden = !(link.textContent.toLowerCase().includes(query) && (!hideMissing || link.dataset.hasCaa === 'true') && filters.every(filter => link.getAttribute('data-has-' + filter) === 'true'));
    });
  }
  document.addEventListener('input', event => { if(event.target.id === 'searchInput') applyFilters(); });
  document.addEventListener('change', event => { if(event.target.closest('.filter-container')) applyFilters(); });
  document.addEventListener('click', event => { if(event.target.closest('.domain-link')) setOpen(false); });
  function sync() {
    applyFilters();
    const search = document.querySelector('.search-container');
    if(search) document.documentElement.style.setProperty('--search-container-height', `${search.getBoundingClientRect().height}px`);
    const content = document.querySelector('#content');
    const heading = content.querySelector('.page-header-title');
    document.title = heading ? `${heading.textContent.trim()}${location.pathname.includes('/providers/') ? ' - Certificate Authority' : ''} - DNS CAA Catalog` : 'DNS CAA Catalog';
    panel.querySelectorAll('.domain-link').forEach(link => { if(new URL(link.href).pathname === location.pathname) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current'); });
  }
  document.body.addEventListener('htmx:after:swap', event => {
    sync();
    // HTMX 4 dispatches on the requester, not necessarily the swap region.
    if(event.target.closest('a[hx-target="#content"]')) { setOpen(false); document.querySelector('#content').focus({preventScroll:true}); }
  });
  window.addEventListener('popstate', () => setTimeout(sync, 100));
  sync();
})();
