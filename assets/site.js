
(() => {
  if (window.__uvyThemeInitialized) return;
  window.__uvyThemeInitialized = true;
  const root = document.documentElement;
  const selector = '[data-uvy-theme-toggle], #theme-toggle';
  const system = matchMedia('(prefers-color-scheme: dark)');
  let preference = null;
  try {
    const cookie = document.cookie.split('; ').find(value => value.startsWith('uvy-theme='));
    const saved = cookie?.slice('uvy-theme='.length);
    if (saved === 'light' || saved === 'dark') preference = saved;
  } catch {}
  const sync = () => {
    const dark = preference ? preference === 'dark' : system.matches;
    root.dataset.theme = dark ? 'dark' : 'light';
    root.style.colorScheme = dark ? 'dark' : 'light';
    document.querySelectorAll(selector).forEach(button => {
      button.hidden = false;
      button.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
      button.title = dark ? 'Switch to light mode' : 'Switch to dark mode';
    });
  };
  sync();
  system.addEventListener('change', () => { if (!preference) sync(); });
  document.addEventListener('click', event => {
    if (!(event.target instanceof Element) || !event.target.closest(selector)) return;
    preference = root.dataset.theme === 'dark' ? 'light' : 'dark';
    try {
      document.cookie = `uvy-theme=${preference}; Path=/; Max-Age=31536000; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
    } catch {}
    sync();
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', sync, { once: true });
  else sync();
  // Both spellings are version-specific; supporting shell reinitialization is harmless.
  document.addEventListener('htmx:after:swap', sync);
  document.addEventListener('htmx:afterSwap', sync);
})();

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
