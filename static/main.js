document.addEventListener('DOMContentLoaded', () => {
  console.log('IPAM loaded');
  // Enable Bootstrap tooltips
  if (window.bootstrap) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
      try { new bootstrap.Tooltip(el); } catch (_) {}
    });
  }

  // Inline edit for subnet name
  document.querySelectorAll('.js-edit-subnet').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const form = document.querySelector(`.js-subnet-edit[data-id="${id}"]`);
      if (form) {
        form.classList.remove('d-none');
        const input = form.querySelector('input[name="name"]');
        if (input) input.focus();
      }
    });
  });
  document.querySelectorAll('.js-cancel-edit-subnet').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const form = document.querySelector(`.js-subnet-edit[data-id="${id}"]`);
      if (form) form.classList.add('d-none');
    });
  });

  // Toggle MAC edit form
  document.querySelectorAll('.js-toggle-mac').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const f = document.querySelector(`.js-mac-edit[data-id="${id}"]`);
      const d = document.querySelector(`.js-mac-display[data-id="${id}"]`);
      if (f && d) {
        f.classList.toggle('d-none');
        d.classList.toggle('d-none');
        const input = f.querySelector('input[name="mac"]');
        if (input && !f.classList.contains('d-none')) input.focus();
      }
    });
  });
  document.querySelectorAll('.js-cancel-mac').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const form = e.target.closest('.js-mac-edit');
      if (form) {
        const id = form.getAttribute('data-id');
        const d = document.querySelector(`.js-mac-display[data-id="${id}"]`);
        form.classList.add('d-none');
        if (d) d.classList.remove('d-none');
      }
    });
  });

  // Copy MAC on click
  document.querySelectorAll('.js-copy-mac').forEach(el => {
    el.addEventListener('click', async () => {
      const text = (el.innerText || '').trim();
      if (!text) return;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          const ta = document.createElement('textarea');
          ta.value = text; document.body.appendChild(ta); ta.select();
          document.execCommand('copy'); document.body.removeChild(ta);
        }
        const oldTitle = el.getAttribute('title') || '';
        el.setAttribute('title', 'Copied!');
        try { if (window.bootstrap) new bootstrap.Tooltip(el).show(); } catch (_) {}
        el.classList.add('text-success');
        setTimeout(() => {
          el.classList.remove('text-success');
          el.setAttribute('title', oldTitle || 'Click to copy');
        }, 800);
      } catch (_) {}
    });
  });

  // Copy IP on click (pill) and via Enter/Space
  document.querySelectorAll('.pill-ip').forEach(el => {
    const doCopy = async () => {
      const ip = (el.innerText || '').trim();
      if (!ip) return;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(ip);
        } else {
          const ta = document.createElement('textarea');
          ta.value = ip; document.body.appendChild(ta); ta.select();
          document.execCommand('copy'); document.body.removeChild(ta);
        }
        // Ensure any existing tooltip (ports) hides and doesn't stick
        try {
          if (window.bootstrap) {
            const inst = bootstrap.Tooltip.getInstance(el);
            if (inst) inst.hide();
          }
        } catch (_) {}
        // Remove focus so tooltip tied to :focus isn't re-shown
        try { el.blur(); } catch (_) {}
        // Subtle visual confirmation without a tooltip
        el.classList.add('text-success');
        setTimeout(() => { el.classList.remove('text-success'); }, 500);
      } catch (_) {}
    };
    el.addEventListener('click', doCopy);
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        doCopy();
      }
    });
  });

  // Preserve active host tab across reloads
  const tabKey = 'activeHostTab';
  document.querySelectorAll('#hostTabs a[data-bs-toggle="tab"]').forEach(a => {
    a.addEventListener('shown.bs.tab', (ev) => {
      const href = ev.target.getAttribute('href');
      if (href) localStorage.setItem(tabKey, href);
      ensureTabVisible(ev.target);
    });
  });
  const saved = localStorage.getItem(tabKey);
  if (saved) {
    const link = document.querySelector(`#hostTabs a[href="${saved}"]`);
    if (link && window.bootstrap) {
      try { new bootstrap.Tab(link).show(); } catch (_) {}
      ensureTabVisible(link);
    }
  }

  // Mobile select for tabs
  const tabSelect = document.getElementById('hostTabSelect');
  if (tabSelect && window.bootstrap) {
    tabSelect.addEventListener('change', () => {
      const target = tabSelect.value;
      const link = document.querySelector(`#hostTabs a[href="${target}"]`);
      if (link) {
        try { new bootstrap.Tab(link).show(); } catch (_) {}
      }
    });
    // Keep select in sync with active tab
    document.querySelectorAll('#hostTabs a[data-bs-toggle="tab"]').forEach(a => {
      a.addEventListener('shown.bs.tab', (ev) => {
        const href = ev.target.getAttribute('href');
        if (href) tabSelect.value = href;
      });
    });
  }

  // Toggle tab-global-actions visibility to match active tab
  function updateTabActions(target) {
    document.querySelectorAll('.tab-action').forEach(f => {
      const t = f.getAttribute('data-target');
      if (t === target) f.classList.remove('d-none'); else f.classList.add('d-none');
    });
  }
  // Initialize based on active pane
  const activePane = document.querySelector('.tab-pane.show.active');
  if (activePane) updateTabActions('#'+activePane.id);
  document.querySelectorAll('#hostTabs a[data-bs-toggle="tab"]').forEach(a => {
    a.addEventListener('shown.bs.tab', (ev) => {
      const href = ev.target.getAttribute('href');
      if (href) updateTabActions(href);
    });
  });

  // Drag scroll for tabs
  document.querySelectorAll('.tab-scroll').forEach(scroller => {
    let isDown = false, startX = 0, scrollLeft = 0;
    scroller.addEventListener('mousedown', (e) => { isDown = true; startX = e.pageX - scroller.offsetLeft; scrollLeft = scroller.scrollLeft; });
    scroller.addEventListener('mouseleave', () => { isDown = false; });
    scroller.addEventListener('mouseup', () => { isDown = false; });
    scroller.addEventListener('mousemove', (e) => {
      if (!isDown) return; e.preventDefault(); const x = e.pageX - scroller.offsetLeft; const walk = (x - startX) * 1; scroller.scrollLeft = scrollLeft - walk;
    });
    // Hover scroll toward edges with a single timer
    let hoverTimer = null; let edgeDir = 0;
    function startHoverScroll() {
      if (hoverTimer) return;
      hoverTimer = setInterval(() => { if (edgeDir !== 0) scroller.scrollLeft += edgeDir * 8; }, 30);
    }
    function stopHoverScroll() { if (hoverTimer) { clearInterval(hoverTimer); hoverTimer = null; } edgeDir = 0; }
    scroller.addEventListener('mousemove', (e) => {
      const rect = scroller.getBoundingClientRect(); const margin = 48; const mx = e.clientX - rect.left;
      edgeDir = (mx < margin) ? -1 : (mx > rect.width - margin) ? 1 : 0; if (edgeDir !== 0) startHoverScroll();
      else if (!isDown) stopHoverScroll();
    });
    scroller.addEventListener('mouseleave', stopHoverScroll);
    // Wheel scroll horizontally
    scroller.addEventListener('wheel', (e) => {
      const delta = Math.abs(e.deltaY) > Math.abs(e.deltaX) ? e.deltaY : e.deltaX;
      scroller.scrollLeft += delta;
      e.preventDefault();
    }, { passive: false });
  });

  // Removed arrow controls; hover edge + wheel + drag provide scrolling

  // Ensure active tab remains visible within horizontal scroller
  function ensureTabVisible(link) {
    const scroller = link.closest('.tab-scroll');
    if (!scroller) return;
    const itemRect = link.getBoundingClientRect();
    const scrollRect = scroller.getBoundingClientRect();
    const pad = 24;
    if (itemRect.left < scrollRect.left) {
      scroller.scrollLeft -= (scrollRect.left - itemRect.left) + pad;
    } else if (itemRect.right > scrollRect.right) {
      scroller.scrollLeft += (itemRect.right - scrollRect.right) + pad;
    }
  }

  // Theme toggle (light/dark) persisted
  const themeKey = 'ipamTheme';
  const root = document.documentElement;
  function applyTheme(t) {
    root.setAttribute('data-bs-theme', t);
    const sun = document.getElementById('icon-sun');
    const moon = document.getElementById('icon-moon');
    if (sun && moon) {
      if (t === 'dark') { sun.classList.add('d-none'); moon.classList.remove('d-none'); }
      else { moon.classList.add('d-none'); sun.classList.remove('d-none'); }
    }
  }
  const storedTheme = localStorage.getItem(themeKey) || 'light';
  applyTheme(storedTheme);
  const themeBtn = document.getElementById('themeToggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const cur = root.getAttribute('data-bs-theme') || 'light';
      const next = cur === 'dark' ? 'light' : 'dark';
      localStorage.setItem(themeKey, next);
      applyTheme(next);
    });
  }
});
