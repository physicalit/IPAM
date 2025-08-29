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
});
