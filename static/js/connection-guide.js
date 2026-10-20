(() => {
  const guide = document.getElementById('connection-guide');
  if (!guide) return;
  const steps = [...guide.querySelectorAll('.guide-step')];
  const checks = [...guide.querySelectorAll('[data-step]')];
  const key = guide.dataset.storageKey;
  const reset = document.getElementById('guide-reset');
  let remembered = [];
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || '[]');
    if (Array.isArray(value)) remembered = value.filter(item => typeof item === 'string');
  } catch (_) { /* The guide also works when browser storage is unavailable. */ }
  checks.forEach(check => { check.checked = remembered.includes(check.dataset.step); });

  function updateProgress(save) {
    const completed = checks.filter(check => check.checked).map(check => check.dataset.step);
    document.getElementById('guide-progress').value = completed.length;
    document.getElementById('guide-progress-text').textContent = `${completed.length} de 6 pasos marcados`;
    steps.forEach((step, index) => {
      step.classList.toggle('is-complete', checks[index].checked);
      step.querySelector('.guide-done').hidden = !checks[index].checked;
    });
    reset.hidden = completed.length === 0;
    if (save) {
      try { sessionStorage.setItem(key, JSON.stringify(completed)); } catch (_) { /* Keep current marks in memory. */ }
    }
  }
  function openHash() {
    const target = document.getElementById(location.hash.slice(1));
    if (!target || !guide.contains(target)) return;
    const step = target.closest('details');
    if (step) step.open = true;
    target.scrollIntoView({block: 'start'});
  }
  checks.forEach(check => check.addEventListener('change', () => updateProgress(true)));
  reset.addEventListener('click', () => {
    checks.forEach(check => { check.checked = false; });
    updateProgress(true);
  });
  guide.querySelectorAll('a[href^="#"]').forEach(link => link.addEventListener('click', () => {
    const target = document.getElementById(link.hash.slice(1));
    if (target?.matches('details')) target.open = true;
  }));
  window.addEventListener('hashchange', openHash);
  document.querySelectorAll('[data-copy-target]').forEach(button => {
    if (!navigator.clipboard?.writeText) return;
    button.hidden = false;
    button.addEventListener('click', async () => {
      const text = document.getElementById(button.dataset.copyTarget)?.textContent.trim();
      if (!text) return;
      const message = document.getElementById('guide-copy-status');
      try {
        await navigator.clipboard.writeText(text);
        message.textContent = 'Destino copiado. Introduce la IP y el puerto en sus campos correspondientes.';
      } catch (_) {
        message.textContent = 'Selecciona el destino mostrado y cópialo manualmente.';
      }
    });
  });
  updateProgress(false);
  if (location.hash) openHash();
})();
