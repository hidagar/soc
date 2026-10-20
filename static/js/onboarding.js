(() => {
  const destination = document.getElementById('id_destination');
  const displayedDestination = document.getElementById('wizard-destination');
  destination?.addEventListener('change', () => { displayedDestination.textContent = destination.value; });
  document.querySelectorAll('[data-copy], [data-copy-value]').forEach(button => {
    button.addEventListener('click', async () => {
      const value = button.dataset.copyValue || document.getElementById(button.dataset.copy)?.textContent;
      const feedback = document.getElementById('copy-status');
      try { await navigator.clipboard.writeText(value); feedback.textContent = 'Copiado.'; }
      catch { feedback.textContent = 'Selecciona el dato y cópialo manualmente.'; }
    });
  });
  const verification = document.getElementById('wizard-verification');
  if (!verification || verification.dataset.verified === 'true') return;
  const message = document.getElementById('verification-poll-status');
  const check = document.getElementById('check-now');
  let complete = false, running = false, timer = null, polls = 0;
  async function update() {
    if (complete || running || document.hidden) return;
    running = true;
    if (check) check.disabled = true;
    try {
      const response = await fetch(verification.dataset.statusUrl, {credentials: 'same-origin', cache: 'no-store', headers: {'Accept': 'application/json'}});
      if (!response.ok || response.redirected) throw new Error('No se pudo consultar el estado. Comprueba tu sesión y recarga la página.');
      const state = await response.json();
      const receiver = document.getElementById('receiver-check');
      receiver.classList.toggle('done', state.receiver_ready);
      receiver.textContent = state.receiver_ready ? 'Receptor Wazuh preparado' : 'Receptor Wazuh preparado · pendiente';
      const error = document.getElementById('verification-error');
      error.hidden = !state.error; error.textContent = state.error;
      message.textContent = state.checked_at ? `Última comprobación del SOC: ${state.checked_at}.` : 'Esperando la primera comprobación del SOC.';
      if (state.zenarmor_required) {
        const opnsense = document.getElementById('event-check');
        opnsense.classList.toggle('done', state.opnsense_received);
        opnsense.textContent = state.opnsense_received ? 'Eventos OPNsense recibidos e interpretados' : 'Eventos OPNsense · pendiente';
        const zenarmor = document.getElementById('zenarmor-check');
        if (zenarmor) {
          zenarmor.classList.toggle('done', state.zenarmor_received);
          zenarmor.textContent = state.zenarmor_received ? 'Eventos Zenarmor recibidos e interpretados' : 'Eventos Zenarmor · pendiente';
        }
      }
      if (state.verified) {
        complete = true;
        clearInterval(timer);
        document.getElementById('verification-title').textContent = 'Equipo activo';
        const event = document.getElementById('event-check'); event.classList.add('done'); event.textContent = state.zenarmor_required ? 'Eventos OPNsense recibidos e interpretados' : 'Evento nuevo recibido e interpretado';
        document.getElementById('verification-wait').hidden = true;
        document.getElementById('verification-pending-actions').hidden = true;
        document.getElementById('verification-complete').hidden = false;
        document.getElementById('verified-event-at').textContent = state.event_at;
        document.getElementById('verified-decoder').textContent = state.decoder;
        document.getElementById('verified-rule').textContent = state.rule;
      }
    } catch (error) { message.textContent = error.message; }
    finally { running = false; if (check) check.disabled = false; }
  }
  check?.addEventListener('click', update);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) update(); });
  update();
  timer = setInterval(() => {
    if (++polls >= 60) { clearInterval(timer); message.textContent = 'La consulta automática se ha pausado tras 10 minutos. Puedes comprobar ahora o volver más tarde.'; }
    else update();
  }, 10000);
})();
