// Comportamiento común de los formularios del SOC y del portal del cliente.
(function () {
  // Doble envío: al enviar un formulario se bloquea su botón. Se hace tras recoger los datos, para
  // que el nombre y el valor del botón pulsado sigan llegando al servidor.
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (form.method.toLowerCase() !== 'post' || form.dataset.sending) return;
    form.dataset.sending = '1';
    setTimeout(function () {
      form.querySelectorAll('button[type=submit],button:not([type])').forEach(function (button) { button.setAttribute('aria-busy', 'true'); });
    }, 0);
    setTimeout(function () {
      delete form.dataset.sending;
      form.querySelectorAll('button[aria-busy]').forEach(function (button) { button.removeAttribute('aria-busy'); });
    }, 8000);
  }, true);
  window.addEventListener('pageshow', function () {
    document.querySelectorAll('button[aria-busy]').forEach(function (button) { button.removeAttribute('aria-busy'); });
    document.querySelectorAll('form[data-sending]').forEach(function (form) { delete form.dataset.sending; });
  });
})();
