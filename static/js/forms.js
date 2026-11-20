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
  // Adjuntos: se comprueba el número y el tamaño total antes de enviar; Nginx rechaza lo que supera su
  // límite con una página de error sin explicación. El servidor vuelve a comprobarlo todo.
  document.addEventListener('change', function (event) {
    var input = event.target;
    if (!input.matches || !input.matches('input[type=file][data-max-bytes]')) return;
    var max = parseInt(input.dataset.maxBytes, 10), maxFiles = parseInt(input.dataset.maxFiles || '0', 10), total = 0;
    Array.prototype.forEach.call(input.files, function (file) { total += file.size; });
    var message = '';
    if (maxFiles && input.files.length > maxFiles) message = 'Como máximo ' + maxFiles + ' archivos por mensaje.';
    else if (total > max) message = 'Los archivos ocupan ' + (total / 1048576).toFixed(1).replace('.', ',') + ' MB y el máximo es '
      + (max / 1048576).toFixed(1).replace('.', ',') + ' MB en total.';
    input.setCustomValidity(message);
    if (message) input.reportValidity();
  });
  window.addEventListener('pageshow', function () {
    document.querySelectorAll('button[aria-busy]').forEach(function (button) { button.removeAttribute('aria-busy'); });
    document.querySelectorAll('form[data-sending]').forEach(function (form) { delete form.dataset.sending; });
  });
})();
