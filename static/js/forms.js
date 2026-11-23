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
  // Menú del portal en el móvil: si la página actual queda fuera, se desliza hasta ella.
  document.addEventListener('DOMContentLoaded', function () {
    var nav = document.querySelector('.customer-nav'), current = nav && nav.querySelector('[aria-current=page]');
    if (nav && current && nav.scrollWidth > nav.clientWidth) {
      nav.scrollLeft = current.offsetLeft - (nav.clientWidth - current.offsetWidth) / 2;
    }
  });
  // Tablas en el móvil: cada fila pasa a ser una tarjeta con el nombre de cada columna, como las tablas
  // «stacked» (el estilo solo actúa en pantallas estrechas). La primera columna hace de título.
  // Una tabla puede quedarse como tabla con data-table-keep en su contenedor.
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.table-wrap:not(.stacked):not([data-table-keep])').forEach(function (wrap) {
      var table = wrap.querySelector('table');
      if (!table || !table.tHead || !table.tHead.rows.length) return;
      var heads = Array.prototype.map.call(table.tHead.rows[0].cells, function (th) { return th.textContent.trim(); });
      if (heads.length < 3) return;
      Array.prototype.forEach.call(table.tBodies, function (body) {
        Array.prototype.forEach.call(body.rows, function (row) {
          var index = 0;
          Array.prototype.forEach.call(row.cells, function (cell) {
            if (index > 0 && cell.colSpan === 1 && heads[index] && !cell.hasAttribute('data-label')) {
              cell.setAttribute('data-label', heads[index]);
            }
            index += cell.colSpan || 1;
          });
        });
      });
      wrap.classList.add('stacked');
    });
  });
  window.addEventListener('pageshow', function () {
    document.querySelectorAll('button[aria-busy]').forEach(function (button) { button.removeAttribute('aria-busy'); });
    document.querySelectorAll('form[data-sending]').forEach(function (form) { delete form.dataset.sending; });
  });
})();
