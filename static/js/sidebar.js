// Recuerda qué grupos del menú lateral abrió el usuario y gestiona el menú en móvil.
(function () {
  var KEY = 'soc-nav-open';
  var groups = document.querySelectorAll('.nav-group[data-nav-group]');
  var saved = [];
  try { saved = JSON.parse(localStorage.getItem(KEY) || '[]'); } catch (e) { saved = []; }
  groups.forEach(function (group) {
    if (saved.indexOf(group.dataset.navGroup) !== -1) group.open = true;
    group.addEventListener('toggle', function () {
      var open = [];
      groups.forEach(function (g) { if (g.open) open.push(g.dataset.navGroup); });
      try { localStorage.setItem(KEY, JSON.stringify(open)); } catch (e) { /* sin almacenamiento */ }
    });
  });
  var sidebar = document.querySelector('.sidebar');
  var toggle = document.querySelector('.nav-toggle');
  if (!sidebar || !toggle) return;
  sidebar.classList.add('nav-collapsible');
  toggle.addEventListener('click', function () {
    var open = sidebar.classList.toggle('nav-open');
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
})();
