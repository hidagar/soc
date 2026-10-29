"""Comprobación de solo lectura tras restaurar el SOC en un ensayo de recuperación.

Se ejecuta en la VM restaurada (red aislada), con el entorno cargado como deploy/update.sh:

    sudo bash -c 'eval "$(python3 /srv/soc-portal/deploy/envfile.py --shell /etc/soc-portal/portal.env)"; cd /srv/soc-portal && runuser -u socportal -- /opt/soc-portal-venv/bin/python manage.py comprobar_restauracion'

Muestra recuentos, el último dato de cada tipo (para medir la pérdida comparándolo con producción),
migraciones pendientes, la cadena de auditoría y si las claves descifran los valores guardados.
Nunca muestra IPs, nombres de clientes, claves ni contenido de registros: la salida se puede compartir.
"""
import subprocess

from django.core.management.base import BaseCommand
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.models import Max
from django.utils import timezone

from core.key_rotation import rotate
from core.models import (AuditEvent, BackupRun, Client, Device, DeviceHealth, Incident, SecurityEvidence, Site,
                         UrgentAlert, WeeklyReport)
from core.security import audit_integrity

# Trabajos que en un clon hablan con el exterior (correo, firewalls de clientes, UniFi, CrowdSec).
OUTBOUND_UNITS = ('soc-monitor.timer', 'soc-urgent-alerts.timer', 'soc-weekly-reports.timer', 'soc-changes.timer',
                  'soc-backup.timer', 'soc-backup-daily.timer', 'soc-wazuh-sources.timer', 'soc-wazuh-dashboards.timer')

LATEST = [
    ('Última detección recibida', SecurityEvidence, 'observed_at'),
    ('Último registro de un equipo', DeviceHealth, 'last_log_at'),
    ('Última incidencia', Incident, 'observed_at'),
    ('Último aviso urgente', UrgentAlert, 'observed_at'),
    ('Último evento de auditoría', AuditEvent, 'created_at'),
    ('Última copia interna', BackupRun, 'created_at'),
]
COUNTS = [('Clientes', Client), ('Sedes', Site), ('Equipos', Device), ('Detecciones', SecurityEvidence),
          ('Incidencias', Incident), ('Informes semanales', WeeklyReport), ('Eventos de auditoría', AuditEvent)]


class Command(BaseCommand):
    help = 'Comprueba (solo lectura) una restauración del SOC y muestra lo necesario para medir la pérdida de datos.'

    def handle(self, *args, **options):
        failures = 0
        now = timezone.now()
        out = self.stdout.write
        out(f'Comprobación de restauración · {timezone.localtime(now):%d/%m/%Y %H:%M}')

        out('\nAislamiento')
        active = [unit for unit in OUTBOUND_UNITS if self.unit_active(unit)]
        if active:
            failures += 1
            out(self.style.ERROR(f'  AVISO: activos {", ".join(active)}. En un ensayo deben estar parados '
                                 '(correo, firewalls y consolas de clientes reales).'))
        else:
            out('  Temporizadores con salida al exterior: parados o no instalados.')

        out('\nBase de datos')
        pending = MigrationExecutor(connection).migration_plan(MigrationExecutor(connection).loader.graph.leaf_nodes())
        if pending:
            failures += 1
            out(self.style.ERROR(f'  {len(pending)} migraciones sin aplicar: la base es de otra versión del código.'))
        else:
            out(f'  Motor {connection.vendor}; todas las migraciones aplicadas.')
        for label, model in COUNTS:
            out(f'  {label}: {model._base_manager.count()}')

        out('\nÚltimo dato de cada tipo (compáralo con producción para medir la pérdida)')
        for label, model, field in LATEST:
            value = model._base_manager.aggregate(m=Max(field))['m']
            if value:
                hours = (now - value).total_seconds() / 3600
                out(f'  {label}: {timezone.localtime(value):%d/%m/%Y %H:%M} (hace {hours:.1f} h)')
            else:
                out(f'  {label}: ninguno')

        out('\nIntegridad')
        if audit_integrity():
            out('  Cadena de auditoría: íntegra (también confirma que SOC_PORTAL_SECRET_KEY es la original).')
        else:
            failures += 1
            out(self.style.ERROR('  Cadena de auditoría: NO coincide. ¿SECRET_KEY distinta o base incompleta?'))
        report = rotate(apply=False)
        undecrypted = sum(rows for (_, _, family), rows in report.items()
                          if family in ('sin descifrar', 'cambiado durante el recifrado'))
        if undecrypted:
            failures += 1
            out(self.style.ERROR(f'  Valores cifrados: {undecrypted} no se descifran con las claves restauradas.'))
        else:
            out(f'  Valores cifrados: {sum(report.values())} revisados, todos se descifran.')

        out('')
        if failures:
            out(self.style.ERROR(f'Resultado: {failures} comprobación(es) a revisar antes de dar el ensayo por bueno.'))
        else:
            out(self.style.SUCCESS('Resultado: restauración coherente. Completa la prueba manual (acceso, MFA, '
                                   'informes, dashboards) y registra pérdida y tiempo en Copias y recuperación.'))

    @staticmethod
    def unit_active(unit):
        try:
            return subprocess.run(['systemctl', 'is-active', '--quiet', unit], timeout=5).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
