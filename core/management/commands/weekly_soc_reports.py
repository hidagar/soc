from datetime import date, timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core.reporting import refresh_week, send_report


class Command(BaseCommand):
    help = "Actualiza informes con alertas Wazuh y envía los clientes que los han activado."

    def add_arguments(self, parser):
        parser.add_argument("--week", help="Lunes de la semana (AAAA-MM-DD); por defecto, la última semana completa")
        parser.add_argument("--send", action="store_true", help="Enviar por SendGrid los informes activados")

    def handle(self, *args, **options):
        if options["week"]:
            try:
                monday = date.fromisoformat(options["week"])
            except ValueError as exc:
                raise CommandError("Indica un lunes válido en formato AAAA-MM-DD.") from exc
        else:
            today = timezone.localdate()
            monday = today - timedelta(days=today.weekday() + 7)
        if monday.weekday() != 0:
            raise CommandError("La fecha debe ser lunes.")
        sent = 0

        def deliver(report):
            # Cada informe se envía justo tras recopilarlo, dentro de su vigencia de 15 minutos.
            nonlocal sent
            if options["send"]:
                try:
                    sent += int(send_report(report))
                except Exception as exc:
                    self.stderr.write(f"Falló el correo del cliente {report.client_id}: {type(exc).__name__}")
            self.stdout.write(f"{report.client.code}: {report.security_count} detecciones SIEM, {report.wazuh_alert_count} alertas Wazuh")

        try:
            reports, failures = refresh_week(monday, on_report=deliver)
        except Exception as exc:
            raise CommandError(f"No se pudo consultar Wazuh: {exc}") from exc
        for client, exc in failures:
            self.stderr.write(f"No se pudo recopilar el cliente {client.code}: {type(exc).__name__}")
        self.stdout.write(f"Informes: {len(reports)}. Correos aceptados por SendGrid: {sent}.")
        if failures:
            raise CommandError(f"{len(failures)} clientes sin informe esta semana. Revisar y repetir con --week {monday}.")
