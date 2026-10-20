from django.core.management.base import BaseCommand, CommandError

from core.urgent_alerts import deliver_pending, scan_events


class Command(BaseCommand):
    help = "Revisa eventos urgentes de Wazuh y envía avisos individuales por SendGrid."

    def handle(self, *args, **options):
        errors=[];recorded=accepted=0
        try:
            accepted += deliver_pending()
        except Exception as exc:
            errors.append('entrega:'+type(exc).__name__)
        try:
            recorded = scan_events()
        except Exception as exc:
            errors.append('consulta:'+type(exc).__name__)
        # Also deliver newly queued pages when scanning reached its bounded limit.
        try:
            accepted += deliver_pending()
        except Exception as exc:
            errors.append('entrega:'+type(exc).__name__)
        if errors:raise CommandError('Avisos urgentes pendientes: '+', '.join(errors))
        self.stdout.write(f"Eventos urgentes nuevos: {recorded}. Correos aceptados por SendGrid: {accepted}.")
