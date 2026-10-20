import json

from django.core.management.base import BaseCommand

from core.models import Client, ExportConfiguration


class Command(BaseCommand):
    help = ('Clientes activos y orígenes Syslog preparados, en JSON, para deploy/sync_wazuh_dashboards.py. '
            'Misma selección que su lectura directa de SQLite; sirve para cualquier motor de base.')

    def handle(self, *args, **options):
        clients = Client._base_manager.filter(active=True).order_by('name').values_list('code', 'name')
        sources = ExportConfiguration._base_manager.filter(
            device__active=True, device__site__active=True, device__site__client__active=True,
            source_ip__isnull=False, receiver_ready=True,
        ).values_list('device__site__client__code', 'source_ip')
        self.stdout.write(json.dumps({'clients': list(clients), 'sources': list(sources)}))
