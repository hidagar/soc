import os
from django.core.management.base import BaseCommand,CommandError
from core.models import SecurityEvidence,Client

class Command(BaseCommand):
    help='Reencola la proyección derivada Wazuh sin borrar evidencias ni índices originales.'
    def add_arguments(self,parser):parser.add_argument('--client',type=int)
    def handle(self,*args,**options):
        if not hasattr(os,'geteuid') or os.geteuid()!=0:raise CommandError('Ejecutar desde el servicio protegido o consola de recuperación con permisos root.')
        rows=SecurityEvidence.objects.exclude(client_scope_id=None)
        if options.get('client'):
            if not Client.objects.filter(pk=options['client']).exists():raise CommandError('Empresa no encontrada.')
            rows=rows.filter(client_scope_id=options['client'])
        count=rows.update(wazuh_published_at=None)
        self.stdout.write(f'{count} evidencias reencoladas. El monitor publicará por lotes las que estén dentro de la retención y tengan un ámbito verificado.')
