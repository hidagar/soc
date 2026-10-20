from django.core.management.base import BaseCommand, CommandError

from core.key_rotation import rotate


class Command(BaseCommand):
    help = ('Vuelve a cifrar los campos encrypted_* con la primera clave de cada lista SOC_PORTAL_*_KEY / '
            'SOC_PORTAL_VAULT_KEYS. Sin --apply solo informa. Ejecutar con los servicios parados y una copia previa.')

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true', help='Escribir los valores recifrados')

    def handle(self, *args, apply, **options):
        report = rotate(apply=apply)
        for (table, field, family), rows in sorted(report.items()):
            self.stdout.write(f'{table}.{field}: {rows} filas · {family}')
        pending = sum(rows for (_, _, family), rows in report.items()
                      if family in ('sin descifrar', 'cambiado durante el recifrado'))
        verb = 'Recifrado' if apply else 'Simulación (sin cambios)'
        self.stdout.write(f'{verb}: {sum(report.values())} valores revisados.')
        if pending:
            raise CommandError(f'{pending} valores no se han recifrado. No retires claves anteriores hasta resolverlos.')
        self.stdout.write(self.style.SUCCESS('Todos los valores se descifran con las claves configuradas.'))
