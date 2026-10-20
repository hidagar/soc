from django.core.management.base import BaseCommand, CommandError

from core.database_transfer import TransferError, open_source, preflight, transfer


class Command(BaseCommand):
    help = ('Traslada la base SQLite del portal a PostgreSQL (conexión default) y verifica filas y huellas '
            'por tabla. Usar una copia consistente del origen, nunca la base en uso.')

    def add_arguments(self, parser):
        parser.add_argument('--source', required=True, help='Copia SQLite de origen (se abre en solo lectura)')
        parser.add_argument('--check', action='store_true', help='Solo comprobación previa; no escribe nada')
        parser.add_argument('--replace-target', action='store_true',
                            help='Confirma que se vacían las tablas del destino PostgreSQL antes de copiar')

    def handle(self, *args, source, check, replace_target, **options):
        try:
            if check:
                issues = preflight(open_source(source))
                for (table, field, problem), rows in sorted(issues.items()):
                    self.stdout.write(f'{table}.{field}: {problem} ({rows} filas)')
                if issues:
                    raise CommandError(f'{sum(issues.values())} valores que PostgreSQL rechazaría.')
                self.stdout.write(self.style.SUCCESS('Comprobación previa correcta: no se ha escrito nada.'))
                return
            if not replace_target:
                raise CommandError('Indica --replace-target: el traslado vacía las tablas del destino PostgreSQL.')
            report = transfer(source, progress=lambda table: self.stdout.write(f'Copiado {table}', ending='\n'))
        except TransferError as exc:
            raise CommandError(str(exc)) from exc
        for table, rows in report:
            self.stdout.write(f'{table}: {rows} filas verificadas')
        self.stdout.write(self.style.SUCCESS(f'Traslado verificado: {len(report)} tablas, '
                                             f'{sum(rows for _, rows in report)} filas.'))
