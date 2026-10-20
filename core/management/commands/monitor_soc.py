import os
from django.core.management.base import BaseCommand,CommandError
from django.utils import timezone
from core.models import WorkerState
from core.background_jobs import dispatch

class Command(BaseCommand):
    help='Programa trabajos independientes; el éxito indica programación, no recepción de eventos.'
    def add_arguments(self,parser):parser.add_argument('--no-notify',action='store_true')
    def handle(self,*args,**options):
        if os.geteuid()!=0:raise CommandError('Ejecutar mediante el servicio root de monitorización.')
        import fcntl
        with open('/run/soc-monitor.lock','a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return
            state,_=WorkerState.objects.get_or_create(name='operations')
            state.last_run_at=timezone.now();state.save(update_fields=['last_run_at'])
            try:count=dispatch(options['no_notify'])
            except Exception:
                state.error='No se pudieron programar todos los trabajos. Revisar systemd.';state.save()
                raise CommandError(state.error)
            state.last_success_at=timezone.now();state.error='';state.details={'mode':'dispatcher','dispatched':count};state.save()
            self.stdout.write(f'Trabajos programados: {count}. Consultar cada trabajo para conocer su resultado.')
