import os
from django.core.management.base import BaseCommand,CommandError
from django.utils import timezone
from core.models import BackupRun,WorkerState

class Command(BaseCommand):
    help='Procesa VPN, cambios aprobados y copias cifradas mediante servicios protegidos.'
    def add_arguments(self,parser):
        parser.add_argument('job',choices=['vpn','changes','backup'])
        parser.add_argument('--daily',action='store_true')
    def handle(self,*args,**options):
        if os.geteuid()!=0: raise CommandError('Ejecutar mediante el servicio protegido de operaciones.')
        import fcntl
        from core.interruption import JobInterrupted,stop_on_sigterm
        stop_on_sigterm()  # la copia limpia índices de prueba y temporales antes de salir
        job=options['job']
        with open('/run/soc-'+job+'.lock','a') as lock:
            try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: return
            state,_=WorkerState.objects.get_or_create(name=job)
            state.last_run_at=timezone.now(); state.save()
            try:
                if job=='vpn':
                    from core.vpn import synchronize
                    synchronize()
                elif job=='changes':
                    from core.change_control import process_queue
                    process_queue()
                else:
                    from core.recovery import make_backup
                    # A crashed backup never retains a permanent running lock.
                    from datetime import timedelta
                    BackupRun.objects.filter(status='running',created_at__lt=timezone.now()-timedelta(hours=2)).update(status='failed',error='Proceso interrumpido; repetir la copia.')
                    if options['daily']:
                        from core.recovery import queue_daily_backup
                        queue_daily_backup()
                    run=BackupRun.objects.filter(status='queued').order_by('pk').first()
                    if run: make_backup(run)
                state.last_success_at=timezone.now(); state.error=''
            except (Exception,JobInterrupted):
                state.error='La tarea no terminó. Revisar los registros protegidos.'; state.save()
                raise CommandError(state.error) from None
            state.save()
            self.stdout.write(job+': comprobación terminada.')
