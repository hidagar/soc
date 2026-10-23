import os
from django.core.management.base import BaseCommand,CommandError
from core.background_jobs import JOBS,run_job
from core.interruption import JobInterrupted,stop_on_sigterm

class Command(BaseCommand):
    help='Ejecuta un trabajo SOC con bloqueo exclusivo por trabajo.'
    def add_arguments(self,parser):parser.add_argument('job',choices=sorted(JOBS))
    def handle(self,*args,**options):
        if os.geteuid()!=0:raise CommandError('Ejecutar mediante el servicio root de monitorización.')
        import fcntl
        name=options['job']
        stop_on_sigterm()
        with open('/run/soc-job-'+name+'.lock','a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return
            try:run_job(name)
            except JobInterrupted:raise CommandError('Trabajo interrumpido por systemd; se reanuda en la próxima ejecución.') from None
            except Exception:raise CommandError('El trabajo no terminó. Revisar su estado en el panel.') from None
        self.stdout.write('Trabajo completado: '+name)
