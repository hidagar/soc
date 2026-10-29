"""Configuración de gunicorn del portal: soc-portal.service arranca `gunicorn -c` con este archivo.

Va con el código, así que deploy/update.sh la actualiza en cada despliegue. Las instalaciones
anteriores, que llevan las opciones en la propia unidad, la adoptan con deploy/configurar_registros.sh.
"""
bind = '127.0.0.1:8000'
# Dos procesos con 8 hilos cada uno (gthread), la misma memoria que antes. Con procesos de un solo hilo,
# dos acciones lentas a la vez (UniFi, CrowdSec y OPNsense responden en hasta 25 s) dejaban sin atender
# la ingesta HTTPS y las descargas de las listas de bloqueo, que llegan a este mismo servicio. Con hilos,
# una petición larga tampoco hace que el proceso supere `timeout` y lo maten a mitad de una operación:
# termina aunque Nginx corte la respuesta al navegador a los 30 s.
workers = 2
threads = 8
worker_class = 'gthread'
timeout = 60
graceful_timeout = 30
# Renovar los procesos de vez en cuando limita el crecimiento de memoria.
max_requests = 2000
max_requests_jitter = 200
# Sin registro de accesos: escribía en el diario la URL completa de cada petición, con los enlaces de
# informes, las listas de bloqueo y las invitaciones. Nginx guarda las peticiones con esos secretos
# ocultos (deploy/nginx/soc-log-redaction.conf).
accesslog = None
errorlog = '-'
