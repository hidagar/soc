"""Configuración de gunicorn del portal: soc-portal.service arranca `gunicorn -c` con este archivo.

Va con el código, así que deploy/update.sh la actualiza en cada despliegue. Las instalaciones
anteriores, que llevan las opciones en la propia unidad, la adoptan con deploy/configurar_registros.sh.
"""
bind = '127.0.0.1:8000'
workers = 2
# Sin registro de accesos: escribía en el diario la URL completa de cada petición, con los enlaces de
# informes, las listas de bloqueo y las invitaciones. Nginx guarda las peticiones con esos secretos
# ocultos (deploy/nginx/soc-log-redaction.conf).
accesslog = None
errorlog = '-'
