# Reenviador de logs por HTTPS · ib-red empresas

Requisitos: un Linux Debian/Ubuntu en la sede con Python 3, systemd, salida HTTPS 443 a soc.ibred.es y espacio para la cola. No necesita VPN ni una IP pública fija. Usa un paquete y proceso por firewall; no mezcles mensajes de varios clientes/equipos con una sola clave.

1. Copia el paquete al host de la sede por un canal seguro. Contiene una clave privada de acceso al receptor de logs: no lo envíes por correo ni lo publiques.
2. Como administrador local, crea el usuario de servicio y coloca los archivos:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin soc-relay
sudo install -d -m 755 /opt/soc-log-relay
sudo install -m 644 soc_log_relay.py /opt/soc-log-relay/soc_log_relay.py
sudo install -o root -g soc-relay -m 640 soc-log-relay.json /etc/soc-log-relay.json
sudo install -m 644 soc-log-relay.service /etc/systemd/system/soc-log-relay.service
```

3. El receptor local escucha por defecto en `127.0.0.1:5515/UDP`. Si el firewall es otro equipo de la LAN, cambia **solo** `listen_host` en `/etc/soc-log-relay.json` por la IP LAN de este host. Permite el puerto UDP 5515 únicamente desde la IP LAN del firewall. No publiques este puerto en Internet. El SOC no necesita conocer la IP pública del cliente.
4. Activa el servicio:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now soc-log-relay
sudo systemctl status soc-log-relay
```

5. Configura Syslog en el firewall hacia la IP local del reenviador y puerto UDP 5515. Activa las categorías que indique el asistente para UniFi, OPNsense, Zenarmor o Hillstone. No apuntes el syslog UDP directamente a la URL HTTPS.
6. Pulsa «Comprobar en Wazuh» en el portal y genera actividad normal. La aceptación HTTPS confirma que el SOC ha guardado el lote cifrado: la conexión se valida cuando Wazuh interpreta un evento real.

Se conserva una cola SQLite sin caducidad automática mientras no exista confirmación de persistencia, con límite aproximado de 64 MiB de texto. El reenviador solo elimina un lote cuando el SOC confirma su identificador, número de mensajes, huella y almacenamiento durable. Actualiza el script de instalaciones anteriores para aplicar este comportamiento; conserva su configuración y SQLite. El SOC conserva los cuerpos confirmados siete días y los pendientes hasta su resolución. Los lotes nuevos usan transporte v2: el servidor espera el recibo del motor Wazuh privado y verifica las alertas indexadas. Un mensaje procesado sin alerta no acredita amenaza. Los recibos antiguos v1 enviados por UDP siguen sin confirmación y las entregas ambiguas requieren revisión; no convertirlas retroactivamente en confirmadas. Si alcanza el límite descarta los mensajes nuevos y avisa por journal. Límite del SOC: 200 lotes/minuto y 10 MiB/minuto por equipo. Este reenviador agrupa hasta 32 mensajes por lote (máximo teórico de 6.400 eventos/minuto, sujeto al límite de bytes); dimensiona otra solución si tu volumen es mayor. Cada mensaje debe ser UTF-8, de una sola línea y de hasta 8 KiB; los mensajes fuera de ese formato se descartan. No hay garantía de entrega del tramo UDP. Ante una interrupción durante un envío puede existir repetición; no se garantiza entrega exactamente una vez. No desactives la validación HTTPS.

Para revocar una instalación, desactiva el canal en el portal. Para cambiar la clave, rótala en el portal, descarga el paquete nuevo y sustituye la configuración local antes de reiniciar. Borra de forma segura las copias del ZIP tras instalarlo.

Diagnóstico local sin mostrar mensajes ni claves: `sudo -u soc-relay python3 /opt/soc-log-relay/soc_log_relay.py --config /etc/soc-log-relay.json --status`. Muestra cola pendiente, antigüedad, errores de entrega, mensajes inválidos y descartes por saturación. Estos contadores son locales; no acreditan recepción en Wazuh.

## Documentación del proyecto

[Arquitectura de ingesta](../../docs/ingestion.md), [operación](../../docs/operations.md) y [estado del piloto](../../docs/handoff.md). La prueba de servidor/laboratorio no acredita una instalación real en una sede.
