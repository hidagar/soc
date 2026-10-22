# Variables de entorno: lectores reales

Generado desde el código por `python docs/tools/generate_reference.py`. No es telemetría ni una declaración de permisos efectivos.

Valores, formatos y secretos: [configuración](../configuration.md). Se enumeran lecturas literales, no toda configuración en archivos, base de datos, systemd o rutas fijas. No se imprimen valores del entorno.

| Variable | Lectores |
|---|---|
| `SOC_ASN_DATABASE` | [core/asn.py](../../core/asn.py) |
| `SOC_GEOIP_DATABASE` | [core/threat_map.py](../../core/threat_map.py), [core/vpn_security.py](../../core/vpn_security.py) |
| `SOC_INDEXER_CA` | [core/reporting.py](../../core/reporting.py) |
| `SOC_INDEXER_READER_FILE` | [core/reporting.py](../../core/reporting.py) |
| `SOC_NATIVE_ENGINE_GATE` | [core/test_native_pipeline.py](../../core/test_native_pipeline.py) |
| `SOC_PORTAL_ALLOWED_HOSTS` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_CROWDSEC_CTI_PER_RUN` | [core/reputation.py](../../core/reputation.py) |
| `SOC_PORTAL_CROWDSEC_DAILY_LIMIT` | [core/reputation.py](../../core/reputation.py) |
| `SOC_PORTAL_CROWDSEC_ENGINE_ID` | [core/crowdsec_catalog.py](../../core/crowdsec_catalog.py) |
| `SOC_PORTAL_CROWDSEC_LAPI_URL` | [core/reputation.py](../../core/reputation.py) |
| `SOC_PORTAL_CROWDSEC_MONTHLY_LIMIT` | [core/reputation.py](../../core/reputation.py) |
| `SOC_PORTAL_CROWDSEC_SERVICE_KEY` | [core/crowdsec_catalog.py](../../core/crowdsec_catalog.py) |
| `SOC_PORTAL_CSRF_ORIGINS` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DB_ENGINE` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DB_HOST` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DB_NAME` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DB_PASSWORD` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DB_PORT` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DB_SSLMODE` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DB_TEST_NAME` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DB_USER` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_DEBUG` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_EXTRA_SYSLOG_IPS` | [core/provisioning.py](../../core/provisioning.py) |
| `SOC_PORTAL_LOGIN_IP_LIMIT` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_MAIL_KEY` | [core/mail_delivery.py](../../core/mail_delivery.py) |
| `SOC_PORTAL_MFA_REQUIRED` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_OPNSENSE_KEY` | [core/opnsense_api.py](../../core/opnsense_api.py) |
| `SOC_PORTAL_PUBLIC_SYSLOG_IP` | [core/provisioning.py](../../core/provisioning.py) |
| `SOC_PORTAL_RECEIVER_IP` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_RECEIVER_PORT` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_SECRET_KEY` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_SQLITE_PATH` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_SSH_KEY` | [core/ssh_connection.py](../../core/ssh_connection.py) |
| `SOC_PORTAL_TRUSTED_PROXIES` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PORTAL_UNIFI_KEY` | [core/unifi_cloud.py](../../core/unifi_cloud.py) |
| `SOC_PORTAL_VAULT_KEYS` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_PUBLIC_ORIGIN` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_REPORT_EMAIL_BACKEND` | [socportal/settings.py](../../socportal/settings.py) |
| `SOC_WAZUH_PROXY_KEY` | [socportal/settings.py](../../socportal/settings.py) |
