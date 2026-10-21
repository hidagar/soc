# Rutas y handlers

Generado desde el código por `python docs/tools/generate_reference.py`. No es telemetría ni una declaración de permisos efectivos.

Rutas extraídas de los URLconf, no una API REST pública estable. Métodos, autenticación, MFA, ámbito, permisos y respuestas se definen en middleware/decoradores/handler. Los parámetros de URL son identificadores, no credenciales; los tokens públicos sí deben custodiarse.

## socportal/urls.py

| Ruta | Nombre | Handler |
|---|---|---|
| `admin/` | `` | `admin.site.urls` |
| `login/` | `login` | `auth_views.LoginView.as_view(template_name='login.html', authentication_form=EmailAuthenticationForm)` |
| `logout/` | `logout` | `auth_views.LogoutView.as_view()` |
| `/` | `` | `include('core.urls')` |
## core/urls.py

| Ruta | Nombre | Handler |
|---|---|---|
| `ingest/<uuid:channel_id>/` | `secure_log_ingest` | `secure_logs.ingest` |
| `devices/<int:pk>/secure-logs/` | `secure_log_setup` | `secure_logs.setup` |
| `activate/<int:uid>/<str:token>/` | `accept_invitation` | `invitations.activate` |
| `operations/investigation/` | `security_explore` | `investigation.explore` |
| `operations/investigation/ip/` | `ip_investigation` | `investigation.ip_detail` |
| `operations/vpn-security/` | `vpn_security` | `vpn_security.dashboard` |
| `devices/<int:pk>/advanced/` | `advanced_coverage` | `advanced_views.advanced` |
| `security/wazuh/check/` | `wazuh_sso_check` | `wazuh_sso.check` |
| `security/wazuh/enter/` | `wazuh_sso_enter` | `wazuh_sso.enter` |
| `operations/coverage/` | `network_coverage` | `network_views.coverage` |
| `devices/<int:pk>/coverage/` | `device_coverage` | `network_views.coverage` |
| `operations/networks/<int:pk>/requirements/` | `network_requirements` | `network_views.requirements` |
| `reports/delivery-events/` | `delivery_webhook` | `delivery.delivery_webhook` |
| `operations/delivery/` | `delivery_status` | `delivery.delivery_status` |
| `operations/delivery/settings/` | `delivery_settings` | `delivery.delivery_settings` |
| `alerts/<int:pk>/acknowledge/` | `acknowledge_alert` | `suite.acknowledge` |
| `incidents/<int:pk>/runbook/` | `runbook` | `suite.runbook` |
| `incidents/<int:incident_pk>/tasks/new/` | `customer_task_new` | `suite.task_edit` |
| `operations/tasks/<int:pk>/` | `customer_task_edit` | `suite.task_edit` |
| `cliente/tareas/<int:pk>/responder/` | `customer_task_reply` | `suite.customer_task_reply` |
| `devices/<int:pk>/validations/` | `validations` | `suite.validations` |
| `devices/<int:pk>/archives/` | `configuration_archives` | `suite.archives` |
| `operations/work/` | `work_queue` | `work_queue.work_queue` |
| `incidents/<int:pk>/claim/` | `claim_incident` | `work_queue.claim_incident` |
| `cliente/mapa/` | `customer_map` | `service.customer_map` |
| `cliente/mapa/data/` | `customer_map_data` | `service.customer_map_data` |
| `operations/exposure/device/<int:pk>/interfaces/` | `exposure_interfaces` | `exposure_views.exposure_interfaces` |
| `cliente/` | `customer_home` | `service.customer_home` |
| `cliente/informes/<int:pk>/` | `customer_weekly` | `service.customer_weekly` |
| `cliente/informes/<int:pk>/pdf/` | `customer_weekly_pdf` | `service.customer_weekly_pdf` |
| `clients/<int:client_pk>/publish/` | `customer_publish` | `service.publish` |
| `clients/<int:client_pk>/monthly/` | `monthly_summary` | `service.monthly` |
| `devices/<int:pk>/history/` | `device_history` | `service.device_history` |
| `operations/intelligence/` | `intelligence` | `service.intelligence` |
| `operations/crowdsec/` | `crowdsec_overview` | `reputation_views.overview` |
| `operations/protection/` | `protection_list` | `protection_views.protection_list` |
| `operations/protection/<int:pk>/` | `protection_device` | `protection_views.protection_device` |
| `operations/exposure/` | `exposure_list` | `exposure_views.exposure_list` |
| `devices/<int:pk>/unifi-policies/` | `unifi_policies` | `exposure_views.unifi_policies` |
| `operations/exposure/<int:pk>/` | `exposure_detail` | `exposure_views.exposure_detail` |
| `operations/exposure/device/<int:pk>/recheck/` | `exposure_recheck` | `exposure_views.exposure_recheck` |
| `operations/actions/` | `action_list` | `action_tracking.action_list` |
| `incidents/<int:incident_pk>/actions/new/` | `action_new` | `action_tracking.action_form` |
| `operations/actions/<int:pk>/edit/` | `action_edit` | `action_tracking.action_form` |
| `clients/<int:client_pk>/trends/` | `client_trends` | `trends.client_trends` |
| `operations/map/` | `threat_map` | `geography.threat_map` |
| `operations/map/data/` | `threat_map_data` | `geography.threat_map_data` |
| `help/operations/` | `operations_help` | `login_required(TemplateView.as_view(template_name='operations_help.html'))` |
| `operations/changes/` | `changes` | `controls.changes` |
| `operations/changes/<int:pk>/` | `change_detail` | `controls.change_detail` |
| `operations/vpn/` | `vpn_sites` | `controls.vpn_sites` |
| `operations/vpn/<int:pk>/config/` | `vpn_download` | `controls.vpn_download` |
| `operations/recovery/` | `recovery` | `controls.recovery` |
| `security/staff/<int:pk>/mfa-reset/` | `mfa_reset` | `security.mfa_reset` |
| `operations/health/` | `health_list` | `ops.health_list` |
| `operations/health/<int:pk>/` | `health_device` | `ops.health_device` |
| `operations/inventory/` | `inventory` | `ops.inventory` |
| `operations/assets/<int:pk>/` | `asset_edit` | `ops.asset_edit` |
| `incidents/<int:pk>/note/` | `incident_note` | `ops.incident_note` |
| `security/staff/` | `staff` | `ops.staff` |
| `security/staff/<int:pk>/` | `staff_edit` | `ops.staff` |
| `security/audit/` | `audit_log` | `ops.audit_log` |
| `security/mfa/setup/` | `mfa_setup` | `security.mfa_setup` |
| `security/mfa/verify/` | `mfa_challenge` | `security.mfa_challenge` |
| `reports/health/` | `report_health` | `report_sharing.report_health` |
| `reports/<str:token>/pdf/` | `customer_report_pdf` | `report_sharing.customer_report_pdf` |
| `reports/<str:token>/` | `customer_report` | `report_sharing.customer_report` |
| `report-links/<int:report_pk>/` | `manage_report_link` | `report_sharing.manage_report_link` |
| `report-versions/<int:report_pk>/rectify/` | `rectify_report` | `report_versions.rectify` |
| `mail/verify-reports/` | `verify_public_reports` | `report_sharing.verify_public_reports` |
| `gestion/` | `dashboard` | `views.dashboard` |
| `/` | `dashboard_legacy` | `views.dashboard` |
| `connections/` | `api_connections` | `views.api_connections` |
| `help/connect-firewall/` | `connection_guide` | `connection_guide` |
| `mail/` | `mail_settings` | `views.mail_settings` |
| `alerts/` | `urgent_alert_list` | `views.urgent_alert_list` |
| `clients/` | `client_list` | `views.client_list` |
| `clients/new/` | `client_new` | `views.client_form` |
| `clients/<int:pk>/` | `client_detail` | `views.client_detail` |
| `clients/<int:pk>/edit/` | `client_edit` | `views.client_form` |
| `clients/<int:client_pk>/report/` | `weekly_report` | `views.weekly_report` |
| `sites/new/` | `site_new` | `views.site_form` |
| `sites/<int:site_pk>/add-device/` | `onboarding_add_device` | `onboarding.add_device` |
| `devices/<int:pk>/connect/` | `device_onboarding` | `onboarding.device_wizard` |
| `devices/<int:pk>/connect/status/` | `onboarding_status` | `onboarding.status` |
| `sites/<int:pk>/` | `site_detail` | `views.site_detail` |
| `sites/<int:pk>/edit/` | `site_edit` | `views.site_form` |
| `sites/<int:pk>/delete/` | `site_delete` | `views.site_delete` |
| `devices/new/` | `device_new` | `views.device_form` |
| `devices/<int:pk>/` | `device_detail` | `views.device_detail` |
| `devices/<int:pk>/edit/` | `device_edit` | `views.device_form` |
| `devices/<int:pk>/export-destination/` | `export_destination` | `views.export_destination` |
| `devices/<int:pk>/unifi-cloud/` | `unifi_cloud` | `views.unifi_cloud` |
| `devices/<int:pk>/opnsense-api/` | `opnsense_api` | `views.opnsense_api` |
| `devices/<int:pk>/hillstone-api/` | `hillstone_api` | `hillstone_views.hillstone_api` |
| `devices/<int:pk>/gdms-cloud/` | `gdms_cloud` | `gdms_views.gdms_cloud` |
| `devices/<int:pk>/inventory/refresh/` | `refresh_device_inventory` | `inventory_views.refresh_inventory` |
| `devices/<int:pk>/ssh/` | `ssh_connection` | `views.ssh_connection` |
| `incidents/` | `incident_list` | `views.incident_list` |
| `incidents/new/` | `incident_new` | `views.incident_form` |
| `incidents/<int:pk>/` | `incident_detail` | `views.incident_detail` |
| `incidents/<int:pk>/edit/` | `incident_edit` | `views.incident_form` |
| `options/` | `related_options` | `views.related_options` |
