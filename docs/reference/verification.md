# Migraciones y pruebas

Generado desde el código por `python docs/tools/generate_reference.py`. No es telemetría ni una declaración de permisos efectivos.

Los nombres ayudan a navegar; un método presente no significa que se haya ejecutado ni que cubra todos los casos. Los decorators pueden omitir ensayos que exigen Linux/archivo/motor real.

## Módulos de pruebas

| Módulo | Métodos `test_*` declarados |
|---|---:|
| [core/test_access_onboarding.py](../../core/test_access_onboarding.py) | 20 |
| [core/test_action_tracking.py](../../core/test_action_tracking.py) | 8 |
| [core/test_advanced_expansion.py](../../core/test_advanced_expansion.py) | 6 |
| [core/test_asn.py](../../core/test_asn.py) | 5 |
| [core/test_asset_context.py](../../core/test_asset_context.py) | 15 |
| [core/test_audit_presentation.py](../../core/test_audit_presentation.py) | 10 |
| [core/test_connection_guide.py](../../core/test_connection_guide.py) | 6 |
| [core/test_dashboard_sources.py](../../core/test_dashboard_sources.py) | 1 |
| [core/test_database_concurrency.py](../../core/test_database_concurrency.py) | 2 |
| [core/test_database_engine.py](../../core/test_database_engine.py) | 5 |
| [core/test_database_transfer.py](../../core/test_database_transfer.py) | 5 |
| [core/test_device_inventory.py](../../core/test_device_inventory.py) | 13 |
| [core/test_device_mac.py](../../core/test_device_mac.py) | 7 |
| [core/test_durable_operations.py](../../core/test_durable_operations.py) | 21 |
| [core/test_email_auth.py](../../core/test_email_auth.py) | 6 |
| [core/test_event_contract.py](../../core/test_event_contract.py) | 16 |
| [core/test_exposure.py](../../core/test_exposure.py) | 13 |
| [core/test_exposure_context.py](../../core/test_exposure_context.py) | 8 |
| [core/test_exposure_ssh.py](../../core/test_exposure_ssh.py) | 3 |
| [core/test_gcc_connection_status.py](../../core/test_gcc_connection_status.py) | 3 |
| [core/test_gdms_cloud.py](../../core/test_gdms_cloud.py) | 12 |
| [core/test_grandstream_gcc.py](../../core/test_grandstream_gcc.py) | 4 |
| [core/test_hillstone_api.py](../../core/test_hillstone_api.py) | 14 |
| [core/test_hillstone_flow.py](../../core/test_hillstone_flow.py) | 7 |
| [core/test_hillstone_security.py](../../core/test_hillstone_security.py) | 8 |
| [core/test_improvements.py](../../core/test_improvements.py) | 24 |
| [core/test_indexer_tls.py](../../core/test_indexer_tls.py) | 4 |
| [core/test_interface_topology.py](../../core/test_interface_topology.py) | 12 |
| [core/test_investigation.py](../../core/test_investigation.py) | 11 |
| [core/test_login_ip_throttle.py](../../core/test_login_ip_throttle.py) | 5 |
| [core/test_native_pipeline.py](../../core/test_native_pipeline.py) | 1 |
| [core/test_navigation.py](../../core/test_navigation.py) | 3 |
| [core/test_network_coverage.py](../../core/test_network_coverage.py) | 20 |
| [core/test_onboarding.py](../../core/test_onboarding.py) | 16 |
| [core/test_operations.py](../../core/test_operations.py) | 31 |
| [core/test_protection.py](../../core/test_protection.py) | 14 |
| [core/test_public_panel.py](../../core/test_public_panel.py) | 3 |
| [core/test_receiver_transition.py](../../core/test_receiver_transition.py) | 3 |
| [core/test_recovery_coverage.py](../../core/test_recovery_coverage.py) | 11 |
| [core/test_release_and_receiver.py](../../core/test_release_and_receiver.py) | 5 |
| [core/test_report_freshness.py](../../core/test_report_freshness.py) | 3 |
| [core/test_report_sharing.py](../../core/test_report_sharing.py) | 8 |
| [core/test_roadmap_456.py](../../core/test_roadmap_456.py) | 22 |
| [core/test_roadmap_first.py](../../core/test_roadmap_first.py) | 20 |
| [core/test_service_development.py](../../core/test_service_development.py) | 18 |
| [core/test_site_client_context.py](../../core/test_site_client_context.py) | 4 |
| [core/test_site_delete.py](../../core/test_site_delete.py) | 8 |
| [core/test_threat_map.py](../../core/test_threat_map.py) | 10 |
| [core/test_unifi_policy_details.py](../../core/test_unifi_policy_details.py) | 12 |
| [core/test_unifi_zone_scope.py](../../core/test_unifi_zone_scope.py) | 18 |
| [core/test_wazuh_delivery.py](../../core/test_wazuh_delivery.py) | 21 |
| [core/test_wazuh_sso.py](../../core/test_wazuh_sso.py) | 7 |
| [core/test_work_queue.py](../../core/test_work_queue.py) | 8 |
| [core/test_zenarmor_export.py](../../core/test_zenarmor_export.py) | 9 |
| [core/test_zenarmor_onboarding.py](../../core/test_zenarmor_onboarding.py) | 8 |
| [core/test_zenarmor_scope.py](../../core/test_zenarmor_scope.py) | 15 |
| [core/testing_access.py](../../core/testing_access.py) | 0 |
| [core/tests.py](../../core/tests.py) | 51 |

## Migraciones

No editar migraciones aplicadas; ver dependencias/operaciones reales.

- [core/migrations/0001_initial.py](../../core/migrations/0001_initial.py)
- [core/migrations/0002_device_zenarmor_edition_device_zenarmor_version.py](../../core/migrations/0002_device_zenarmor_edition_device_zenarmor_version.py)
- [core/migrations/0003_unificloudconnection.py](../../core/migrations/0003_unificloudconnection.py)
- [core/migrations/0004_opnsenseconnection.py](../../core/migrations/0004_opnsenseconnection.py)
- [core/migrations/0005_device_connection_methods.py](../../core/migrations/0005_device_connection_methods.py)
- [core/migrations/0006_device_connection_permission.py](../../core/migrations/0006_device_connection_permission.py)
- [core/migrations/0007_device_ssh_username.py](../../core/migrations/0007_device_ssh_username.py)
- [core/migrations/0008_ssh_and_export.py](../../core/migrations/0008_ssh_and_export.py)
- [core/migrations/0009_weekly_reports.py](../../core/migrations/0009_weekly_reports.py)
- [core/migrations/0010_report_findings.py](../../core/migrations/0010_report_findings.py)
- [core/migrations/0011_mail_settings.py](../../core/migrations/0011_mail_settings.py)
- [core/migrations/0012_urgent_alerts.py](../../core/migrations/0012_urgent_alerts.py)
- [core/migrations/0013_mailsettings_public_reports_url_and_more.py](../../core/migrations/0013_mailsettings_public_reports_url_and_more.py)
- [core/migrations/0014_firewall_onboarding.py](../../core/migrations/0014_firewall_onboarding.py)
- [core/migrations/0015_zenarmor_onboarding.py](../../core/migrations/0015_zenarmor_onboarding.py)
- [core/migrations/0016_soc_operations.py](../../core/migrations/0016_soc_operations.py)
- [core/migrations/0017_soc_roles.py](../../core/migrations/0017_soc_roles.py)
- [core/migrations/0018_soc_incident_identity.py](../../core/migrations/0018_soc_incident_identity.py)
- [core/migrations/0019_security_geography.py](../../core/migrations/0019_security_geography.py)
- [core/migrations/0020_incident_actions.py](../../core/migrations/0020_incident_actions.py)
- [core/migrations/0021_exposure_review.py](../../core/migrations/0021_exposure_review.py)
- [core/migrations/0022_exposure_history.py](../../core/migrations/0022_exposure_history.py)
- [core/migrations/0023_protection_policy.py](../../core/migrations/0023_protection_policy.py)
- [core/migrations/0024_customer_intelligence_history.py](../../core/migrations/0024_customer_intelligence_history.py)
- [core/migrations/0025_exposure_alias_interfaces.py](../../core/migrations/0025_exposure_alias_interfaces.py)
- [core/migrations/0026_customer_map.py](../../core/migrations/0026_customer_map.py)
- [core/migrations/0027_operational_improvements.py](../../core/migrations/0027_operational_improvements.py)
- [core/migrations/0028_configuration_review.py](../../core/migrations/0028_configuration_review.py)
- [core/migrations/0029_network_coverage.py](../../core/migrations/0029_network_coverage.py)
- [core/migrations/0030_hillstone_connection.py](../../core/migrations/0030_hillstone_connection.py)
- [core/migrations/0031_hillstone_validation_engine.py](../../core/migrations/0031_hillstone_validation_engine.py)
- [core/migrations/0032_attribution_catalog_and_flow.py](../../core/migrations/0032_attribution_catalog_and_flow.py)
- [core/migrations/0033_zenarmor_export_request.py](../../core/migrations/0033_zenarmor_export_request.py)
- [core/migrations/0034_vm_recovery_method.py](../../core/migrations/0034_vm_recovery_method.py)
- [core/migrations/0035_delivery_coverage_customer_dashboards.py](../../core/migrations/0035_delivery_coverage_customer_dashboards.py)
- [core/migrations/0036_vpn_access_event.py](../../core/migrations/0036_vpn_access_event.py)
- [core/migrations/0037_user_invitations_secure_log_channels.py](../../core/migrations/0037_user_invitations_secure_log_channels.py)
- [core/migrations/0038_grandstream_gcc.py](../../core/migrations/0038_grandstream_gcc.py)
- [core/migrations/0039_unique_login_email.py](../../core/migrations/0039_unique_login_email.py)
- [core/migrations/0040_source_ownership_urgent_checkpoint.py](../../core/migrations/0040_source_ownership_urgent_checkpoint.py)
- [core/migrations/0041_gdms_cloud_connection.py](../../core/migrations/0041_gdms_cloud_connection.py)
- [core/migrations/0042_device_mac_identity.py](../../core/migrations/0042_device_mac_identity.py)
- [core/migrations/0043_automatic_device_inventory.py](../../core/migrations/0043_automatic_device_inventory.py)
- [core/migrations/0044_event_interpretation.py](../../core/migrations/0044_event_interpretation.py)
- [core/migrations/0045_durable_https_inbox.py](../../core/migrations/0045_durable_https_inbox.py)
- [core/migrations/0046_acknowledged_wazuh_delivery.py](../../core/migrations/0046_acknowledged_wazuh_delivery.py)
- [core/migrations/0047_export_receiver_defaults.py](../../core/migrations/0047_export_receiver_defaults.py)
