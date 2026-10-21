# Mapa de módulos

Generado desde el código por `python docs/tools/generate_reference.py`. No es telemetría ni una declaración de permisos efectivos.

La descripción procede del docstring cuando existe. Los nombres de símbolos ayudan a localizar código; leer el servicio y sus llamadas antes de atribuirle capacidades o ejecutar operaciones.

| Módulo | Descripción / símbolos públicos de entrada |
|---|---|
| [core/access_models.py](../../core/access_models.py) | `UserInvitation`, `SecureLogChannel`, `SecureLogReceipt`, `SecureLogMessage` |
| [core/action_tracking.py](../../core/action_tracking.py) | `ActionForm`, `action_list`, `action_form` |
| [core/admin.py](../../core/admin.py) | `ClientAdmin`, `SiteAdmin`, `DeviceAdmin`, `IncidentAdmin`, `WeeklyReportAdmin` |
| [core/advanced_coverage.py](../../core/advanced_coverage.py) | Readonly capabilities, with complete paginated reads and explicit gaps. — `collect_unifi`, `snapshot` |
| [core/advanced_views.py](../../core/advanced_views.py) | `revision`, `ReviewForm`, `advanced` |
| [core/apps.py](../../core/apps.py) | `CoreConfig` |
| [core/asn.py](../../core/asn.py) | Local ASN lookups. Only the root worker downloads the public monthly dataset. — `database_path`, `values`, `database_stamp`, `lookup`, `update_database` |
| [core/asset_context.py](../../core/asset_context.py) | Current configuration context, never proof of historical NAT or infection. — `address`, `port`, `flow_projection`, `digest`, `interface_projection`, `xml_flag`, `network_specs`, `port_specs`, `endpoint`, `configuration_projection`, `collect`, `refresh`, `refresh_due`, `contains`, … (ver archivo) |
| [core/asset_identity.py](../../core/asset_identity.py) | Bounded discovery and event-time identity; IP ownership is not permanent. — `identity_snapshot`, `update_identity`, `discover_dhcp` |
| [core/audit_presentation.py](../../core/audit_presentation.py) | Readable audit projection. Signed records are never rewritten. — `object_labels`, `detail_lines`, `present` |
| [core/background_jobs.py](../../core/background_jobs.py) | Whitelisted jobs, each executed in a separate time-limited systemd process. — `reconcile_sources`, `execute`, `run_job`, `dispatch`, `check_health` |
| [core/blocklist.py](../../core/blocklist.py) | Listas de bloqueo del SOC para los firewalls de cada cliente (hoja de ruta 7A/C2, fase 1). — `parse_allowlist`, `qualifying`, `activity`, `build`, `observation`, `refresh_feeds`, `rotate_token`, `feed_url`, `serve`, `alias_name`, `plan_preview`, `overview`, `detail` |
| [core/change_control.py](../../core/change_control.py) | Versioned review plans. Remote changes are disabled drafts until explicit approval. — `preview`, `api`, `snapshot`, `digest`, `completed`, `stage_ids`, `stage_zenarmor`, `stage_blocklist_alias`, `stage`, `rollback`, `enable`, `process_queue` |
| [core/configuration_archives.py](../../core/configuration_archives.py) | Root-only encrypted OPNsense backups and a redacted change summary. — `fetch_configuration`, `summarize_xml`, `archive_device`, `refresh_archives` |
| [core/connection_help.py](../../core/connection_help.py) | Operator guidance using the same destinations as actual provisioning. — `connection_guide` |
| [core/context_processors.py](../../core/context_processors.py) | `connection_permissions` |
| [core/control_views.py](../../core/control_views.py) | `global_permission`, `TemplateForm`, `changes`, `change_detail`, `vpn_sites`, `vpn_download`, `RecoveryForm`, `recovery` |
| [core/crowdsec_catalog.py](../../core/crowdsec_catalog.py) | Catálogo de listas de CrowdSec y suscripción guiada por los ataques reales (Service API). — `ServiceError`, `service_key`, `daily_downloads`, `auto_subscribe_limit`, `call`, `engine_id`, `refresh_catalog`, `attackers`, `matches`, `evaluate`, `recommended`, `process_actions`, `auto_subscribe`, `refresh`, … (ver archivo) |
| [core/customer_portal.py](../../core/customer_portal.py) | Portal del cliente: firewalls y detecciones con proyección explícita (invariante 3). — `wazuh_ready`, `portal_client`, `detection_row`, `firewall_rows`, `detection_summary`, `firewalls`, `detections` |
| [core/database_transfer.py](../../core/database_transfer.py) | Traslado verificado de la base del portal de SQLite a PostgreSQL (bloque 4, paso 4). — `TransferError`, `close_source`, `open_source`, `transfer_models`, `applied_migrations`, `check_target`, `preflight`, `field_problem`, `preserved_timestamps`, `normalized`, `fingerprint`, `copy_rows`, `transfer` |
| [core/delivery_provider.py](../../core/delivery_provider.py) | Readonly, bounded diagnosis of this service's SendGrid webhook. — `fingerprint`, `diagnose` |
| [core/delivery_tracking.py](../../core/delivery_tracking.py) | Signed provider events; primary recipients only, immutable dispatch correlation. — `verification_key`, `delivery_webhook`, `DeliveryForm`, `delivery_settings`, `delivery_status`, `escalate_unacknowledged` |
| [core/device_identity.py](../../core/device_identity.py) | Canonical equipment MAC identifiers; transport IP is a separate identity. — `normalize_mac`, `MacFormField`, `MacAddressField` |
| [core/device_inventory.py](../../core/device_inventory.py) | Read-only, allowlisted device facts. Unknown values never erase known facts. — `InventoryError`, `clean`, `provider`, `signature`, `facts`, `opnsense_details`, `ssh_details`, `collect`, `refresh`, `queue`, `refresh_due` |
| [core/email_auth.py](../../core/email_auth.py) | Email login, with two explicitly retained pre-existing operator accounts. — `EmailBackend`, `EmailAuthenticationForm`, `EmailAdminAuthenticationForm` |
| [core/event_contract.py](../../core/event_contract.py) | Versioned action and risk vocabulary for indexed and locally stored events. — `normalize_action`, `family`, `metadata`, `recommendation`, `snapshot`, `selectors`, `security_filter`, `action_filter` |
| [core/evidence_repair.py](../../core/evidence_repair.py) | Reinterpret an existing physical Wazuh alert without replacing its identity. — `repair_hillstone` |
| [core/exposure.py](../../core/exposure.py) | Configuration review via bounded GET queries; never asserts reachability from rule presence. — `text`, `boolean`, `active`, `any_network`, `wan`, `port_risk`, `normalized`, `assess`, `opnsense_rows`, `collect`, `save_result`, `refresh_due` |
| [core/exposure_context.py](../../core/exposure_context.py) | Bounded static alias expansion. No DNS, URL downloads or secret persistence. — `choices`, `alias_catalog`, `expand`, `enrich`, `interface_catalog` |
| [core/exposure_ssh.py](../../core/exposure_ssh.py) | Fixed read-only OPNsense SSH reader; emits only whitelisted legacy settings. — `read_legacy` |
| [core/exposure_views.py](../../core/exposure_views.py) | `ReviewForm`, `exposure_list`, `exposure_recheck`, `exposure_interfaces`, `exposure_detail`, `json_evidence`, `unifi_policies` |
| [core/findings.py](../../core/findings.py) | Turn indexed firewall alerts into evidence-backed customer findings. — `inventories_for_sources`, `build_findings` |
| [core/forms.py](../../core/forms.py) | `StyledModelForm`, `ClientForm`, `MailSettingsForm`, `SiteForm`, `SiteEditForm`, `DeviceForm`, `SiteDeviceForm`, `IncidentForm` |
| [core/gdms_api.py](../../core/gdms_api.py) | GDMS Networking OAuth probe. Fixed vendor hosts, no configuration writes. — `GdmsError`, `NoRedirect`, `encrypt`, `decrypt`, `credential`, `access_token`, `check_connection`, `read_inventory`, `discover_device` |
| [core/gdms_views.py](../../core/gdms_views.py) | `ConnectionForm`, `gdms_cloud` |
| [core/hillstone_api.py](../../core/hillstone_api.py) | StoneOS REST login and bounded inventory discovery; no configuration writes. — `HillstoneApiError`, `NoRedirect`, `validate_url`, `validate_ca`, `encrypt`, `decrypt`, `username`, `inventory`, `check_connection` |
| [core/hillstone_events.py](../../core/hillstone_events.py) | Threat@FLOW layout contrasted with actual StoneOS logs (19 October 2026). — `action`, `flow`, `legacy_action_regexp` |
| [core/hillstone_views.py](../../core/hillstone_views.py) | `ConnectionForm`, `hillstone_api` |
| [core/improvement_models.py](../../core/improvement_models.py) | `RunbookStep`, `ProtectionValidation`, `ZenarmorExportRequest`, `CustomerTask`, `CustomerTaskEntry`, `DeliverySettings`, `AdvancedReview`, `MailDispatch`, `MailEvent`, `ConfigurationArchive`, `ReportVersion`, `IpReputation`, `BlocklistFeed`, `CrowdsecBlocklist` |
| [core/incident_episodes.py](../../core/incident_episodes.py) | `attach_episode` |
| [core/indexer_admin.py](../../core/indexer_admin.py) | Privileged provisioning/recovery only. Reporting uses a separate reader. — `admin_request` |
| [core/indexer_results.py](../../core/indexer_results.py) | Reject partial searches before changing reports or durable cursors. — `complete`, `count`, `total`, `hits` |
| [core/indexer_tls.py](../../core/indexer_tls.py) | Validate the installed legacy Wazuh PKI on Python 3.13+. — `context` |
| [core/interface_topology.py](../../core/interface_topology.py) | Bounded OPNsense topology projection. Relationships do not imply inspection. — `identity`, `catalogue`, `project`, `collect`, `observed`, `current`, `snapshot` |
| [core/inventory_views.py](../../core/inventory_views.py) | `refresh_inventory` |
| [core/investigation.py](../../core/investigation.py) | Bounded investigation of normalized evidence; no external IP lookups. — `selection`, `evidence_queryset`, `ip_url`, `summarize`, `explore`, `ip_detail`, `customer_security_summary` |
| [core/invitations.py](../../core/invitations.py) | One-use welcome links; administrators never choose the user's password. — `origin`, `queue`, `send_pending`, `eligible`, `activate`, `activation_response` |
| [core/key_rotation.py](../../core/key_rotation.py) | Recifrado de los campos encrypted_* con la clave principal de su familia (bloque 8). — `families`, `encrypted_fields`, `identify`, `rotate` |
| [core/keyring.py](../../core/keyring.py) | Claves Fernet con rotación: una lista «nueva,anterior» cifra con la primera y descifra con cualquiera. — `keys_from`, `multifernet` |
| [core/log_delivery.py](../../core/log_delivery.py) | Durable inbox summaries and retained v1 UDP forwarding/recovery. — `queue_summary`, `recover_interrupted`, `retry_reviewed`, `forward_batch`, `deliver_due`, `cleanup` |
| [core/mail_delivery.py](../../core/mail_delivery.py) | Encrypted SendGrid Web API configuration for customer mail. — `MailConfigurationError`, `MailDeliveryError`, `encrypt_sendgrid_key`, `decrypt_sendgrid_key`, `send_via_sendgrid`, `send_test_email`, `send_customer_email`, `send_report_email` |
| [core/models.py](../../core/models.py) | `Client`, `WeeklyReport`, `MailSettings`, `ReportShare`, `UrgentMonitorCursor`, `SourceOwnership`, `UrgentAlert`, `Site`, `Device`, `UnifiCloudConnection`, `OpnsenseConnection`, `HillstoneConnection`, `GdmsConnection`, `SshConnection`, … (ver archivo) |
| [core/navigation.py](../../core/navigation.py) | Menú lateral del portal agrupado por áreas de trabajo. — `build_navigation` |
| [core/network_coverage.py](../../core/network_coverage.py) | Bounded readonly discovery and network-specific proof, without inferring blanket protection. — `literal`, `cidrs`, `opnsense_networks`, `unifi_networks`, `save_discovery`, `discover_networks`, `current`, `fingerprint`, `matches_ip`, `uniquely_contains`, `snapshot` |
| [core/network_models.py](../../core/network_models.py) | `NetworkCheck`, `NetworkCoverage` |
| [core/network_views.py](../../core/network_views.py) | `NetworkForm`, `coverage`, `requirements` |
| [core/onboarding.py](../../core/onboarding.py) | Small, persistent wizard. Credentials use the existing encrypted connection forms. — `EquipmentForm`, `MethodForm`, `source_conflict`, `ExportForm`, `new_site`, `add_device`, `device_wizard`, `status` |
| [core/onboarding_verification.py](../../core/onboarding_verification.py) | Read actual Wazuh output as root; expose only receipt metadata to the portal. — `confirm_onboarding_events`, `verify_pending_onboardings` |
| [core/operations.py](../../core/operations.py) | Vendor-neutral evidence and operational health. Never configure remote devices. — `clean`, `ip`, `private`, `normalize`, `source_map`, `recommendation`, `ingest_events`, `set_issue`, `silence_threshold`, `evaluate_health`, `observe_asset`, `probe_device`, `read_receipts`, `reconcile_security`, … (ver archivo) |
| [core/operations_models.py](../../core/operations_models.py) | `IncidentAction`, `ProtectionPolicy`, `ExposureCheck`, `ExposureFinding`, `StaffAccess`, `MfaProfile`, `AuthAttempt`, `AuditEvent`, `DeviceHealth`, `DeviceFeed`, `FeedBucket`, `Asset`, `SecurityEvidence`, `AttributionCatalog`, … (ver archivo) |
| [core/operations_suite.py](../../core/operations_suite.py) | `runbook_titles`, `runbook`, `TaskForm`, `task_edit`, `customer_task_reply`, `ValidationForm`, `reconcile_validations`, `validations`, `archives`, `acknowledge` |
| [core/operations_views.py](../../core/operations_views.py) | `permitted`, `AssetForm`, `HealthForm`, `StaffForm`, `health_list`, `health_device`, `inventory`, `asset_edit`, `incident_note`, `staff`, `audit_log` |
| [core/opnsense_api.py](../../core/opnsense_api.py) | Credential storage and read-only OPNsense API connectivity check. — `OpnsenseApiError`, `encrypt_credential`, `decrypt_credential`, `validate_api_url`, `validate_ca_certificate`, `check_connection`, `get_firmware_info`, `discover_version` |
| [core/protection.py](../../core/protection.py) | Observed protection, declared requirements and evidence stay distinct. — `flag`, `selected`, `ids_mode`, `backend_date`, `zenarmor_export_entitlement`, `extra_opnsense`, `unifi_protection`, `incident_key`, `snapshot` |
| [core/protection_views.py](../../core/protection_views.py) | `PolicyForm`, `protection_list`, `protection_device` |
| [core/provisioning.py](../../core/provisioning.py) | Idempotent, per-device syslog provisioning for supported management methods. — `ProvisionError`, `available_destinations`, `default_destination`, `provision_export` |
| [core/recovery.py](../../core/recovery.py) | Encrypted consistent backups, pinned SFTP transfer and isolated restore checks. — `cipher`, `file_hash`, `encrypt_file`, `decrypt_file`, `sftp_connect`, `transfer`, `validate_archive`, `validate_tar`, `pg_environment`, `dump_database`, `verify_database`, `HashingReader`, `native_snapshot`, `test_indexer_restore`, … (ver archivo) |
| [core/recovery_components.py](../../core/recovery_components.py) | Explicit recovery coverage; secrets stay inside the encrypted archive. — `selected_indices`, `export_live_security`, `verify_profile` |
| [core/release.py](../../core/release.py) | Versión instalada: commit que deploy/update.sh registra al desplegar. — `deployed_release` |
| [core/report_pdf.py](../../core/report_pdf.py) | Customer PDF using the same scoped report context as the browser view. — `render_report_pdf` |
| [core/report_sharing.py](../../core/report_sharing.py) | Revocable report links; anonymous requests never enter internal portal views. — `validate_public_url`, `share_path`, `create_report_link`, `resolve_share`, `private_headers`, `customer_report`, `customer_report_pdf`, `report_health`, `verify_public_reports`, `manage_report_link` |
| [core/report_versions.py](../../core/report_versions.py) | Versiones publicadas e inmutables de los informes semanales (bloque 6). — `render_snapshot`, `freeze`, `published_version`, `version_page`, `version_pdf`, `rectify` |
| [core/reporting.py](../../core/reporting.py) | Weekly customer reporting from indexed Wazuh alerts. — `indexer_authorization`, `report_sources`, `security_filter`, `action_filter`, `coverage_for_week`, `collect_client_week`, `refresh_week`, `refresh_current_reports`, `report_context`, `send_report` |
| [core/reputation.py](../../core/reputation.py) | Reputación de IPs con CrowdSec (hoja de ruta 4A/C1): contexto, nunca detección. — `QuotaExceeded`, `KeyRejected`, `EngineUnavailable`, `daily_limit`, `monthly_limit`, `lapi_url`, `mode`, `protected_addresses`, `eligible`, `candidates`, `fetch_lapi`, `count_decisions`, `summarize_lists`, `parse_lapi`, … (ver archivo) |
| [core/reputation_views.py](../../core/reputation_views.py) | Página «Reputación CrowdSec»: estado del motor y orígenes en lista dentro del ámbito del usuario. — `engine_status`, `overview` |
| [core/roles.py](../../core/roles.py) | `synchronize_roles` |
| [core/scope.py](../../core/scope.py) | Customer scope is request-local. Root/background jobs explicitly have no scope. — `ScopedManager` |
| [core/secure_logs.py](../../core/secure_logs.py) | Authenticated HTTPS log transport, independent of the client's public IP. — `queue_has_room`, `active_channels`, `ensure_local_guard`, `prepare`, `ingest`, `persisted_reply`, `setup`, `relay_package` |
| [core/security.py](../../core/security.py) | Internal staff security: TOTP, client authorization and redacted audit. — `vault`, `encrypt`, `decrypt`, `totp`, `verify_token`, `attempt_key`, `throttled`, `failed_attempt`, `client_ip`, `login_throttled`, `failed_login`, `audit`, `audit_integrity`, `mfa_fresh`, … (ver archivo) |
| [core/service_development.py](../../core/service_development.py) | Customer publication boundaries and evidence-based service follow-up. — `PublicationForm`, `publish`, `customer_client`, `released_reports`, `customer_report_context`, `customer_home`, `customer_geography`, `customer_map`, `customer_map_data`, `customer_version`, `customer_weekly`, `customer_weekly_pdf`, `record_observation`, `device_history`, … (ver archivo) |
| [core/source_ownership.py](../../core/source_ownership.py) | Time-bounded source ownership shared by reporting and alert attribution. — `desired`, `capture`, `synchronize`, `report_scope`, `owns_at`, `coverage_metadata` |
| [core/ssh_connection.py](../../core/ssh_connection.py) | Pinned-host-key SSH access. Never accept an unknown key during authentication. — `SshConnectionError`, `encrypt_password`, `decrypt_password`, `validate_host`, `validate_port`, `fingerprint`, `probe_host_key`, `run_command`, `check_connection`, `check_generic_connection` |
| [core/threat_map.py](../../core/threat_map.py) | Local GeoIP enrichment and scoped, bounded geography of real SOC evidence. — `update_geoip_database`, `backfill_map_history`, `public_ip`, `peer_for`, `enrich_geography`, `filters`, `map_data`, `threat_map`, `threat_map_data` |
| [core/trends.py](../../core/trends.py) | `period_metrics`, `trend_context`, `client_trends` |
| [core/unifi_cloud.py](../../core/unifi_cloud.py) | Read-only UniFi Site Manager access for one configured device. — `UnifiCloudError`, `encrypt_api_key`, `decrypt_api_key`, `list_sites`, `list_host_consoles`, `list_host_names`, `get_console_details`, `connector_json`, `discover_syslog_source` |
| [core/unifi_flow.py](../../core/unifi_flow.py) | Three-valued evaluation of observed catalogue criteria, never reachability. — `project`, `conjunction`, `matches`, `evaluate` |
| [core/unifi_policy_details.py](../../core/unifi_policy_details.py) | Bounded display of observed UniFi port/protocol types; not a flow evaluator. — `addresses`, `ports`, `protocol` |
| [core/unifi_policy_history.py](../../core/unifi_policy_history.py) | Differences between complete observations, without attributing unknown IDs/actors. — `rules`, `changes`, `track`, `presentation` |
| [core/unifi_zone_scope.py](../../core/unifi_zone_scope.py) | Readonly official UniFi Integration API. Catalogue order is not a flow verdict. — `identity`, `name`, `boolean`, `integer`, `sequence`, `integration_json`, `catalogue`, `resources`, `project`, `collect`, `snapshot` |
| [core/urgent_alerts.py](../../core/urgent_alerts.py) | Near-real-time, customer-scoped alerts from verified Wazuh event sources. — `scan_events`, `deliver_pending` |
| [core/urls.py](../../core/urls.py) |  |
| [core/views.py](../../core/views.py) | `dashboard`, `api_connections`, `urgent_alert_list`, `mail_settings`, `client_list`, `client_detail`, `site_detail`, `site_delete`, `device_detail`, `export_destination`, `client_form`, `site_form`, `device_form`, `unifi_cloud`, … (ver archivo) |
| [core/vpn.py](../../core/vpn.py) | Isolated WireGuard peers; the portal queues changes for a privileged worker. — `create_peer`, `client_config`, `active_peers`, `synchronize`, `record_log_transport`, `transfer_sample`, `transport_snapshot` |
| [core/vpn_security.py](../../core/vpn_security.py) | VPN access observations, separate from threat and tunnel-health counters. — `VpnAccessEvent`, `parse`, `record`, `analysis`, `dashboard` |
| [core/wazuh_delivery.py](../../core/wazuh_delivery.py) | Acknowledged, replayable delivery through a dedicated native Wazuh analysisd. — `provision_pipeline`, `uid_for`, `hostname`, `reframe`, `prepare_messages`, `identify`, `canonical`, `read_native_receipts`, `send_due`, `native_bulk`, `publish_due`, `finish_batches`, `run_cycle`, `check_profile`, … (ver archivo) |
| [core/wazuh_isolation.py](../../core/wazuh_isolation.py) | Real negative checks using the proxy identity, no fake security documents. — `proxy_get`, `verify_isolation` |
| [core/wazuh_scoped.py](../../core/wazuh_scoped.py) | Per-customer read-only projection. Raw Wazuh indices are never granted. — `names`, `role_definition`, `binding_ready`, `document`, `bulk_publish`, `sync_client`, `synchronize` |
| [core/wazuh_sso.py](../../core/wazuh_sso.py) | Internal nginx authorization subrequest; never accepts browser identity headers. — `allowed`, `global_access`, `selected_scope`, `verified`, `check`, `enter` |
| [core/wazuh_tenant_objects.py](../../core/wazuh_tenant_objects.py) | Tenant-local objects generated from the corporate dashboard components. — `load`, `sync_objects` |
| [core/work_queue.py](../../core/work_queue.py) | Scoped daily operations and race-safe, explicit incident ownership. — `work_queue`, `claim_incident` |
| [core/zenarmor_bypass.py](../../core/zenarmor_bypass.py) | Known local XML bypass flags only; SSO exemptions are not packet exemptions. — `project`, `snapshot` |
| [core/zenarmor_export.py](../../core/zenarmor_export.py) | Operator-authorized native Syslog setup; license required, no report DB scraping. — `ExportError`, `queue`, `configure`, `refresh_due` |
| [core/zenarmor_scope.py](../../core/zenarmor_scope.py) | Readonly Zenarmor 2.6 scope adapter; stored data is an explicit projection. — `digest`, `items`, `identifiers`, `boolean`, `policy_id`, `parse_interfaces`, `parse_policy`, `collect`, `scope_current`, `network_snapshot`, `device_snapshot` |

## Interfaz y activos

| Directorio | Función |
|---|---|
| [templates](../../templates/) | HTML de servidor, formularios y correo. |
| [static](../../static/) | CSS, JavaScript, logos y mapa. |
| [public](../../public/) | Índice público de informes. |
| [deploy](../../deploy/) | Instaladores, unidades, relay, reglas y utilidades. |
