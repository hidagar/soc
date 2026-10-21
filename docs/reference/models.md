# Modelos y campos

Generado desde el código por `python docs/tools/generate_reference.py`. No es telemetría ni una declaración de permisos efectivos.

Inventario estático de clases Django y campos declarados; no incluye campos ID automáticos ni tablas estándar de auth/sessions. Consultar constraints, clean/save, manager y migraciones para semántica y borrado. `blank` no significa `null`; un campo cifrado no debe mostrarse como dato de diagnóstico.

## UserInvitation

Fuente: [core/access_models.py](../../core/access_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `user` | OneToOneField | → settings.AUTH_USER_MODEL; on_delete=models.CASCADE |
| `recipient` | EmailField |  |
| `token_hash` | CharField | max_length=64 |
| `encrypted_token` | TextField | blank=True |
| `created_at` | DateTimeField |  |
| `expires_at` | DateTimeField |  |
| `accepted_at` | DateTimeField | null=True |
| `sent_at` | DateTimeField | null=True |
| `attempted_at` | DateTimeField | null=True |
| `status` | CharField | max_length=16 |
| `error` | CharField | max_length=240; blank=True |
| `provider_id` | CharField | max_length=180; blank=True |
## SecureLogChannel

Fuente: [core/access_models.py](../../core/access_models.py).

Ámbito declarado: `'client_scope_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `id` | UUIDField | primary_key=True |
| `device` | OneToOneField | → 'core.Device'; on_delete=models.PROTECT |
| `client_scope_id` | PositiveBigIntegerField |  |
| `source_identity` | GenericIPAddressField | unique=True |
| `token_hash` | CharField | max_length=64 |
| `encrypted_token` | TextField |  |
| `enabled` | BooleanField |  |
| `receiver_ready` | BooleanField |  |
| `created_at` | DateTimeField |  |
| `last_received_at` | DateTimeField | null=True |
| `last_transport_ip` | GenericIPAddressField | null=True |
## SecureLogReceipt

Fuente: [core/access_models.py](../../core/access_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `channel` | ForeignKey | → SecureLogChannel; on_delete=models.CASCADE |
| `batch_id` | UUIDField |  |
| `digest` | CharField | max_length=64 |
| `received_at` | DateTimeField | db_index=True |
| `bytes_count` | PositiveIntegerField |  |
| `messages_count` | PositiveIntegerField |  |
| `status` | CharField | max_length=16; db_index=True |
| `encrypted_payload` | TextField | blank=True |
| `forwarded_count` | PositiveIntegerField |  |
| `inflight_index` | PositiveIntegerField | null=True |
| `attempts` | PositiveIntegerField |  |
| `attempted_at` | DateTimeField | null=True |
| `next_attempt_at` | DateTimeField | null=True; db_index=True |
| `forwarded_at` | DateTimeField | null=True |
| `error` | CharField | max_length=240; blank=True |
| `transport_version` | PositiveSmallIntegerField |  |
| `confirmed_at` | DateTimeField | null=True |
## SecureLogMessage

Fuente: [core/access_models.py](../../core/access_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `uid` | CharField | max_length=64; primary_key=True |
| `receipt` | ForeignKey | → SecureLogReceipt; on_delete=models.CASCADE |
| `position` | PositiveSmallIntegerField |  |
| `frame_digest` | CharField | max_length=64 |
| `status` | CharField | max_length=16; db_index=True |
| `attempts` | PositiveSmallIntegerField |  |
| `sent_at` | DateTimeField | null=True |
| `next_attempt_at` | DateTimeField | null=True; db_index=True |
| `processed_at` | DateTimeField | null=True |
| `indexed_at` | DateTimeField | null=True |
| `projected_at` | DateTimeField | null=True |
| `rule_level` | PositiveSmallIntegerField | null=True |
| `decoder` | CharField | max_length=120; blank=True |
| `encrypted_event` | TextField | blank=True |
| `error` | CharField | max_length=240; blank=True |
## RunbookStep

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'incident__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `incident` | ForeignKey | → 'core.Incident'; on_delete=models.CASCADE |
| `position` | PositiveSmallIntegerField |  |
| `title` | CharField | max_length=220 |
| `done` | BooleanField |  |
| `evidence` | TextField | blank=True |
| `completed_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `completed_at` | DateTimeField | null=True |
## ProtectionValidation

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `network` | ForeignKey | → 'core.NetworkCoverage'; on_delete=models.SET_NULL; null=True; blank=True |
| `test_ip` | GenericIPAddressField | null=True; blank=True |
| `network_snapshot` | JSONField | blank=True |
| `configuration_fingerprint` | CharField | max_length=64; blank=True |
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `engine` | CharField | max_length=16 |
| `networks` | CharField | max_length=500 |
| `expected_signature` | CharField | max_length=240 |
| `started_at` | DateTimeField |  |
| `expires_at` | DateTimeField |  |
| `evidence` | ForeignKey | → 'core.SecurityEvidence'; on_delete=models.SET_NULL; null=True; blank=True |
| `requested_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
## ZenarmorExportRequest

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → 'core.Device'; on_delete=models.CASCADE |
| `status` | CharField | max_length=24 |
| `requested_at` | DateTimeField |  |
| `checked_at` | DateTimeField | null=True |
| `confirmed_at` | DateTimeField | null=True |
| `requested_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `note` | TextField | blank=True |
| `encrypted_previous` | TextField | blank=True |
## CustomerTask

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'incident__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `incident` | ForeignKey | → 'core.Incident'; on_delete=models.PROTECT |
| `action` | OneToOneField | → 'core.IncidentAction'; on_delete=models.SET_NULL; null=True; blank=True |
| `title` | CharField | max_length=220 |
| `instructions` | TextField |  |
| `due_at` | DateTimeField | null=True; blank=True |
| `visible` | BooleanField |  |
| `status` | CharField | max_length=16 |
| `response` | TextField | blank=True |
| `submitted_at` | DateTimeField | null=True |
| `reviewed_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `review_note` | TextField | blank=True |
| `reviewed_at` | DateTimeField | null=True |
| `updated_at` | DateTimeField |  |
## CustomerTaskEntry

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'task__incident__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `task` | ForeignKey | → CustomerTask; on_delete=models.CASCADE |
| `kind` | CharField | max_length=16 |
| `status` | CharField | max_length=16 |
| `text` | TextField |  |
| `author` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `created_at` | DateTimeField |  |
## DeliverySettings

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `public_key` | TextField | blank=True |
| `enabled` | BooleanField |  |
| `ack_minutes` | PositiveIntegerField |  |
| `last_signed_at` | DateTimeField | null=True; blank=True |
| `last_matched_at` | DateTimeField | null=True; blank=True |
## AdvancedReview

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `note` | TextField | max_length=2000 |
| `valid_until` | DateTimeField |  |
| `baseline` | CharField | max_length=64 |
| `created_at` | DateTimeField |  |
| `reviewed_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
## MailDispatch

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `token` | UUIDField | unique=True |
| `client` | ForeignKey | → 'core.Client'; on_delete=models.CASCADE; null=True; blank=True |
| `report` | ForeignKey | → 'core.WeeklyReport'; on_delete=models.SET_NULL; null=True; blank=True |
| `urgent` | ForeignKey | → 'core.UrgentAlert'; on_delete=models.SET_NULL; null=True; blank=True |
| `recipient` | EmailField |  |
| `kind` | CharField | max_length=16 |
| `provider_id` | CharField | max_length=180; blank=True |
| `status` | CharField | max_length=16 |
| `event_at` | DateTimeField | null=True |
| `created_at` | DateTimeField |  |
## MailEvent

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'dispatch__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `event_hash` | CharField | max_length=64; unique=True |
| `dispatch` | ForeignKey | → MailDispatch; on_delete=models.CASCADE |
| `kind` | CharField | max_length=16 |
| `occurred_at` | DateTimeField |  |
## ConfigurationArchive

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `reviewed_at` | DateTimeField | null=True; blank=True |
| `reviewed_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True; blank=True |
| `review_note` | TextField | blank=True |
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `created_at` | DateTimeField |  |
| `status` | CharField | max_length=16 |
| `kind` | CharField | max_length=24 |
| `sha256` | CharField | max_length=64; blank=True |
| `summary` | JSONField |  |
| `changes` | JSONField |  |
| `note` | CharField | max_length=250; blank=True |
## ReportVersion

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

Ámbito declarado: `'report__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `report` | ForeignKey | → 'core.WeeklyReport'; on_delete=models.CASCADE |
| `number` | PositiveIntegerField |  |
| `html` | TextField |  |
| `pdf` | BinaryField |  |
| `html_sha256` | CharField | max_length=64 |
| `pdf_sha256` | CharField | max_length=64 |
| `reason` | TextField | blank=True |
| `created_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `created_at` | DateTimeField |  |
## IpReputation

Fuente: [core/improvement_models.py](../../core/improvement_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `ip` | GenericIPAddressField | unique=True |
| `source` | CharField | max_length=8 |
| `listed_range` | CharField | max_length=64; blank=True |
| `found` | BooleanField |  |
| `reputation` | CharField | max_length=16; blank=True |
| `confidence` | CharField | max_length=16; blank=True |
| `background_noise` | CharField | max_length=16; blank=True |
| `background_noise_score` | PositiveSmallIntegerField | null=True |
| `scores` | JSONField | blank=True |
| `behaviors` | JSONField | blank=True |
| `classifications` | JSONField | blank=True |
| `false_positives` | JSONField | blank=True |
| `as_name` | CharField | max_length=200; blank=True |
| `country` | CharField | max_length=2; blank=True |
| `first_seen` | CharField | max_length=40; blank=True |
| `last_seen` | CharField | max_length=40; blank=True |
| `fetched_at` | DateTimeField |  |
| `expires_at` | DateTimeField |  |
## Client

Fuente: [core/models.py](../../core/models.py).

Ámbito declarado: `'pk'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `name` | CharField | max_length=180 |
| `code` | SlugField | max_length=50; unique=True |
| `contact_email` | EmailField | blank=True |
| `report_email` | EmailField | blank=True |
| `weekly_reports_enabled` | BooleanField |  |
| `customer_live_map_enabled` | BooleanField |  |
| `urgent_email` | EmailField | blank=True |
| `urgent_alerts_enabled` | BooleanField |  |
| `urgent_availability_enabled` | BooleanField |  |
| `active` | BooleanField |  |
| `notes` | TextField | blank=True |
| `created_at` | DateTimeField |  |
## WeeklyReport

Fuente: [core/models.py](../../core/models.py).

Ámbito declarado: `'client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `coverage` | JSONField |  |
| `client` | ForeignKey | → Client; on_delete=models.CASCADE |
| `week_start` | DateField |  |
| `sources` | JSONField |  |
| `wazuh_alert_count` | PositiveIntegerField |  |
| `security_count` | PositiveIntegerField |  |
| `availability_count` | PositiveIntegerField |  |
| `other_high_count` | PositiveIntegerField |  |
| `allowed_count` | PositiveIntegerField |  |
| `blocked_count` | PositiveIntegerField |  |
| `notable_alerts` | JSONField |  |
| `findings` | JSONField |  |
| `details_limited` | BooleanField |  |
| `collected_at` | DateTimeField |  |
| `sent_at` | DateTimeField | null=True; blank=True |
| `sent_to` | EmailField | blank=True |
| `provider_message_id` | CharField | max_length=180; blank=True |
| `last_send_error` | CharField | max_length=250; blank=True |
## MailSettings

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `region` | CharField | max_length=10 |
| `encrypted_api_key` | TextField | blank=True |
| `from_email` | EmailField |  |
| `reply_to_email` | EmailField | blank=True |
| `report_copy_email` | EmailField | blank=True |
| `public_reports_url` | URLField | max_length=255; blank=True |
| `public_reports_verified` | BooleanField |  |
| `enabled` | BooleanField |  |
| `last_tested_at` | DateTimeField | null=True; blank=True |
| `last_test_ok` | BooleanField |  |
| `updated_at` | DateTimeField |  |
## ReportShare

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `report` | OneToOneField | → WeeklyReport; on_delete=models.CASCADE |
| `nonce` | UUIDField | unique=True |
| `expires_at` | DateTimeField |  |
| `revoked` | BooleanField |  |
## UrgentMonitorCursor

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `last_checked_at` | DateTimeField |  |
| `checkpoint` | JSONField | blank=True |
## SourceOwnership

Fuente: [core/models.py](../../core/models.py).

Ámbito declarado: `'client_scope_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `source` | GenericIPAddressField | db_index=True |
| `client_scope_id` | PositiveBigIntegerField | null=True; db_index=True |
| `valid_from` | DateTimeField |  |
| `valid_until` | DateTimeField | null=True; blank=True |
## UrgentAlert

Fuente: [core/models.py](../../core/models.py).

Ámbito declarado: `'client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `interpretation` | JSONField | blank=True |
| `acknowledged_at` | DateTimeField | null=True; blank=True |
| `acknowledged_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True; blank=True |
| `client` | ForeignKey | → Client; on_delete=models.CASCADE |
| `event_uid` | CharField | max_length=64; unique=True |
| `fingerprint` | CharField | max_length=64; db_index=True |
| `kind` | CharField | max_length=24 |
| `status` | CharField | max_length=16; db_index=True |
| `observed_at` | DateTimeField |  |
| `created_at` | DateTimeField |  |
| `source_ip` | GenericIPAddressField |  |
| `external_ip` | GenericIPAddressField | null=True; blank=True |
| `destination_ip` | GenericIPAddressField | null=True; blank=True |
| `destination_port` | CharField | max_length=16; blank=True |
| `site_name` | CharField | max_length=160; blank=True |
| `asset_name` | CharField | max_length=160; blank=True |
| `signature` | CharField | max_length=240; blank=True |
| `action` | CharField | max_length=32; blank=True |
| `rule_level` | PositiveSmallIntegerField |  |
| `recipient` | EmailField |  |
| `attempts` | PositiveSmallIntegerField |  |
| `next_retry_at` | DateTimeField | null=True; blank=True |
| `last_attempt_at` | DateTimeField | null=True; blank=True |
| `sent_at` | DateTimeField | null=True; blank=True |
| `provider_message_id` | CharField | max_length=180; blank=True |
| `last_error` | CharField | max_length=250; blank=True |
## Site

Fuente: [core/models.py](../../core/models.py).

Ámbito declarado: `'client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `client` | ForeignKey | → Client; on_delete=models.PROTECT |
| `name` | CharField | max_length=160 |
| `code` | SlugField | max_length=50 |
| `address` | CharField | max_length=250; blank=True |
| `notes` | TextField | blank=True |
| `active` | BooleanField |  |
## Device

Fuente: [core/models.py](../../core/models.py).

Ámbito declarado: `'site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `site` | ForeignKey | → Site; on_delete=models.PROTECT |
| `name` | CharField | max_length=160 |
| `vendor` | CharField | max_length=20 |
| `model` | CharField | max_length=120; blank=True |
| `software_version` | CharField | max_length=120; blank=True |
| `management_method` | CharField | max_length=16 |
| `log_method` | CharField | max_length=16 |
| `zenarmor_edition` | CharField | max_length=120; blank=True |
| `zenarmor_enabled` | BooleanField |  |
| `zenarmor_version` | CharField | max_length=120; blank=True |
| `management_address` | CharField | max_length=255; blank=True |
| `ssh_username` | CharField | max_length=120; blank=True |
| `serial_number` | CharField | max_length=120; blank=True |
| `inventory_checked_at` | DateTimeField | null=True; blank=True |
| `inventory_metadata` | JSONField | blank=True |
| `wazuh_identifier` | CharField | max_length=160; blank=True |
| `integration` | CharField | max_length=20 |
| `notes` | TextField | blank=True |
| `active` | BooleanField |  |
## UnifiCloudConnection

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → Device; on_delete=models.CASCADE |
| `encrypted_api_key` | TextField |  |
| `remote_site_id` | CharField | max_length=160; blank=True |
| `remote_host_id` | CharField | max_length=200; blank=True |
| `remote_site_name` | CharField | max_length=200; blank=True |
| `last_checked_at` | DateTimeField | null=True; blank=True |
| `last_ok` | BooleanField |  |
## OpnsenseConnection

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → Device; on_delete=models.CASCADE |
| `api_url` | URLField | max_length=255 |
| `encrypted_api_key` | TextField |  |
| `encrypted_api_secret` | TextField |  |
| `ca_certificate` | TextField | blank=True |
| `last_checked_at` | DateTimeField | null=True; blank=True |
| `last_ok` | BooleanField |  |
## HillstoneConnection

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → Device; on_delete=models.CASCADE |
| `api_url` | URLField | max_length=255 |
| `username` | CharField | max_length=120 |
| `encrypted_password` | TextField |  |
| `ca_certificate` | TextField | blank=True |
| `last_checked_at` | DateTimeField | null=True; blank=True |
| `last_ok` | BooleanField |  |
## GdmsConnection

Fuente: [core/models.py](../../core/models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → Device; on_delete=models.CASCADE |
| `client_scope_id` | PositiveBigIntegerField |  |
| `region` | CharField | max_length=2 |
| `app_id` | CharField | max_length=120 |
| `encrypted_secret` | TextField |  |
| `restricted` | BooleanField |  |
| `username` | CharField | max_length=254; blank=True |
| `encrypted_password` | TextField | blank=True |
| `last_checked_at` | DateTimeField | null=True; blank=True |
| `last_ok` | BooleanField |  |
## SshConnection

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → Device; on_delete=models.CASCADE |
| `hostname` | CharField | max_length=253 |
| `port` | PositiveIntegerField |  |
| `username` | CharField | max_length=120 |
| `encrypted_password` | TextField |  |
| `host_key_type` | CharField | max_length=80 |
| `host_key_base64` | TextField |  |
| `fingerprint` | CharField | max_length=80 |
| `last_checked_at` | DateTimeField | null=True; blank=True |
| `last_ok` | BooleanField |  |
## ExportConfiguration

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → Device; on_delete=models.CASCADE |
| `destination` | GenericIPAddressField |  |
| `port` | PositiveIntegerField |  |
| `source_ip` | GenericIPAddressField | null=True; blank=True |
| `receiver_ready` | BooleanField |  |
| `status` | CharField | max_length=16 |
| `remote_identifier` | CharField | max_length=160; blank=True |
| `last_error` | TextField | blank=True |
| `configured_at` | DateTimeField | null=True; blank=True |
| `last_attempt_at` | DateTimeField | null=True; blank=True |
## FirewallOnboarding

Fuente: [core/models.py](../../core/models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → Device; on_delete=models.CASCADE |
| `method` | CharField | max_length=12 |
| `step` | PositiveSmallIntegerField |  |
| `verification_started_at` | DateTimeField | null=True; blank=True |
| `checked_at` | DateTimeField | null=True; blank=True |
| `verified_at` | DateTimeField | null=True; blank=True |
| `event_at` | DateTimeField | null=True; blank=True |
| `event_decoder` | CharField | max_length=120; blank=True |
| `event_rule` | CharField | max_length=24; blank=True |
| `zenarmor_event_at` | DateTimeField | null=True; blank=True |
| `verification_error` | CharField | max_length=250; blank=True |
| `created_at` | DateTimeField |  |
## Incident

Fuente: [core/models.py](../../core/models.py).

Ámbito declarado: `'client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `episode_key` | CharField | max_length=64; blank=True; db_index=True |
| `fingerprint` | CharField | max_length=96; blank=True; db_index=True |
| `occurrence_count` | PositiveIntegerField |  |
| `last_seen_at` | DateTimeField | null=True; blank=True |
| `recommendation` | TextField | blank=True |
| `client` | ForeignKey | → Client; on_delete=models.PROTECT |
| `site` | ForeignKey | → Site; on_delete=models.PROTECT; null=True; blank=True |
| `device` | ForeignKey | → Device; on_delete=models.PROTECT; null=True; blank=True |
| `title` | CharField | max_length=220 |
| `description` | TextField |  |
| `severity` | CharField | max_length=12 |
| `status` | CharField | max_length=16 |
| `owner` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True; blank=True |
| `observed_at` | DateTimeField |  |
| `resolved_at` | DateTimeField | null=True; blank=True |
| `wazuh_alert_id` | CharField | max_length=180; blank=True |
| `actions` | TextField | blank=True |
| `created_at` | DateTimeField |  |
| `updated_at` | DateTimeField |  |
## NetworkCheck

Fuente: [core/network_models.py](../../core/network_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → 'core.Device'; on_delete=models.CASCADE |
| `checked_at` | DateTimeField | null=True |
| `last_success_at` | DateTimeField | null=True |
| `status` | CharField | max_length=16 |
## NetworkCoverage

Fuente: [core/network_models.py](../../core/network_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `remote_id` | CharField | max_length=120 |
| `name` | CharField | max_length=180 |
| `interface` | CharField | max_length=120; blank=True |
| `physical_interface` | CharField | max_length=120; blank=True |
| `cidrs` | JSONField |  |
| `role` | CharField | max_length=20 |
| `enabled` | BooleanField | null=True |
| `inspection_selected` | BooleanField | null=True |
| `present` | BooleanField |  |
| `last_seen_at` | DateTimeField |  |
| `scope` | CharField | max_length=16 |
| `require_ips` | BooleanField |  |
| `require_zenarmor` | BooleanField |  |
| `review_note` | TextField | blank=True |
| `review_until` | DateTimeField | null=True; blank=True |
| `updated_at` | DateTimeField |  |
## IncidentAction

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'incident__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `incident` | ForeignKey | → 'core.Incident'; on_delete=models.PROTECT |
| `title` | CharField | max_length=240 |
| `description` | TextField | blank=True |
| `owner` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True; blank=True |
| `responsible_party` | CharField | max_length=16 |
| `due_at` | DateTimeField | null=True; blank=True |
| `status` | CharField | max_length=20 |
| `resolution` | TextField | blank=True |
| `completed_at` | DateTimeField | null=True; blank=True |
| `created_at` | DateTimeField |  |
| `updated_at` | DateTimeField |  |
## ProtectionPolicy

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → 'core.Device'; on_delete=models.CASCADE |
| `require_ips` | BooleanField |  |
| `require_zenarmor` | BooleanField |  |
| `require_clamav` | BooleanField |  |
| `notes` | TextField | blank=True |
| `updated_at` | DateTimeField |  |
## ExposureCheck

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → 'core.Device'; on_delete=models.CASCADE |
| `external_interfaces` | JSONField | blank=True |
| `checked_at` | DateTimeField | null=True |
| `last_success_at` | DateTimeField | null=True |
| `requested_at` | DateTimeField | null=True |
| `status` | CharField | max_length=20 |
| `coverage` | JSONField |  |
| `notes` | TextField | blank=True |
## ExposureFinding

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `section` | CharField | max_length=20 |
| `remote_id` | CharField | max_length=180 |
| `kind` | CharField | max_length=30 |
| `title` | CharField | max_length=240 |
| `severity` | CharField | max_length=12 |
| `evidence` | JSONField |  |
| `recommendation` | TextField |  |
| `fingerprint` | CharField | max_length=64 |
| `history` | JSONField |  |
| `present` | BooleanField |  |
| `first_seen_at` | DateTimeField |  |
| `last_seen_at` | DateTimeField |  |
| `removed_at` | DateTimeField | null=True |
| `review` | CharField | max_length=20 |
| `review_note` | TextField | blank=True |
| `review_until` | DateTimeField | null=True |
| `reviewed_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `reviewed_at` | DateTimeField | null=True |
| `incident` | ForeignKey | → 'core.Incident'; on_delete=models.SET_NULL; null=True; blank=True |
## StaffAccess

Fuente: [core/operations_models.py](../../core/operations_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `user` | OneToOneField | → settings.AUTH_USER_MODEL; on_delete=models.CASCADE |
| `clients` | ManyToManyField | → 'core.Client'; blank=True |
| `role` | CharField | max_length=16 |
| `all_clients` | BooleanField |  |
## MfaProfile

Fuente: [core/operations_models.py](../../core/operations_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `user` | OneToOneField | → settings.AUTH_USER_MODEL; on_delete=models.CASCADE |
| `encrypted_secret` | TextField | blank=True |
| `enabled` | BooleanField |  |
| `last_counter` | BigIntegerField |  |
| `recovery_hashes` | JSONField |  |
| `version` | PositiveIntegerField |  |
| `updated_at` | DateTimeField |  |
## AuthAttempt

Fuente: [core/operations_models.py](../../core/operations_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `identifier` | CharField | max_length=64; db_index=True |
| `occurred_at` | DateTimeField | db_index=True |
## AuditEvent

Fuente: [core/operations_models.py](../../core/operations_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `actor` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True; blank=True |
| `actor_name` | CharField | max_length=150; blank=True |
| `action` | CharField | max_length=100 |
| `object_type` | CharField | max_length=80; blank=True |
| `object_id` | CharField | max_length=80; blank=True |
| `details` | JSONField |  |
| `previous_hash` | CharField | max_length=64; blank=True |
| `digest` | CharField | max_length=64 |
| `created_at` | DateTimeField |  |
## DeviceHealth

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → 'core.Device'; on_delete=models.CASCADE |
| `api_ok` | BooleanField | null=True |
| `checked_at` | DateTimeField | null=True |
| `protection_checked_at` | DateTimeField | null=True |
| `api_error` | CharField | max_length=240; blank=True |
| `certificate_expires` | DateTimeField | null=True |
| `engines` | JSONField |  |
| `issues` | JSONField |  |
| `inventory_checked_at` | DateTimeField | null=True |
| `expected_silence_minutes` | PositiveIntegerField |  |
| `maintenance_until` | DateTimeField | null=True; blank=True |
| `status` | CharField | max_length=24 |
| `last_log_at` | DateTimeField | null=True |
| `security_verified_at` | DateTimeField | null=True |
| `security_evidence_uid` | CharField | max_length=64; blank=True |
| `updated_at` | DateTimeField |  |
## DeviceFeed

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `kind` | CharField | max_length=16 |
| `first_seen_at` | DateTimeField | null=True |
| `last_seen_at` | DateTimeField | null=True |
| `security_at` | DateTimeField | null=True |
| `event_count` | PositiveBigIntegerField |  |
## FeedBucket

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `kind` | CharField | max_length=16 |
| `hour` | DateTimeField |  |
| `event_count` | PositiveIntegerField |  |
## Asset

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `identified_at` | DateTimeField | null=True; blank=True |
| `identity_conflict` | BooleanField |  |
| `identity_history` | JSONField | blank=True |
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `ip` | GenericIPAddressField |  |
| `name` | CharField | max_length=160; blank=True |
| `discovered_name` | CharField | max_length=160; blank=True |
| `mac` | CharField | max_length=32; blank=True |
| `vlan` | CharField | max_length=40; blank=True |
| `critical` | BooleanField |  |
| `function` | CharField | max_length=160; blank=True |
| `owner_contact` | CharField | max_length=160; blank=True |
| `source` | CharField | max_length=24 |
| `first_seen_at` | DateTimeField |  |
| `last_seen_at` | DateTimeField |  |
## SecurityEvidence

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'client_scope_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `interpretation` | JSONField | blank=True |
| `client_scope_id` | PositiveBigIntegerField | null=True; db_index=True |
| `wazuh_published_at` | DateTimeField | null=True |
| `flow` | JSONField | blank=True |
| `identity` | JSONField | blank=True |
| `geography` | JSONField | blank=True |
| `uid` | CharField | max_length=64; primary_key=True |
| `device` | ForeignKey | → 'core.Device'; on_delete=models.PROTECT |
| `asset` | ForeignKey | → Asset; on_delete=models.SET_NULL; null=True; blank=True |
| `incident` | ForeignKey | → 'core.Incident'; on_delete=models.SET_NULL; null=True; blank=True |
| `observed_at` | DateTimeField | db_index=True |
| `engine` | CharField | max_length=16 |
| `category` | CharField | max_length=80; blank=True |
| `signature` | CharField | max_length=240 |
| `action` | CharField | max_length=24 |
| `source_ip` | GenericIPAddressField | null=True |
| `destination_ip` | GenericIPAddressField | null=True |
| `destination_port` | CharField | max_length=16; blank=True |
| `level` | PositiveSmallIntegerField |  |
| `wazuh_id` | CharField | max_length=180; blank=True |
| `recommendation` | TextField | blank=True |
## AttributionCatalog

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | OneToOneField | → 'core.Device'; on_delete=models.CASCADE |
| `checked_at` | DateTimeField | null=True |
| `last_success_at` | DateTimeField | null=True |
| `status` | CharField | max_length=16 |
| `data` | JSONField | blank=True |
| `fingerprint` | CharField | max_length=64; blank=True |
## IncidentUpdate

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'incident__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `incident` | ForeignKey | → 'core.Incident'; on_delete=models.CASCADE |
| `author` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `text` | TextField |  |
| `created_at` | DateTimeField |  |
## OperationalIssue

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE; null=True; blank=True |
| `key` | CharField | max_length=120; unique=True |
| `title` | CharField | max_length=240 |
| `severity` | CharField | max_length=16 |
| `details` | TextField | blank=True |
| `active` | BooleanField |  |
| `opened_at` | DateTimeField |  |
| `checked_at` | DateTimeField |  |
| `resolved_at` | DateTimeField | null=True |
| `notified_at` | DateTimeField | null=True |
## WorkerState

Fuente: [core/operations_models.py](../../core/operations_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `name` | CharField | max_length=80; primary_key=True |
| `inode` | CharField | max_length=80; blank=True |
| `offset` | PositiveBigIntegerField |  |
| `last_run_at` | DateTimeField | null=True |
| `last_success_at` | DateTimeField | null=True |
| `error` | CharField | max_length=240; blank=True |
| `details` | JSONField |  |
## ChangePlan

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | ForeignKey | → 'core.Device'; on_delete=models.PROTECT |
| `template` | CharField | max_length=32 |
| `template_version` | CharField | max_length=16 |
| `title` | CharField | max_length=240 |
| `parameters` | JSONField |  |
| `preview` | JSONField |  |
| `status` | CharField | max_length=32 |
| `encrypted_backup` | TextField | blank=True |
| `remote_objects` | JSONField |  |
| `baseline_hash` | CharField | max_length=64; blank=True |
| `requested_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `approved_by` | ForeignKey | → settings.AUTH_USER_MODEL; on_delete=models.SET_NULL; null=True |
| `created_at` | DateTimeField |  |
| `updated_at` | DateTimeField |  |
| `result` | CharField | max_length=240; blank=True |
| `rollback_revision` | CharField | max_length=80; blank=True |
| `confirmation_deadline` | DateTimeField | null=True |
## VpnPeer

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `site` | OneToOneField | → 'core.Site'; on_delete=models.PROTECT |
| `address` | GenericIPAddressField | unique=True |
| `public_key` | CharField | max_length=64; unique=True |
| `encrypted_private_key` | TextField |  |
| `encrypted_preshared_key` | TextField |  |
| `enabled` | BooleanField |  |
| `status` | CharField | max_length=24 |
| `handshake_at` | DateTimeField | null=True |
| `transport` | JSONField | blank=True |
| `created_at` | DateTimeField |  |
## RecoverySettings

Fuente: [core/operations_models.py](../../core/operations_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `transport` | CharField | max_length=16 |
| `vm_backup` | JSONField | blank=True |
| `hostname` | CharField | max_length=253; blank=True |
| `port` | PositiveIntegerField |  |
| `username` | CharField | max_length=120; blank=True |
| `encrypted_password` | TextField | blank=True |
| `host_key_type` | CharField | max_length=80; blank=True |
| `host_key_base64` | TextField | blank=True |
| `fingerprint` | CharField | max_length=100; blank=True |
| `remote_path` | CharField | max_length=255; blank=True |
| `enabled` | BooleanField |  |
| `verified` | BooleanField |  |
| `retention_days` | PositiveIntegerField |  |
| `evidence_days` | PositiveIntegerField |  |
| `operational_email` | EmailField |  |
| `notify_enabled` | BooleanField |  |
## BackupRun

Fuente: [core/operations_models.py](../../core/operations_models.py).

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `created_at` | DateTimeField |  |
| `status` | CharField | max_length=24 |
| `filename` | CharField | max_length=180; blank=True |
| `sha256` | CharField | max_length=64; blank=True |
| `size` | PositiveBigIntegerField |  |
| `external_verified` | BooleanField |  |
| `restore_tested_at` | DateTimeField | null=True |
| `details` | JSONField |  |
| `error` | CharField | max_length=240; blank=True |
## CustomerPublication

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `client` | ForeignKey | → 'core.Client'; on_delete=models.CASCADE |
| `title` | CharField | max_length=220 |
| `summary` | TextField |  |
| `next_steps` | TextField | blank=True |
| `status` | CharField | max_length=20 |
| `incident` | ForeignKey | → 'core.Incident'; on_delete=models.SET_NULL; null=True; blank=True |
| `weekly_report` | ForeignKey | → 'core.WeeklyReport'; on_delete=models.SET_NULL; null=True; blank=True |
| `visible` | BooleanField |  |
| `created_at` | DateTimeField |  |
| `updated_at` | DateTimeField |  |
## DeviceObservation

Fuente: [core/operations_models.py](../../core/operations_models.py).

Ámbito declarado: `'device__site__client_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `device` | ForeignKey | → 'core.Device'; on_delete=models.CASCADE |
| `observed_at` | DateTimeField |  |
| `snapshot` | JSONField |  |
| `changes` | JSONField |  |
## VpnAccessEvent

Fuente: [core/vpn_security.py](../../core/vpn_security.py).

Ámbito declarado: `'client_scope_id'`. Ver manager/middleware para aplicación.

| Campo | Tipo | Relación / atributos declarados |
|---|---|---|
| `uid` | CharField | max_length=64; primary_key=True |
| `device` | ForeignKey | → 'core.Device'; on_delete=models.PROTECT |
| `client_scope_id` | PositiveBigIntegerField | db_index=True |
| `observed_at` | DateTimeField | db_index=True |
| `peer_ip` | GenericIPAddressField | null=True |
| `outcome` | CharField | max_length=12 |
| `protocol` | CharField | max_length=24 |
| `country` | CharField | max_length=2; blank=True |
