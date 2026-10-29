from django.urls import path
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required

from . import campaigns
from . import views
from . import wazuh_sso
from . import hillstone_views
from . import gdms_views
from . import inventory_views
from .connection_help import connection_guide
from . import report_sharing
from . import report_versions
from . import onboarding
from . import security
from . import operations_views as ops
from . import control_views as controls
from . import threat_map as geography
from . import action_tracking, trends
from . import exposure_views
from . import protection_views


from . import service_development as service
from . import work_queue
from . import operations_suite as suite,delivery_tracking as delivery
from . import network_views
from . import advanced_views
from . import investigation, vpn_security
from . import reputation_views
from . import customer_portal
from . import customer_preview
from . import blocklist
from . import crowdsec_catalog
from . import invitations
from . import secure_logs

urlpatterns = [
    path('ingest/<uuid:channel_id>/',secure_logs.ingest,name='secure_log_ingest'),
    path('devices/<int:pk>/secure-logs/',secure_logs.setup,name='secure_log_setup'),
    path('activate/<int:uid>/<str:token>/',invitations.activate,name='accept_invitation'),
    path('operations/investigation/',investigation.explore,name='security_explore'),
    path('operations/investigation/ip/',investigation.ip_detail,name='ip_investigation'),
    path('operations/vpn-security/',vpn_security.dashboard,name='vpn_security'),
    path('devices/<int:pk>/advanced/',advanced_views.advanced,name='advanced_coverage'),
    path('security/wazuh/check/',wazuh_sso.check,name='wazuh_sso_check'),
    path('security/wazuh/enter/',wazuh_sso.enter,name='wazuh_sso_enter'),
    path('operations/coverage/',network_views.coverage,name='network_coverage'),
    path('devices/<int:pk>/coverage/',network_views.coverage,name='device_coverage'),
    path('operations/networks/<int:pk>/requirements/',network_views.requirements,name='network_requirements'),
    path('reports/delivery-events/',delivery.delivery_webhook,name='delivery_webhook'),
    path('operations/delivery/',delivery.delivery_status,name='delivery_status'),
    path('operations/delivery/settings/',delivery.delivery_settings,name='delivery_settings'),
    path('alerts/<int:pk>/acknowledge/',suite.acknowledge,name='acknowledge_alert'),
    path('incidents/<int:pk>/runbook/',suite.runbook,name='runbook'),
    path('incidents/<int:incident_pk>/tasks/new/',suite.task_edit,name='customer_task_new'),
    path('operations/tasks/<int:pk>/',suite.task_edit,name='customer_task_edit'),
    path('cliente/tareas/<int:pk>/responder/',suite.customer_task_reply,name='customer_task_reply'),
    path('devices/<int:pk>/validations/',suite.validations,name='validations'),
    path('devices/<int:pk>/archives/',suite.archives,name='configuration_archives'),
    path('operations/work/', work_queue.work_queue, name='work_queue'),
    path('incidents/<int:pk>/claim/', work_queue.claim_incident, name='claim_incident'),
    path('cliente/mapa/',service.customer_map,name='customer_map'),
    path('cliente/firewalls/',customer_portal.firewalls,name='customer_firewalls'),
    path('cliente/informes/',service.customer_reports,name='customer_reports'),
    path('cliente/actuaciones/',service.customer_tasks,name='customer_tasks'),
    path('clients/<int:pk>/customer-view/',customer_preview.home,name='customer_preview'),
    path('clients/<int:pk>/customer-view/firewalls/',customer_preview.firewalls,name='customer_preview_firewalls'),
    path('clients/<int:pk>/customer-view/detections/',customer_preview.detections,name='customer_preview_detections'),
    path('clients/<int:pk>/customer-view/map/',customer_preview.threat_map,name='customer_preview_map'),
    path('clients/<int:pk>/customer-view/map/data/',customer_preview.map_data,name='customer_preview_map_data'),
    path('clients/<int:pk>/customer-view/reports/',customer_preview.reports,name='customer_preview_reports'),
    path('clients/<int:pk>/customer-view/tasks/',customer_preview.tasks,name='customer_preview_tasks'),
    path('clients/<int:pk>/customer-view/reports/<int:report_pk>/',customer_preview.report,name='customer_preview_report'),
    path('clients/<int:pk>/customer-view/reports/<int:report_pk>/pdf/',customer_preview.report_pdf,name='customer_preview_report_pdf'),
    path('cliente/detecciones/',customer_portal.detections,name='customer_detections'),
    path('cliente/mapa/data/',service.customer_map_data,name='customer_map_data'),
    path('operations/exposure/device/<int:pk>/interfaces/',exposure_views.exposure_interfaces,name='exposure_interfaces'),
    path('cliente/',service.customer_home,name='customer_home'),
    path('cliente/informes/<int:pk>/',service.customer_weekly,name='customer_weekly'),
    path('cliente/informes/<int:pk>/pdf/',service.customer_weekly_pdf,name='customer_weekly_pdf'),
    path('clients/<int:client_pk>/publish/',service.publish,name='customer_publish'),
    path('clients/<int:client_pk>/monthly/',service.monthly,name='monthly_summary'),
    path('devices/<int:pk>/history/',service.device_history,name='device_history'),
    path('operations/intelligence/',service.intelligence,name='intelligence'),
    path('operations/crowdsec/',reputation_views.overview,name='crowdsec_overview'),
    path('operations/campaigns/',campaigns.campaign_list,name='campaign_list'),
    path('operations/blocklists/',blocklist.overview,name='blocklists'),
    path('operations/crowdsec/lists/',crowdsec_catalog.overview,name='crowdsec_lists'),
    path('operations/crowdsec/lists/<int:pk>/',crowdsec_catalog.action,name='crowdsec_list_action'),
    path('operations/blocklists/<int:client_pk>/',blocklist.detail,name='blocklist_detail'),
    path('feeds/bloqueo/<int:client_pk>/<str:token>/',blocklist.serve,name='blocklist_serve'),
    path('feeds/bloqueo/<int:client_pk>/<str:token>/salida/',blocklist.serve_outbound,name='blocklist_serve_out'),
    path('operations/protection/',protection_views.protection_list,name='protection_list'),
    path('operations/protection/<int:pk>/',protection_views.protection_device,name='protection_device'),
    path('operations/exposure/',exposure_views.exposure_list,name='exposure_list'),
    path('devices/<int:pk>/unifi-policies/',exposure_views.unifi_policies,name='unifi_policies'),
    path('operations/exposure/<int:pk>/',exposure_views.exposure_detail,name='exposure_detail'),
    path('operations/exposure/device/<int:pk>/recheck/',exposure_views.exposure_recheck,name='exposure_recheck'),
    path('operations/actions/',action_tracking.action_list,name='action_list'),
    path('incidents/<int:incident_pk>/actions/new/',action_tracking.action_form,name='action_new'),
    path('operations/actions/<int:pk>/edit/',action_tracking.action_form,name='action_edit'),
    path('clients/<int:client_pk>/trends/',trends.client_trends,name='client_trends'),
    path('operations/map/',geography.threat_map,name='threat_map'),
    path('operations/map/data/',geography.threat_map_data,name='threat_map_data'),
    path('help/operations/',login_required(TemplateView.as_view(template_name='operations_help.html')),name='operations_help'),
    path('operations/changes/',controls.changes,name='changes'),
    path('operations/changes/<int:pk>/',controls.change_detail,name='change_detail'),
    path('operations/vpn/',controls.vpn_sites,name='vpn_sites'),
    path('operations/vpn/<int:pk>/config/',controls.vpn_download,name='vpn_download'),
    path('operations/recovery/',controls.recovery,name='recovery'),
    path('security/staff/<int:pk>/mfa-reset/',security.mfa_reset,name='mfa_reset'),
    path('operations/health/',ops.health_list,name='health_list'),
    path('operations/health/<int:pk>/',ops.health_device,name='health_device'),
    path('operations/inventory/',ops.inventory,name='inventory'),
    path('operations/assets/<int:pk>/',ops.asset_edit,name='asset_edit'),
    path('incidents/<int:pk>/note/',ops.incident_note,name='incident_note'),
    path('security/staff/',ops.staff,name='staff'),
    path('security/staff/<int:pk>/',ops.staff,name='staff_edit'),
    path('security/audit/',ops.audit_log,name='audit_log'),
    path('security/mfa/setup/', security.mfa_setup, name='mfa_setup'),
    path('security/mfa/verify/', security.mfa_challenge, name='mfa_challenge'),
    path("reports/health/", report_sharing.report_health, name="report_health"),
    path("reports/<str:token>/pdf/", report_sharing.customer_report_pdf, name="customer_report_pdf"),
    path("reports/<str:token>/", report_sharing.customer_report, name="customer_report"),
    path("report-links/<int:report_pk>/", report_sharing.manage_report_link, name="manage_report_link"),
    path("report-versions/<int:report_pk>/rectify/", report_versions.rectify, name="rectify_report"),
    path("mail/verify-reports/", report_sharing.verify_public_reports, name="verify_public_reports"),
    path("gestion/", views.dashboard, name="dashboard"),
    path("", views.dashboard, name="dashboard_legacy"),
    path("connections/", views.api_connections, name="api_connections"),
    path("help/connect-firewall/", connection_guide, name="connection_guide"),
    path("mail/", views.mail_settings, name="mail_settings"),
    path("alerts/", views.urgent_alert_list, name="urgent_alert_list"),
    path("clients/", views.client_list, name="client_list"),
    path("clients/new/", views.client_form, name="client_new"),
    path("clients/<int:pk>/", views.client_detail, name="client_detail"),
    path("clients/<int:pk>/edit/", views.client_form, name="client_edit"),
    path("clients/<int:client_pk>/report/", views.weekly_report, name="weekly_report"),
    path("sites/new/", views.site_form, name="site_new"),
    path("sites/<int:site_pk>/add-device/", onboarding.add_device, name="onboarding_add_device"),
    path("devices/<int:pk>/connect/", onboarding.device_wizard, name="device_onboarding"),
    path("devices/<int:pk>/connect/status/", onboarding.status, name="onboarding_status"),
    path("sites/<int:pk>/", views.site_detail, name="site_detail"),
    path("sites/<int:pk>/edit/", views.site_form, name="site_edit"),
    path("sites/<int:pk>/delete/", views.site_delete, name="site_delete"),
    path("devices/new/", views.device_form, name="device_new"),
    path("devices/<int:pk>/", views.device_detail, name="device_detail"),
    path("devices/<int:pk>/edit/", views.device_form, name="device_edit"),
    path("devices/<int:pk>/export-destination/", views.export_destination, name="export_destination"),
    path("devices/<int:pk>/unifi-cloud/", views.unifi_cloud, name="unifi_cloud"),
    path("devices/<int:pk>/opnsense-api/", views.opnsense_api, name="opnsense_api"),
    path("devices/<int:pk>/hillstone-api/", hillstone_views.hillstone_api, name="hillstone_api"),
    path("devices/<int:pk>/gdms-cloud/", gdms_views.gdms_cloud, name="gdms_cloud"),
    path("devices/<int:pk>/inventory/refresh/", inventory_views.refresh_inventory, name="refresh_device_inventory"),
    path("devices/<int:pk>/ssh/", views.ssh_connection, name="ssh_connection"),
    path("incidents/", views.incident_list, name="incident_list"),
    path("incidents/new/", views.incident_form, name="incident_new"),
    path("incidents/<int:pk>/", views.incident_detail, name="incident_detail"),
    path("incidents/<int:pk>/edit/", views.incident_form, name="incident_edit"),
    path("options/", views.related_options, name="related_options"),
]
