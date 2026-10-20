from django.contrib import admin
from .email_auth import EmailAdminAuthenticationForm
admin.site.login_form = EmailAdminAuthenticationForm

from .models import Client, Device, Incident, Site, WeeklyReport

admin.site.site_header = "ib-red · Administración técnica"
admin.site.site_title = "Administración técnica · ib-red"
admin.site.index_title = "Administración técnica del SOC"
admin.site.site_url = "/gestion/"


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "active", "report_email", "weekly_reports_enabled")
    search_fields = ("name", "code")


@admin.register(Site)
class SiteAdmin(admin.ModelAdmin):
    list_display = ("name", "client", "code", "active")
    list_filter = ("client", "active")
    search_fields = ("name", "client__name")


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("name", "site", "vendor", "software_version", "integration")
    list_filter = ("vendor", "integration", "active")
    search_fields = ("name", "site__name", "site__client__name", "management_address")


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ("title", "client", "severity", "status", "observed_at")
    list_filter = ("severity", "status", "client")
    search_fields = ("title", "description", "wazuh_alert_id")


@admin.register(WeeklyReport)
class WeeklyReportAdmin(admin.ModelAdmin):
    list_display = ("client", "week_start", "security_count", "availability_count", "wazuh_alert_count", "sent_at", "last_send_error")
    list_filter = ("week_start", "client", "sent_at")
    readonly_fields = ("client", "week_start", "sources", "wazuh_alert_count", "security_count", "availability_count", "other_high_count", "allowed_count", "blocked_count", "findings", "details_limited", "notable_alerts", "collected_at", "sent_at", "sent_to", "last_send_error")

    def has_add_permission(self, request):
        return False
