from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [("core", "0008_ssh_and_export")]

    operations = [
        migrations.AddField(model_name="client", name="report_email", field=models.EmailField(blank=True, max_length=254, verbose_name="Correo para informes semanales")),
        migrations.AddField(model_name="client", name="weekly_reports_enabled", field=models.BooleanField(default=False, verbose_name="Enviar informe semanal automáticamente")),
        migrations.CreateModel(
            name="WeeklyReport",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("week_start", models.DateField()),
                ("sources", models.JSONField(default=list)),
                ("wazuh_alert_count", models.PositiveIntegerField(default=0)),
                ("security_count", models.PositiveIntegerField(default=0)),
                ("allowed_count", models.PositiveIntegerField(default=0)),
                ("blocked_count", models.PositiveIntegerField(default=0)),
                ("notable_alerts", models.JSONField(default=list)),
                ("collected_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("sent_at", models.DateTimeField(blank=True, null=True)),
                ("sent_to", models.EmailField(blank=True, max_length=254)),
                ("last_send_error", models.CharField(blank=True, max_length=250)),
                ("client", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="weekly_reports", to="core.client")),
            ],
            options={"ordering": ["-week_start", "client__name"]},
        ),
        migrations.AddConstraint(model_name="weeklyreport", constraint=models.UniqueConstraint(fields=("client", "week_start"), name="unique_weekly_report_client_week")),
    ]
