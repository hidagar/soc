from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [("core", "0011_mail_settings")]

    operations = [
        migrations.AddField(model_name="client", name="urgent_email", field=models.EmailField(blank=True, max_length=254, verbose_name="Correo para avisos urgentes")),
        migrations.AddField(model_name="client", name="urgent_alerts_enabled", field=models.BooleanField(default=False, verbose_name="Enviar avisos urgentes automáticamente")),
        migrations.AddField(model_name="client", name="urgent_availability_enabled", field=models.BooleanField(default=False, verbose_name="Incluir caídas de Internet en avisos urgentes")),
        migrations.CreateModel(name="UrgentMonitorCursor", fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("last_checked_at", models.DateTimeField(default=django.utils.timezone.now)),
        ]),
        migrations.CreateModel(name="UrgentAlert", fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("event_uid", models.CharField(max_length=64, unique=True)),
            ("fingerprint", models.CharField(db_index=True, max_length=64)),
            ("kind", models.CharField(choices=[("security_allowed", "Seguridad permitida"), ("security_critical", "Seguridad crítica"), ("availability", "Caída de Internet")], max_length=24)),
            ("status", models.CharField(choices=[("pending", "Pendiente"), ("sending", "Enviando"), ("accepted", "Aceptado por SendGrid"), ("suppressed", "Agrupado con otro aviso"), ("failed", "Error de envío"), ("uncertain", "Entrega por comprobar"), ("expired", "Fuera de plazo")], db_index=True, default="pending", max_length=16)),
            ("observed_at", models.DateTimeField()),
            ("created_at", models.DateTimeField(auto_now_add=True)),
            ("source_ip", models.GenericIPAddressField()),
            ("external_ip", models.GenericIPAddressField(blank=True, null=True)),
            ("destination_ip", models.GenericIPAddressField(blank=True, null=True)),
            ("destination_port", models.CharField(blank=True, max_length=16)),
            ("site_name", models.CharField(blank=True, max_length=160)),
            ("asset_name", models.CharField(blank=True, max_length=160)),
            ("signature", models.CharField(blank=True, max_length=240)),
            ("action", models.CharField(blank=True, max_length=32)),
            ("rule_level", models.PositiveSmallIntegerField(default=0)),
            ("recipient", models.EmailField(max_length=254)),
            ("attempts", models.PositiveSmallIntegerField(default=0)),
            ("next_retry_at", models.DateTimeField(blank=True, null=True)),
            ("last_attempt_at", models.DateTimeField(blank=True, null=True)),
            ("sent_at", models.DateTimeField(blank=True, null=True)),
            ("provider_message_id", models.CharField(blank=True, max_length=180)),
            ("last_error", models.CharField(blank=True, max_length=250)),
            ("client", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="urgent_alerts", to="core.client")),
        ], options={"ordering": ["-observed_at"]}),
        migrations.AddIndex(model_name="urgentalert", index=models.Index(fields=["client", "observed_at"], name="urgent_client_seen_idx")),
    ]
