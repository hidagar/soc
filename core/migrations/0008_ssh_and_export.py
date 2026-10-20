from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("core", "0007_device_ssh_username")]

    operations = [
        migrations.CreateModel(
            name="SshConnection",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hostname", models.CharField(max_length=253)),
                ("port", models.PositiveIntegerField(default=22)),
                ("username", models.CharField(max_length=120)),
                ("encrypted_password", models.TextField()),
                ("host_key_type", models.CharField(max_length=80)),
                ("host_key_base64", models.TextField()),
                ("fingerprint", models.CharField(max_length=80)),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_ok", models.BooleanField(default=False)),
                ("device", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="ssh_connection", to="core.device")),
            ],
        ),
        migrations.CreateModel(
            name="ExportConfiguration",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("destination", models.GenericIPAddressField(default="172.20.10.20", protocol="IPv4")),
                ("port", models.PositiveIntegerField(default=5514)),
                ("source_ip", models.GenericIPAddressField(blank=True, null=True, protocol="IPv4")),
                ("receiver_ready", models.BooleanField(default=False)),
                ("status", models.CharField(choices=[("pending", "Pendiente"), ("configuring", "Configurando"), ("configured", "Configurado"), ("error", "Error")], default="pending", max_length=16)),
                ("remote_identifier", models.CharField(blank=True, max_length=160)),
                ("last_error", models.TextField(blank=True)),
                ("configured_at", models.DateTimeField(blank=True, null=True)),
                ("last_attempt_at", models.DateTimeField(blank=True, null=True)),
                ("device", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="export_configuration", to="core.device")),
            ],
        ),
    ]
