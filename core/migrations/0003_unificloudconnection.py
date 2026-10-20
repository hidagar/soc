from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("core", "0002_device_zenarmor_edition_device_zenarmor_version")]

    operations = [
        migrations.CreateModel(
            name="UnifiCloudConnection",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("encrypted_api_key", models.TextField()),
                ("remote_site_id", models.CharField(blank=True, max_length=160)),
                ("remote_host_id", models.CharField(blank=True, max_length=200)),
                ("remote_site_name", models.CharField(blank=True, max_length=200)),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_ok", models.BooleanField(default=False)),
                ("device", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="unifi_cloud", to="core.device")),
            ],
        ),
    ]
