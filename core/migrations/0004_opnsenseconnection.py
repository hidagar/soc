from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("core", "0003_unificloudconnection")]

    operations = [
        migrations.CreateModel(
            name="OpnsenseConnection",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("api_url", models.URLField(max_length=255)),
                ("encrypted_api_key", models.TextField()),
                ("encrypted_api_secret", models.TextField()),
                ("ca_certificate", models.TextField(blank=True)),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("last_ok", models.BooleanField(default=False)),
                ("device", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="opnsense_api", to="core.device")),
            ],
        ),
    ]
