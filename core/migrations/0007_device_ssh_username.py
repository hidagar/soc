from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0006_device_connection_permission")]

    operations = [
        migrations.AddField(
            model_name="device",
            name="ssh_username",
            field=models.CharField(blank=True, max_length=120, verbose_name="Usuario SSH"),
        ),
    ]
