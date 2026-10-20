from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("core", "0004_opnsenseconnection")]

    operations = [
        migrations.AddField(
            model_name="device",
            name="management_method",
            field=models.CharField(choices=[("none", "Pendiente"), ("api", "API"), ("ssh", "SSH")], default="none", max_length=16, verbose_name="Acceso de gestión"),
        ),
        migrations.AddField(
            model_name="device",
            name="log_method",
            field=models.CharField(choices=[("none", "Pendiente"), ("syslog", "Syslog"), ("wazuh_agent", "Agente Wazuh")], default="none", max_length=16, verbose_name="Envío de eventos"),
        ),
    ]
