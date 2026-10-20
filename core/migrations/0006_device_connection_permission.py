from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("core", "0005_device_connection_methods")]

    operations = [
        migrations.AlterModelOptions(
            name="device",
            options={
                "ordering": ["site__client__name", "site__name", "name"],
                "verbose_name": "Equipo",
                "verbose_name_plural": "Equipos",
                "permissions": [("manage_connections", "Puede gestionar credenciales y conexiones de equipos")],
            },
        ),
    ]
