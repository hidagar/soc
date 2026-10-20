from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('core', '0043_automatic_device_inventory')]
    operations = [
        migrations.AddField(model_name='securityevidence', name='interpretation', field=models.JSONField(default=dict, blank=True)),
        migrations.AddField(model_name='urgentalert', name='interpretation', field=models.JSONField(default=dict, blank=True)),
    ]
