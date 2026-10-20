from django.db import migrations,models

class Migration(migrations.Migration):
    dependencies=[('core','0018_soc_incident_identity')]
    operations=[migrations.AddField(model_name='securityevidence',name='geography',field=models.JSONField(default=dict,blank=True))]
