from django.db import migrations,models
import django.db.models.deletion

class Migration(migrations.Migration):
    dependencies=[('core','0035_delivery_coverage_customer_dashboards')]
    operations=[migrations.CreateModel(name='VpnAccessEvent',fields=[
        ('uid',models.CharField(max_length=64,primary_key=True,serialize=False)),
        ('client_scope_id',models.PositiveBigIntegerField(db_index=True,editable=False)),
        ('observed_at',models.DateTimeField(db_index=True)),
        ('peer_ip',models.GenericIPAddressField(null=True)),
        ('outcome',models.CharField(max_length=12)),
        ('protocol',models.CharField(max_length=24)),
        ('country',models.CharField(blank=True,max_length=2)),
        ('device',models.ForeignKey(on_delete=django.db.models.deletion.PROTECT,to='core.device')),
    ],options={'ordering':['-observed_at']})]
