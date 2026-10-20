from datetime import datetime,timezone
from django.db import migrations,models
from django.utils import timezone as dj_timezone


def baseline(apps,schema_editor):
    Ownership=apps.get_model('core','SourceOwnership');Export=apps.get_model('core','ExportConfiguration')
    Channel=apps.get_model('core','SecureLogChannel');Evidence=apps.get_model('core','SecurityEvidence')
    owners={};devices={}
    for source,cid,did in Export.objects.filter(receiver_ready=True).exclude(source_ip=None).values_list('source_ip','device__site__client_id','device_id'):
        owners.setdefault(source,set()).add(cid);devices.setdefault(source,set()).add(did)
    for source,cid,did in Channel.objects.filter(receiver_ready=True,client_scope_id=models.F('device__site__client_id')).values_list('source_identity','client_scope_id','device_id'):
        owners.setdefault(source,set()).add(cid);devices.setdefault(source,set()).add(did)
    for source,ids in owners.items():
        cid=next(iter(ids)) if len(ids)==1 else None
        # Known historic transfers cannot acquire an invented historic owner.
        foreign=Evidence.objects.filter(device_id__in=devices[source]).exclude(client_scope_id=cid).exists()
        Ownership.objects.create(source=source,client_scope_id=cid,valid_from=dj_timezone.now() if foreign or cid is None else datetime(1970,1,1,tzinfo=timezone.utc))


class Migration(migrations.Migration):
    dependencies=[('core','0039_unique_login_email')]
    operations=[
        migrations.AddField(model_name='urgentmonitorcursor',name='checkpoint',field=models.JSONField(default=dict,blank=True)),
        migrations.CreateModel(name='SourceOwnership',fields=[('id',models.BigAutoField(auto_created=True,primary_key=True,serialize=False,verbose_name='ID')),
            ('source',models.GenericIPAddressField(db_index=True)),('client_scope_id',models.PositiveBigIntegerField(null=True,editable=False,db_index=True)),
            ('valid_from',models.DateTimeField()),('valid_until',models.DateTimeField(null=True,blank=True))],options={'constraints':[models.UniqueConstraint(fields=('source',),condition=models.Q(valid_until__isnull=True),name='unique_current_source_owner')]}),
        migrations.RunPython(baseline,migrations.RunPython.noop),
    ]
