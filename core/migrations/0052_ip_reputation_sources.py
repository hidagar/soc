"""Separa en IpReputation las listas del motor local y la API CTI, cada una con su fecha.

Las filas del modo `lapi` pasan a los campos de listas; las del modo `cti`, a los de CTI.
"""
from django.db import migrations, models


def split_sources(apps, schema_editor):
    IpReputation = apps.get_model('core', 'IpReputation')
    for row in IpReputation.objects.all().iterator(chunk_size=500):
        if row.source == 'lapi':
            row.listed = row.found
            row.list_origins, row.list_scenarios = row.classifications, row.behaviors
            row.lists_checked_at, row.lists_expires_at = row.fetched_at, row.expires_at
            row.reputation, row.classifications, row.behaviors = '', [], []
        else:
            row.cti_found = row.found
            row.cti_checked_at, row.cti_expires_at = row.fetched_at, row.expires_at
        row.save()


def merge_sources(apps, schema_editor):
    IpReputation = apps.get_model('core', 'IpReputation')
    for row in IpReputation.objects.all().iterator(chunk_size=500):
        if row.cti_found is not None:
            row.source, row.found, row.expires_at = 'cti', row.cti_found, row.cti_expires_at
        else:
            row.source, row.found, row.expires_at = 'lapi', bool(row.listed), row.lists_expires_at or row.fetched_at
            row.reputation = 'listed' if row.listed else 'unknown'
            row.classifications, row.behaviors = row.list_origins, row.list_scenarios
        row.save()


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0051_customer_portal_detail"),
    ]

    operations = [
        migrations.AddField(model_name="ipreputation", name="listed", field=models.BooleanField(null=True)),
        migrations.AddField(model_name="ipreputation", name="list_origins",
                            field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name="ipreputation", name="list_scenarios",
                            field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name="ipreputation", name="lists_checked_at",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="ipreputation", name="lists_expires_at",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="ipreputation", name="cti_found", field=models.BooleanField(null=True)),
        migrations.AddField(model_name="ipreputation", name="cti_checked_at",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="ipreputation", name="cti_expires_at",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AlterField(model_name="ipreputation", name="expires_at", field=models.DateTimeField(null=True)),
        migrations.RunPython(split_sources, merge_sources),
        migrations.RemoveField(model_name="ipreputation", name="source"),
        migrations.RemoveField(model_name="ipreputation", name="found"),
        migrations.RemoveField(model_name="ipreputation", name="expires_at"),
    ]
