from django.db import migrations


def seed(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')
    User = apps.get_model('auth', 'User')
    Access = apps.get_model('core', 'StaffAccess')
    Settings = apps.get_model('core', 'RecoverySettings')
    owned = {'client','site','device','incident','weeklyreport','asset','securityevidence','devicehealth','devicefeed','operationalissue','changeplan','vpnpeer','incidentupdate','urgentalert'}
    for name, role in [('SOC Consulta','reader'),('SOC Operador','operator'),('SOC Administrador','manager')]:
        group, _ = Group.objects.get_or_create(name=name)
        perms = []
        for p in Permission.objects.filter(content_type__app_label='core').select_related('content_type'):
            model = p.content_type.model
            if role == 'manager' or (model in owned and p.codename.startswith('view_')) or (role == 'operator' and (p.codename == 'manage_operations' or model in {'site','device','incident','asset','incidentupdate'} and p.codename.startswith(('add_','change_')))):
                perms.append(p.pk)
        group.permissions.set(perms)
    # Existing internal accounts retain their established access; new accounts are deny-by-default.
    for u in User.objects.all():
        manager = u.is_superuser or u.is_staff or u.user_permissions.filter(codename='manage_connections').exists()
        role = 'manager' if manager else 'operator'
        Access.objects.get_or_create(user=u, defaults={'role':role,'all_clients':True})
        u.groups.add(Group.objects.get(name='SOC Administrador' if manager else 'SOC Operador'))
    Settings.objects.get_or_create(pk=1)


class Migration(migrations.Migration):
    dependencies = [('core','0016_soc_operations'),('auth','0012_alter_user_first_name_max_length')]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
