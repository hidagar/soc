from django.contrib.auth.models import Group, Permission

def synchronize_roles(**kwargs):
    owned = {'client','site','device','incident','weeklyreport','asset','securityevidence','devicehealth','devicefeed','operationalissue','changeplan','vpnpeer','incidentupdate','urgentalert'}
    for name, role in [('SOC Consulta','reader'),('SOC Operador','operator'),('SOC Administrador','manager')]:
        group,_ = Group.objects.get_or_create(name=name)
        selected=[]
        for p in Permission.objects.filter(content_type__app_label='core').select_related('content_type'):
            if role=='manager' or p.content_type.model in owned and p.codename.startswith('view_') or role=='operator' and (p.codename=='manage_operations' or p.content_type.model in {'site','device','incident','asset','incidentupdate'} and p.codename.startswith(('add_','change_'))):
                selected.append(p.pk)
        group.permissions.set(selected)
