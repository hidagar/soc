"""Explicit grants for historical workflow test fixtures, never production fallback."""
from django.contrib.auth.models import Permission
from .models import StaffAccess

def workflow_access(user, reader=False):
    StaffAccess.objects.create(user=user,role='reader' if reader else 'manager',all_clients=True)
    models={'client','site','device','incident','weeklyreport'}
    from django.db.models import Q
    perms=Permission.objects.filter(content_type__app_label='core',content_type__model__in=models).filter(Q(codename__startswith='view_')|Q(codename__startswith='add_')|Q(codename__startswith='change_')|Q(codename__startswith='delete_'))
    if reader:
        perms=perms.filter(codename__startswith='view_')
    user.user_permissions.add(*perms)


def legacy_sources():
    """Test fixture for sources present before the ownership-ledger migration."""
    from datetime import datetime,timezone
    from .models import SourceOwnership
    SourceOwnership._base_manager.update(valid_from=datetime(1970,1,1,tzinfo=timezone.utc))


def collected_report(report):
    """Mark a synthetic fixture as a completed, scoped collection."""
    from .source_ownership import report_scope
    _,_,fingerprint=report_scope(report.client,report.week_start)
    report.coverage={**report.coverage,'collection_schema':2,'ownership_fingerprint':fingerprint}
    report.save(update_fields=['coverage'])
