"""Conservación de datos: limpieza horaria por bloques, independiente de las copias."""
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from . import recovery, retention
from .background_jobs import execute
from .models import (AuthAttempt, BackupRun, Client, Device, FeedBucket, Incident, OperationalIssue, RecoverySettings,
                     SecurityEvidence, Site)


class RetentionTests(TestCase):
    def setUp(self):
        self.client_row = Client.objects.create(name='Cliente', code='c')
        self.device = Device.objects.create(site=Site.objects.create(client=self.client_row, name='Sede', code='s'),
                                            name='FW', vendor='opnsense')
        self.now = timezone.now()

    def evidence(self, uid, days, incident=None):
        return SecurityEvidence.objects.create(uid=f'{uid:064x}', device=self.device, observed_at=self.now - timedelta(days=days),
                                               engine='suricata', signature='ET SCAN', incident=incident)

    def test_old_data_is_pruned_and_incident_evidence_is_kept(self):
        incident = Incident.objects.create(client=self.client_row, title='Caso', observed_at=self.now)
        self.evidence(1, 120)
        self.evidence(2, 120, incident)
        self.evidence(3, 10)
        FeedBucket.objects.create(device=self.device, kind='system', hour=self.now - timedelta(days=120))
        FeedBucket.objects.create(device=self.device, kind='system', hour=self.now - timedelta(days=10))
        AuthAttempt.objects.create(identifier='a', occurred_at=self.now - timedelta(days=2))
        AuthAttempt.objects.create(identifier='b', occurred_at=self.now - timedelta(minutes=5))
        result = retention.prune(self.now)
        self.assertEqual((result['evidence'], result['feed_buckets'], result['auth_attempts']), (1, 1, 1))
        self.assertFalse(result['pending'])
        self.assertEqual(sorted(SecurityEvidence.objects.values_list('uid', flat=True)), [f'{2:064x}', f'{3:064x}'])
        self.assertEqual(FeedBucket.objects.count(), 1)
        self.assertEqual(list(AuthAttempt.objects.values_list('identifier', flat=True)), ['b'])

    def test_uses_the_configured_evidence_days(self):
        RecoverySettings.objects.update_or_create(pk=1, defaults={'evidence_days': 30})
        self.evidence(1, 40)
        retention.prune(self.now)
        self.assertFalse(SecurityEvidence.objects.exists())

    def test_deletes_in_chunks_and_resumes_after_the_time_budget(self):
        for uid in range(5):
            self.evidence(uid, 120)
        with mock.patch.object(retention, 'CHUNK', 2):
            self.assertTrue(retention.prune(self.now, budget=0)['pending'])  # sin tiempo: no borra nada
            self.assertEqual(SecurityEvidence.objects.count(), 5)
            result = retention.prune(self.now)
        self.assertEqual(result['evidence'], 5)
        self.assertFalse(SecurityEvidence.objects.exists())

    def test_the_hourly_housekeeping_job_prunes_without_any_backup(self):
        # Antes solo se limpiaba al final de una copia correcta.
        self.evidence(1, 120)
        execute('housekeeping')
        self.assertFalse(SecurityEvidence.objects.exists())
        self.assertFalse(BackupRun.objects.exists())


class ExpireOldBackupsTests(TestCase):
    def test_a_failure_expiring_old_copies_is_a_warning_not_a_failed_backup(self):
        run = BackupRun.objects.create(status='verified')
        cfg = RecoverySettings.objects.get_or_create(pk=1)[0]
        with mock.patch.object(recovery, 'retention', side_effect=OSError('snapshot API')):
            self.assertFalse(recovery.expire_old_backups(cfg))
        run.refresh_from_db()
        self.assertEqual(run.status, 'verified')
        issue = OperationalIssue.objects.get(key='platform:backup-retention', active=True)
        self.assertEqual(issue.severity, 'warning')
        with mock.patch.object(recovery, 'retention'):
            self.assertTrue(recovery.expire_old_backups(cfg))
        self.assertFalse(OperationalIssue.objects.filter(key='platform:backup-retention', active=True).exists())
