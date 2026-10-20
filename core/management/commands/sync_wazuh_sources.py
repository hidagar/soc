"""Run as root from a restricted systemd timer, never from a web request."""

import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core.models import Device, ExportConfiguration


CONFIG_PATH = Path("/var/ossec/etc/ossec.conf")
REMOTE_BLOCK = re.compile(r"<remote>.*?</remote>", re.DOTALL)
PROJECT_ROOT = Path(__file__).resolve().parents[3]
UNIFI_FILES = (
    (PROJECT_ROOT / "deploy/wazuh/soc_unifi_decoder.xml", Path("/var/ossec/etc/decoders/soc_unifi_decoder.xml")),
    (PROJECT_ROOT / "deploy/wazuh/soc_unifi_rules.xml", Path("/var/ossec/etc/rules/soc_unifi_rules.xml")),
)
ZENARMOR_FILES = (
    (PROJECT_ROOT / 'deploy/wazuh/soc_zenarmor_decoder.xml', Path('/var/ossec/etc/decoders/010_zenarmor.xml')),
    (PROJECT_ROOT / 'deploy/wazuh/soc_zenarmor_rules.xml', Path('/var/ossec/etc/rules/100_zenarmor.xml')),
)


def add_sources(contents, sources):
    def validate(document):
        without_declaration = re.sub(r"^\s*<\?xml[^>]+\?>", "", document, count=1)
        ET.fromstring("<soc-root>" + without_declaration + "</soc-root>")

    validate(contents)
    for match in REMOTE_BLOCK.finditer(contents):
        node = ET.fromstring(match.group())
        if node.findtext("connection", "").strip() != "syslog" or node.findtext("port", "").strip() != "5514":
            continue
        existing = {item.text.strip() for item in node.findall("allowed-ips") if item.text}
        additions = sorted(set(sources) - existing)
        if not additions:
            return contents, False
        addition = "".join(f"    <allowed-ips>{ip}</allowed-ips>\n" for ip in additions)
        replacement = match.group().replace("</remote>", addition + "  </remote>", 1)
        updated = contents[:match.start()] + replacement + contents[match.end():]
        validate(updated)
        return updated, True
    raise ValueError("No se encontró el receptor syslog UDP 5514 en Wazuh.")


def _replace_file(path, data, previous_stat=None):
    import pwd
    import grp
    owner = pwd.getpwnam("wazuh").pw_uid
    group = grp.getgrnam("wazuh").gr_gid
    if previous_stat is not None:
        owner, group = previous_stat.st_uid, previous_stat.st_gid
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.soc-", delete=False) as handle:
        temp_path = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chown(temp_path, owner, group)
        os.chmod(temp_path, (previous_stat.st_mode & 0o777) if previous_stat else 0o660)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _validate_xml_fragments(contents):
    ET.fromstring("<soc-root>" + contents + "</soc-root>")


def _restore(changes):
    for path, old_data, old_stat in reversed(changes):
        if old_data is None:
            path.unlink(missing_ok=True)
        else:
            _replace_file(path, old_data, old_stat)


class Command(BaseCommand):
    help = "Sincroniza orígenes syslog y reglas UniFi y Zenarmor con Wazuh."

    def handle(self, *args, **options):
        if os.geteuid() != 0:
            raise CommandError("Este comando debe ejecutarse como root mediante systemd.")
        all_configs = list(ExportConfiguration.objects.filter(
            status=ExportConfiguration.Status.CONFIGURED,
        ).select_related("device"))
        configs = [row for row in all_configs if row.source_ip]
        from core.secure_logs import active_channels,ensure_local_guard
        channels=list(active_channels())
        if channels:ensure_local_guard()
        sources = []
        for config in configs:
            source = ipaddress.ip_address(config.source_ip)
            if source.version == 4:
                sources.append(str(source))
        sources.extend(channel.source_identity for channel in channels)
        contents = CONFIG_PATH.read_text(encoding="utf-8")
        try:
            updated, changed = add_sources(contents, sources)
        except (ET.ParseError, ValueError) as exc:
            raise CommandError(str(exc)) from exc
        planned = []
        if changed:
            planned.append((CONFIG_PATH, updated.encode("utf-8")))
        # Prepared for all registered OPNsense receivers, including a later wizard upgrade.
        if any(row.device.vendor == Device.Vendor.OPNSENSE for row in all_configs):
            for source_path, destination_path in ZENARMOR_FILES:
                desired = source_path.read_bytes()
                _validate_xml_fragments(desired.decode('utf-8'))
                if not destination_path.exists() or destination_path.read_bytes() != desired:
                    planned.append((destination_path, desired))
        if any(row.device.vendor == Device.Vendor.UNIFI for row in all_configs):
            try:
                for source_path, destination_path in UNIFI_FILES:
                    desired = source_path.read_bytes()
                    _validate_xml_fragments(desired.decode("utf-8"))
                    if not destination_path.exists() or destination_path.read_bytes() != desired:
                        planned.append((destination_path, desired))
            except (OSError, UnicodeError, ET.ParseError) as exc:
                raise CommandError("No se pudieron preparar las reglas UniFi de Wazuh.") from exc
        changes = []
        try:
            for path, data in planned:
                old_data = path.read_bytes() if path.exists() else None
                old_stat = path.stat() if path.exists() else None
                if old_data is not None:
                    backup = path.with_name(f"{path.name}.soc-backup-{datetime.now(timezone.utc):%Y%m%d%H%M%S}")
                    shutil.copy2(path, backup)
                _replace_file(path, data, old_stat)
                changes.append((path, old_data, old_stat))
            if changes:
                check = subprocess.run(["/var/ossec/bin/wazuh-analysisd", "-t"], capture_output=True, text=True, timeout=45)
                if check.returncode != 0 or "duplicated" in (check.stdout + check.stderr).lower():
                    raise CommandError("Wazuh rechazó las reglas o detectó identificadores duplicados.")
                result = subprocess.run(["/usr/bin/systemctl", "restart", "wazuh-manager"], capture_output=True, timeout=90)
                if result.returncode != 0:
                    raise CommandError("Wazuh no inició con la configuración nueva.")
        except (OSError, subprocess.TimeoutExpired, CommandError) as exc:
            if changes:
                _restore(changes)
                subprocess.run(["/usr/bin/systemctl", "restart", "wazuh-manager"], capture_output=True, timeout=90)
            raise CommandError("No se pudo aplicar la configuración Wazuh; se restauró la anterior.") from exc
        active = subprocess.run(["/usr/bin/systemctl", "is-active", "wazuh-manager"], capture_output=True, text=True, timeout=10)
        if active.stdout.strip() != "active":
            raise CommandError("Wazuh no está activo; no se marca el receptor como listo.")
        from core.source_ownership import synchronize,desired
        ownership_before=desired()
        ExportConfiguration.objects.filter(pk__in=[row.pk for row in configs]).update(receiver_ready=True)
        from core.models import SecureLogChannel
        SecureLogChannel.objects.filter(pk__in=[channel.pk for channel in channels]).update(receiver_ready=True)
        synchronize(expected_before=ownership_before)
        from core.onboarding_verification import verify_pending_onboardings
        confirmed = verify_pending_onboardings()
        self.stdout.write(f"Asistente: {confirmed} equipo(s) verificados con eventos reales de Wazuh.")
        self.stdout.write(f"Wazuh activo; {len(sources)} IP de origen registradas.")
