"""Versión instalada: commit que deploy/update.sh registra al desplegar."""
import re
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

from django.conf import settings
from django.db import connection

COMMIT = re.compile(r'[0-9a-f]{40}')


def deployed_release(base_dir=None):
    path = Path(base_dir or settings.BASE_DIR) / '.deployed-commit'
    try:
        value = path.read_text(encoding='ascii').strip()
        stamp = path.stat().st_mtime
    except (OSError, UnicodeError):
        value, stamp = '', None
    valid = bool(COMMIT.fullmatch(value))
    return {'commit': value if valid else '', 'short': value[:12] if valid else '',
            'deployed_at': datetime.fromtimestamp(stamp, dt_timezone.utc) if valid else None,
            'database': connection.vendor}
