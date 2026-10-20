"""Set the portal's public syslog endpoint without printing other env values."""

import ipaddress
import os
import sys
import tempfile
from pathlib import Path


value = sys.argv[1]
if ipaddress.ip_address(value).version != 4:
    raise SystemExit("IPv4 required")
path = Path("/etc/soc-portal/portal.env")
stat = path.stat()
lines = [line for line in path.read_text(encoding="utf-8").splitlines()
         if not line.startswith("SOC_PORTAL_PUBLIC_SYSLOG_IP=")]
lines.append("SOC_PORTAL_PUBLIC_SYSLOG_IP=" + value)
with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".portal-env-", delete=False) as stream:
    temporary = Path(stream.name)
    stream.write("\n".join(lines) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
os.chown(temporary, stat.st_uid, stat.st_gid)
os.chmod(temporary, stat.st_mode & 0o777)
os.replace(temporary, path)
