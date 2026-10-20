"""One-time deployment helper; run as root. Never print the generated key."""

from pathlib import Path

from cryptography.fernet import Fernet


path = Path("/etc/soc-portal/portal.env")
content = path.read_text(encoding="utf-8")
if not any(line.startswith("SOC_PORTAL_SSH_KEY=") for line in content.splitlines()):
    with path.open("a", encoding="utf-8") as handle:
        if not content.endswith("\n"):
            handle.write("\n")
        handle.write("SOC_PORTAL_SSH_KEY=" + Fernet.generate_key().decode("ascii") + "\n")
