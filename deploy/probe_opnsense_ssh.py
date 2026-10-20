import sys

sys.path.insert(0, "/srv/soc-portal")

from core.ssh_connection import probe_host_key


info = probe_host_key("172.20.10.1", 22)
print("SSH key type:", info["type"])
print("SSH fingerprint:", info["fingerprint"])
