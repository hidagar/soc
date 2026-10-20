"""Privileged provisioning/recovery only. Reporting uses a separate reader."""
import json
import urllib.request

def admin_request(path,payload=None,method=None,timeout=20):
    # Local admin mTLS certificate; no admin password enters the web process or logs.
    from .indexer_tls import context as tls_context
    context=tls_context()
    context.load_cert_chain('/etc/wazuh-indexer/certs/admin.pem','/etc/wazuh-indexer/certs/admin-key.pem')
    req=urllib.request.Request('https://127.0.0.1:9200'+path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={'Content-Type':'application/json'},method=method or ('POST' if payload is not None else 'GET'))
    with urllib.request.urlopen(req,context=context,timeout=timeout) as response:
        return json.load(response)
