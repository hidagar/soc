"""Validate the installed legacy Wazuh PKI on Python 3.13+.

Installer CA predates RFC5280 keyUsage enforcement. Relax ONLY certificate-profile
strictness for this fixed private trust store; require signatures, time validity
and server hostname. CERT_NONE/check_hostname=False are never permitted.
"""
import ssl

def context(cafile='/etc/wazuh-indexer/certs/root-ca.pem'):
    result=ssl.create_default_context(cafile=cafile)
    result.verify_flags &= ~ssl.VERIFY_X509_STRICT
    assert result.verify_mode==ssl.CERT_REQUIRED and result.check_hostname
    return result
