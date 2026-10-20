import socket
import ssl
import tempfile
import threading
from pathlib import Path
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.test import SimpleTestCase
from .indexer_tls import context

class IndexerTlsTests(SimpleTestCase):
    def handshake(self,expired=False,hostname='localhost',trusted=True):
        now=datetime.now(timezone.utc)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2)).not_valid_after(now-timedelta(days=1) if expired else now+timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).sign(key,hashes.SHA256())
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); pem=root/'cert.pem'; secret=root/'key.pem'
            pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM));secret.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.load_cert_chain(pem,secret)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
                def accept():
                    try:
                        conn,_=listener.accept()
                        with conn:
                            with server.wrap_socket(conn,server_side=True) as tls: tls.sendall(b'X')
                    except (ssl.SSLError,OSError): pass
                thread=threading.Thread(target=accept,daemon=True);thread.start()
                client=context(cafile=str(pem)) if trusted else ssl.create_default_context()
                try:
                    with socket.create_connection(listener.getsockname(),timeout=5) as conn:
                        with client.wrap_socket(conn,server_hostname=hostname) as tls: return tls.recv(1)
                finally: thread.join(5)
    def test_trusted_valid_cert_is_accepted(self):
        self.assertEqual(self.handshake(),b'X')
    def test_wrong_hostname_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError): self.handshake(hostname='other.example')
    def test_expired_cert_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError): self.handshake(expired=True)
    def test_untrusted_cert_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError): self.handshake(trusted=False)
